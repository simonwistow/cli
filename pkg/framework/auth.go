package framework

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/cap/oidc"

	"github.com/fastly/go-fastly/v12/fastly"

	"github.com/fastly/cli/pkg/api"
	"github.com/fastly/cli/pkg/argparser"
	"github.com/fastly/cli/pkg/auth"
	"github.com/fastly/cli/pkg/config"
	"github.com/fastly/cli/pkg/env"
	fsterr "github.com/fastly/cli/pkg/errors"
	"github.com/fastly/cli/pkg/global"
	"github.com/fastly/cli/pkg/lookup"
	"github.com/fastly/cli/pkg/profile"
	"github.com/fastly/cli/pkg/text"
)

// processToken handles all aspects related to the required API token.
func processToken(data *global.Data) (token string, tokenSource lookup.Source, err error) {
	token, tokenSource = data.Token()

	switch tokenSource {
	case lookup.SourceFile:
		profileName, profileData, err := data.Profile()
		if err != nil {
			return "", tokenSource, err
		}
		if shouldSkipSSO(profileData, data) {
			return token, tokenSource, nil
		}
		if auth.IsLongLivedToken(profileData) {
			return ssoAuthentication("You've not authenticated via OAuth before", data)
		}
		reauth, err := checkAndRefreshSSOToken(profileData, profileName, data)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidGrant) {
				data.SSOAuth.SetForceReAuth(true)
				return ssoAuthentication("We can't refresh your token", data)
			}
			return token, tokenSource, fmt.Errorf("failed to check access/refresh token: %w", err)
		}
		if reauth {
			return ssoAuthentication("Your access token has expired and so has your refresh token", data)
		}
	case lookup.SourceUndefined:
		if data.Env.UseSSO != "1" && !data.Flags.SSO {
			return "", tokenSource, nil
		}
		return ssoAuthentication("No API token could be found", data)
	case lookup.SourceEnvironment, lookup.SourceFlag, lookup.SourceDefault:
		// no-op
	}

	return token, tokenSource, nil
}

// checkAndRefreshSSOToken refreshes the access/refresh tokens if expired.
func checkAndRefreshSSOToken(profileData *config.Profile, profileName string, data *global.Data) (reauth bool, err error) {
	if auth.TokenExpired(profileData.AccessTokenTTL, profileData.AccessTokenCreated) {
		if auth.TokenExpired(profileData.RefreshTokenTTL, profileData.RefreshTokenCreated) {
			return true, nil
		}

		if data.Flags.Verbose {
			text.Info(data.Output, "\nYour access token has now expired. We will attempt to refresh it")
		}

		updatedJWT, err := data.AuthServer.RefreshAccessToken(profileData.RefreshToken)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidGrant) {
				return false, err
			}
			return false, fmt.Errorf("failed to refresh access token: %w", err)
		}

		email, at, err := data.AuthServer.ValidateAndRetrieveAPIToken(updatedJWT.AccessToken)
		if err != nil {
			return false, fmt.Errorf("failed to validate JWT and retrieve API token: %w", err)
		}

		current := profile.Get(profileName, data.Config.Profiles)
		if current == nil {
			return false, fmt.Errorf("failed to locate '%s' profile", profileName)
		}
		now := time.Now().Unix()
		refreshToken := current.RefreshToken
		refreshTokenCreated := current.RefreshTokenCreated
		refreshTokenTTL := current.RefreshTokenTTL
		if current.RefreshToken != updatedJWT.RefreshToken {
			if data.Flags.Verbose {
				text.Info(data.Output, "Your refresh token was also updated")
				text.Break(data.Output)
			}
			refreshToken = updatedJWT.RefreshToken
			refreshTokenCreated = now
			refreshTokenTTL = updatedJWT.RefreshExpiresIn
		}

		ps, ok := profile.Edit(profileName, data.Config.Profiles, func(p *config.Profile) {
			p.AccessToken = updatedJWT.AccessToken
			p.AccessTokenCreated = now
			p.AccessTokenTTL = updatedJWT.ExpiresIn
			p.Email = email
			p.RefreshToken = refreshToken
			p.RefreshTokenCreated = refreshTokenCreated
			p.RefreshTokenTTL = refreshTokenTTL
			p.Token = at.AccessToken
		})
		if !ok {
			return false, fsterr.RemediationError{
				Inner:       fmt.Errorf("failed to update '%s' profile with new token data", profileName),
				Remediation: "Run `fastly sso` to retry.",
			}
		}
		data.Config.Profiles = ps
		if err := data.Config.Write(data.ConfigPath); err != nil {
			data.ErrLog.Add(err)
			return false, fmt.Errorf("error saving config file: %w", err)
		}
	}

	return false, nil
}

// shouldSkipSSO identifies if SSO should be skipped.
func shouldSkipSSO(profileData *config.Profile, data *global.Data) bool {
	if auth.IsLongLivedToken(profileData) {
		return data.Env.UseSSO != "1" && !data.Flags.SSO
	}
	return false
}

// ssoAuthentication executes SSO authentication to handle token acquisition.
func ssoAuthentication(outputMessage string, data *global.Data) (token string, tokenSource lookup.Source, err error) {
	if !data.Flags.AutoYes && !data.Flags.NonInteractive {
		if data.Verbose() {
			text.Break(data.Output)
		}
		text.Important(data.Output, "%s. We need to open your browser to authenticate you.", outputMessage)
		text.Break(data.Output)
		cont, err := text.AskYesNo(data.Output, text.BoldYellow("Do you want to continue? [y/N]: "), data.Input)
		text.Break(data.Output)
		if err != nil {
			return token, tokenSource, err
		}
		if !cont {
			return token, tokenSource, fsterr.ErrDontContinue
		}
	}

	data.SkipAuthPrompt = true
	err = data.SSOAuth.Authenticate(data.Input, data.Output)
	if err != nil {
		return token, tokenSource, fmt.Errorf("failed to authenticate: %w", err)
	}
	text.Break(data.Output)

	token, tokenSource = data.Token()
	if tokenSource == lookup.SourceUndefined {
		return token, tokenSource, fsterr.ErrNoToken
	}
	return token, tokenSource, nil
}

func displayToken(tokenSource lookup.Source, data *global.Data) {
	profileSource := determineProfile(data.Manifest.File.Profile, data.Flags.Profile, data.Config.Profiles)

	switch tokenSource {
	case lookup.SourceFlag:
		fmt.Fprintf(data.Output, "Fastly API token provided via --token\n\n")
	case lookup.SourceEnvironment:
		fmt.Fprintf(data.Output, "Fastly API token provided via %s\n\n", env.APIToken)
	case lookup.SourceFile:
		fmt.Fprintf(data.Output, "Fastly API token provided via config file (profile: %s)\n\n", profileSource)
	case lookup.SourceUndefined, lookup.SourceDefault:
		fallthrough
	default:
		fmt.Fprintf(data.Output, "Fastly API token not provided\n\n")
	}
}

func checkConfigPermissions(commandName string, tokenSource lookup.Source, out io.Writer) {
	segs := strings.Split(commandName, " ")
	if tokenSource == lookup.SourceFile && (len(segs) > 0 && segs[0] != "profile") {
		if fi, err := os.Stat(config.FilePath); err == nil {
			if mode := fi.Mode().Perm(); mode > config.FilePermissions {
				text.Warning(out, "Unprotected configuration file.\n\n")
				text.Output(out, "Permissions for '%s' are too open\n\n", config.FilePath)
				text.Output(out, "It is recommended that your configuration file is NOT accessible by others.\n\n")
			}
		}
	}
}

func displayAPIEndpoint(endpoint string, endpointSource lookup.Source, out io.Writer) {
	switch endpointSource {
	case lookup.SourceFlag:
		fmt.Fprintf(out, "Fastly API endpoint (via --api): %s\n", endpoint)
	case lookup.SourceEnvironment:
		fmt.Fprintf(out, "Fastly API endpoint (via %s): %s\n", env.APIEndpoint, endpoint)
	case lookup.SourceFile:
		fmt.Fprintf(out, "Fastly API endpoint (via config file): %s\n", endpoint)
	case lookup.SourceDefault, lookup.SourceUndefined:
		fallthrough
	default:
		fmt.Fprintf(out, "Fastly API endpoint: %s\n", endpoint)
	}
}

func configureClients(token, apiEndpoint string, acf global.APIClientFactory, debugMode bool) (apiClient api.Interface, rtsClient api.RealtimeStatsInterface, err error) {
	apiClient, err = acf(token, apiEndpoint, debugMode)
	if err != nil {
		return nil, nil, fmt.Errorf("error constructing Fastly API client: %w", err)
	}

	rtsClient, err = fastly.NewRealtimeStatsClientForEndpoint(token, fastly.DefaultRealtimeStatsEndpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error constructing Fastly realtime stats client: %w", err)
	}

	return apiClient, rtsClient, nil
}

// determineProfile determines if the provided token was acquired via the
// fastly.toml manifest, the --profile flag, or was a default profile.
func determineProfile(manifestValue, flagValue string, profiles config.Profiles) string {
	if manifestValue != "" {
		return manifestValue + " -- via fastly.toml"
	}
	if flagValue != "" {
		return flagValue
	}
	name, _ := profile.Default(profiles)
	return name
}

// configureAuth processes authentication tasks.
func configureAuth(apiEndpoint string, args []string, f config.File, c api.HTTPClient, e config.Environment) (*auth.Server, error) {
	metadataEndpoint := fmt.Sprintf(auth.OIDCMetadata, accountEndpoint(args, e, f))
	req, err := http.NewRequest(http.MethodGet, metadataEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct request object for OpenID Connect .well-known metadata: %w", err)
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request OpenID Connect .well-known metadata (%s): %w", metadataEndpoint, err)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		var body []byte
		body, _ = io.ReadAll(resp.Body)
		return nil, fmt.Errorf("the Fastly servers are unresponsive, please check the Fastly Status page (https://fastlystatus.com) and reach out to support if the error persists (HTTP Status Code: %d, Error Message: %s)", resp.StatusCode, body)
	}

	openIDConfig, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenID Connect .well-known metadata: %w", err)
	}
	_ = resp.Body.Close()

	var wellknown auth.WellKnownEndpoints
	err = json.Unmarshal(openIDConfig, &wellknown)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OpenID Connect .well-known metadata: %w", err)
	}

	result := make(chan auth.AuthorizationResult)
	router := http.NewServeMux()
	verifier, err := oidc.NewCodeVerifier()
	if err != nil {
		return nil, fsterr.RemediationError{
			Inner:       fmt.Errorf("failed to generate a code verifier for SSO authentication server: %w", err),
			Remediation: auth.Remediation,
		}
	}

	authServer := &auth.Server{
		APIEndpoint:        apiEndpoint,
		DebugMode:          e.DebugMode,
		HTTPClient:         c,
		Result:             result,
		Router:             router,
		Verifier:           verifier,
		WellKnownEndpoints: wellknown,
	}

	router.HandleFunc("/callback", authServer.HandleCallback())

	return authServer, nil
}

// accountEndpoint parses the account endpoint from multiple locations.
func accountEndpoint(args []string, e config.Environment, cfg config.File) string {
	for i, a := range args {
		if a == "--account" && i+1 < len(args) {
			return args[i+1]
		}
	}
	if e.AccountEndpoint != "" {
		return e.AccountEndpoint
	}
	if cfg.Fastly.AccountEndpoint != global.DefaultAccountEndpoint && cfg.Fastly.AccountEndpoint != "" {
		return cfg.Fastly.AccountEndpoint
	}
	return global.DefaultAccountEndpoint
}

// commandCollectsData determines if the command collects Wasm binary data.
func commandCollectsData(command string) bool {
	switch command {
	case "compute build", "compute hash-files", "compute publish", "compute serve":
		return true
	}
	return false
}

// commandRequiresAuthServer determines if the command requires the auth server.
func commandRequiresAuthServer(command string) bool {
	switch command {
	case "profile create", "profile switch", "profile update", "sso":
		return true
	}
	return false
}

// TokenChecker is implemented by commands that can dynamically determine
// whether they require an API token.
type TokenChecker interface {
	RequiresToken() bool
}

// commandRequiresToken determines if the command requires an API token.
func commandRequiresToken(command argparser.Command) bool {
	commandName := command.Name()
	switch commandName {
	case "compute init":
		if tc, ok := command.(TokenChecker); ok {
			return tc.RequiresToken()
		}
		return false
	case "compute build", "compute hash-files", "compute metadata", "compute serve":
		return false
	}
	commandName = strings.Split(commandName, " ")[0]
	switch commandName {
	case "config", "profile", "sso", "update", "version":
		return false
	}
	return true
}

// commandSuppressesVerbose checks if the given command suppresses verbose output.
func commandSuppressesVerbose(command argparser.Command) bool {
	type verboseSuppressor interface {
		SuppressesVerbose() bool
	}
	if vs, ok := command.(verboseSuppressor); ok {
		return vs.SuppressesVerbose()
	}
	return false
}
