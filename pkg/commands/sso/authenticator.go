package sso

import "io"

// Authenticator wraps a RootCommand to satisfy the global.SSOAuthenticator interface.
type Authenticator struct {
	Cmd *RootCommand
}

// Authenticate executes the SSO command to authenticate the user.
func (a *Authenticator) Authenticate(in io.Reader, out io.Writer) error {
	return a.Cmd.Exec(in, out)
}

// SetForceReAuth sets the ForceReAuth package variable.
func (a *Authenticator) SetForceReAuth(force bool) {
	ForceReAuth = force
}
