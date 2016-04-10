package pam

import "C"

// AccountHandler is our `account` service interface for interacting with PAM as a module
type AccountHandler interface {
	Validate(Handle, []string) Value
}

// AuthHandler is our `auth` service interface for interacting with PAM as a module
type AuthHandler interface {
	Authenticate(Handle, []string) Value
	SetCredential(Handle, []string) Value
}

// PasswordHandler is our `password` service interface for interacting with PAM as a module
type PasswordHandler interface {
	ChangeAuthToken(Handle, []string) Value
}

// SessionHandler is our `session` service interface for interacting with PAM as a module
type SessionHandler interface {
	Open(Handle, []string) Value
	Close(Handle, []string) Value
}

// RegisterAccountHandler registers our handler for interacting with PAM
func RegisterAccountHandler(handle AccountHandler) {
	handlers.account = handle
}

// RegisterAuthHandler registers our handler for interacting with PAM
func RegisterAuthHandler(handle AuthHandler) {
	handlers.auth = handle
}

// RegisterPasswordHandler registers our handler for interacting with PAM
func RegisterPasswordHandler(handle PasswordHandler) error {
	handlers.password = handle
}

// RegisterSessionHandler registers our handler for interacting with PAM
func RegisterSessionHandler(handle SessionHandler) error {
	handlers.session = handle
}
