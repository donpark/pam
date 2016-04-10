package pam

import "unsafe"

/*
#include <security/pam_modules.h>
*/
import "C"

// Flags are PAM related flags
type Flags C.int

// Value is used for return values to/from PAM
type Value C.int

// Handle wraps our pam_handle_t for method attachment
type Handle struct {
	pamh  *C.pam_handle_t
	Flags Flags
}

const (
	ChangeExpiredAuthToken Flags = C.PAM_CHANGE_EXPIRED_AUTHTOK
	DeleteCredential       Flags = C.PAM_DELETE_CRED
	DisallowNullAuthToken  Flags = C.PAM_DISALLOW_NULL_AUTHTOK
	EstablishCredential    Flags = C.PAM_ESTABLISH_CRED
	PrelimCheck            Flags = C.PAM_PRELIM_CHECK
	RefreshCredential      Flags = C.PAM_REFRESH_CRED
	ReinitializeCredential Flags = C.PAM_REINITIALIZE_CRED
	Silent                 Flags = C.PAM_SILENT
	UpdateAuthToken        Flags = C.PAM_UPDATE_AUTHTOK

	AccountExpired         Value = C.PAM_ACCT_EXPIRED
	AuthError              Value = C.PAM_AUTH_ERR
	AuthInfoUnavailable    Value = C.PAM_AUTHINFO_UNAVAIL
	AuthTokenDisableAging  Value = C.PAM_AUTHTOK_DISABLE_AGING
	AuthTokenError         Value = C.PAM_AUTHTOK_ERR
	AuthTokenLockBusy      Value = C.PAM_AUTHTOK_LOCK_BUSY
	AuthTokenRecoveryError Value = C.PAM_AUTHTOK_RECOVERY_ERR
	CredentialError        Value = C.PAM_CRED_ERR
	CredentialExpired      Value = C.PAM_CRED_EXPIRED
	CredentialInsufficient Value = C.PAM_CRED_INSUFFICIENT
	CredentialUnavailable  Value = C.PAM_CRED_UNAVAIL
	MaxTries               Value = C.PAM_MAXTRIES
	NewAuthTokenRequired   Value = C.PAM_NEW_AUTHTOK_REQD
	PermissionDenied       Value = C.PAM_PERM_DENIED
	SessionError           Value = C.PAM_SESSION_ERR
	Success                Value = C.PAM_SUCCESS
	TryAgain               Value = C.PAM_TRY_AGAIN
	UserUnknown            Value = C.PAM_USER_UNKNOWN
)

var handlers = struct {
	auth     AuthHandler
	account  AccountHandler
	session  SessionHandler
	password PasswordHandler
}{
	nullHandler{},
	nullHandler{},
	nullHandler{},
	nullHandler{},
}

// null handler for defaulting all our pam hooks
type nullHandler struct{}

func (h nullHandler) Validate(hdl Handle, args []string) Value {
	return AuthError
}

func (h nullHandler) Authenticate(hdl Handle, args []string) Value {
	return AuthInfoUnavailable
}

func (h nullHandler) SetCredential(hdl Handle, args []string) Value {
	return CredentialUnavailable
}

func (h nullHandler) Open(hdl Handle, args []string) Value {
	return SessionError
}

func (h nullHandler) Close(hdl Handle, args []string) Value {
	return SessionError
}

func (h nullHandler) ChangeAuthToken(hdl Handle, args []string) Value {
	return AuthTokenError
}

// turns our wonderful **C.char into []string
func translateArguments(argc C.int, argv **C.char) []string {
	length := int(argc)
	ptrSlice := (*[1 << 30]*C.char)(unsafe.Pointer(argv))[:length:length]
	ret := make([]string, length)

	for i, ptr := range ptrSlice {
		ret[i] = C.GoString(ptr)
	}
	return ret
}
