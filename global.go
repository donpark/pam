package pam

import (
	"strings"
	"unsafe"
)

/*
#include <security/pam_modules.h>
*/
import "C"

// Flags are PAM related flags
type Flags int

// Value is used for return values to/from PAM
type Value int

// Item represents the pam item flag
type Item int

// Args is what we store are broken out arguments in
type Args map[string]string

const (
	ChangeExpiredAuthToken = Flags(C.PAM_CHANGE_EXPIRED_AUTHTOK)
	DeleteCredential       = Flags(C.PAM_DELETE_CRED)
	DisallowNullAuthToken  = Flags(C.PAM_DISALLOW_NULL_AUTHTOK)
	EstablishCredential    = Flags(C.PAM_ESTABLISH_CRED)
	PrelimCheck            = Flags(C.PAM_PRELIM_CHECK)
	RefreshCredential      = Flags(C.PAM_REFRESH_CRED)
	ReinitializeCredential = Flags(C.PAM_REINITIALIZE_CRED)
	Silent                 = Flags(C.PAM_SILENT)
	UpdateAuthToken        = Flags(C.PAM_UPDATE_AUTHTOK)

	AccountExpired         = Value(C.PAM_ACCT_EXPIRED)
	AuthError              = Value(C.PAM_AUTH_ERR)
	AuthInfoUnavailable    = Value(C.PAM_AUTHINFO_UNAVAIL)
	AuthTokenDisableAging  = Value(C.PAM_AUTHTOK_DISABLE_AGING)
	AuthTokenError         = Value(C.PAM_AUTHTOK_ERR)
	AuthTokenLockBusy      = Value(C.PAM_AUTHTOK_LOCK_BUSY)
	AuthTokenRecoveryError = Value(C.PAM_AUTHTOK_RECOVERY_ERR)
	CredentialError        = Value(C.PAM_CRED_ERR)
	CredentialExpired      = Value(C.PAM_CRED_EXPIRED)
	CredentialInsufficient = Value(C.PAM_CRED_INSUFFICIENT)
	CredentialUnavailable  = Value(C.PAM_CRED_UNAVAIL)
	MaxTries               = Value(C.PAM_MAXTRIES)
	NewAuthTokenRequired   = Value(C.PAM_NEW_AUTHTOK_REQD)
	PermissionDenied       = Value(C.PAM_PERM_DENIED)
	SessionError           = Value(C.PAM_SESSION_ERR)
	Success                = Value(C.PAM_SUCCESS)
	TryAgain               = Value(C.PAM_TRY_AGAIN)
	UserUnknown            = Value(C.PAM_USER_UNKNOWN)

	Service      = Item(C.PAM_SERVICE)
	User         = Item(C.PAM_USER)
	UserPrompt   = Item(C.PAM_USER_PROMPT)
	Tty          = Item(C.PAM_TTY)
	RemoteUser   = Item(C.PAM_RUSER)
	RemoteHost   = Item(C.PAM_RHOST)
	AuthToken    = Item(C.PAM_AUTHTOK)
	OldAuthToken = Item(C.PAM_OLDAUTHTOK)
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

func (h nullHandler) Validate(hdl Handle, args Args) Value {
	return AuthError
}

func (h nullHandler) Authenticate(hdl Handle, args Args) Value {
	return AuthInfoUnavailable
}

func (h nullHandler) SetCredential(hdl Handle, args Args) Value {
	return CredentialUnavailable
}

func (h nullHandler) Open(hdl Handle, args Args) Value {
	return SessionError
}

func (h nullHandler) Close(hdl Handle, args Args) Value {
	return SessionError
}

func (h nullHandler) ChangeAuthToken(hdl Handle, args Args) Value {
	return AuthTokenError
}

func (a Args) add(arg string) {
	spl := strings.SplitN(arg, "=", 2)
	key, arg := spl[0], ""
	if len(spl) == 2 {
		arg = spl[1]
	}

	a[key] = arg
}

// turns our wonderful **C.char into []string
func translateArguments(argc C.int, argv **C.char) Args {
	ret := Args{}
	length := int(argc)
	if length == 0 || argv == nil {
		return ret // argv could be nil
	}
	ptrSlice := (*[1 << 30]*C.char)(unsafe.Pointer(argv))[:length:length]
	for _, ptr := range ptrSlice {
		ret.add(C.GoString(ptr))
	}
	return ret
}
