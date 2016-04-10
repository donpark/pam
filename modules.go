package pam

/*
#include <security/pam_modules.h>
*/
import "C"

//export pamAccountManagement
func pamAccountManagement(pam *C.pam_handle_t, flags Flags, argc C.int, argv **C.char) Value {
	hdl := Handle{pam, flags}
	args := translateArguments(argc, argv)
	return handlers.account.Validate(hdl, args)
}

//export pamAuthenticate
func pamAuthenticate(pam *C.pam_handle_t, flags Flags, argc C.int, argv **C.char) Value {
	hdl := Handle{pam, flags}
	args := translateArguments(argc, argv)
	return handlers.auth.Authenticate(hdl, args)
}

//export pamSetCredential
func pamSetCredential(pam *C.pam_handle_t, flags Flags, argc C.int, argv **C.char) Value {
	hdl := Handle{pam, flags}
	args := translateArguments(argc, argv)
	return handlers.auth.SetCredential(hdl, args)
}

//export pamChangeAuthToken
func pamChangeAuthToken(pam *C.pam_handle_t, flags Flags, argc C.int, argv **C.char) Value {
	hdl := Handle{pam, flags}
	args := translateArguments(argc, argv)
	return handlers.password.ChangeAuthToken(hdl, args)
}

//export pamOpenSession
func pamOpenSession(pam *C.pam_handle_t, flags Flags, argc C.int, argv **C.char) Value {
	hdl := Handle{pam, flags}
	args := translateArguments(argc, argv)
	return handlers.session.Open(hdl, args)
}

//export pamCloseSession
func pamCloseSession(pam *C.pam_handle_t, flags Flags, argc C.int, argv **C.char) Value {
	hdl := Handle{pam, flags}
	args := translateArguments(argc, argv)
	return handlers.session.Close(hdl, args)
}
