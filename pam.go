package pam

import "fmt"

/*
#include <sys/types.h>
#include <security/pam_appl.h>
*/
import "C"

type pamError struct {
	pamh *C.pam_handle_t
	err  C.int
}

func (e pamError) Error() string {
	pamStr := C.pam_strerror(e.pamh, e.err)
	return fmt.Sprintf("Pam Error(%d): %s", e.err, pamStr)
}

// Handle wraps our pam_handle_t for method attachment
type Handle struct {
	pamh  *C.pam_handle_t
	Flags Flags
}

// GetUser .
func (h Handle) GetUser() (string, error) {
	var usr *C.char
	e := C.pam_get_user(h.pamh, &usr, nil)

	if e != Success {
		return C.GoString(usr), nil
	}
	return nil, pamError{h.pamh, e}
}
