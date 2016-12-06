package pam

import (
	"fmt"
	"unsafe"
)

/*
#include <sys/types.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
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

	if Value(e) != Success {
		return "", pamError{h.pamh, e}
	}
	return C.GoString(usr), nil
}

// GetItem for accessing and retrieving pam information of item type
func (h Handle) GetItem(item Item) (string, error) {
	var ret unsafe.Pointer

	e := C.pam_get_item(h.pamh, C.int(item), &ret)
	if Value(e) != Success {
		return "", pamError{h.pamh, e}
	}

	return C.GoString((*C.char)(ret)), nil
}

// SetItem for setting pam information of item type
func (h Handle) SetItem(item Item, value string) error {
	cs := unsafe.Pointer(C.CString(value))
	defer C.free(cs)
	e := C.pam_set_item(h.pamh, C.int(item), cs)

	if Value(e) != Success {
		return pamError{h.pamh, e}
	}
	return nil
}
