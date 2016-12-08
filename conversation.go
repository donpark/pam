package pam

// Full credit for the following belongs to Amanda Cameron
// - https://github.com/AmandaCameron/golang-pam-auth

/*
#cgo LDFLAGS: -lpam
#include <stdlib.h>
#include <security/pam_appl.h>
int do_conv(pam_handle_t* hdlr, int count, const struct pam_message** msgs, struct pam_response** responses) {
	int err;
	struct pam_conv* conv;
	err = pam_get_item(hdlr, PAM_CONV, (const void**)&conv);
	if(err != PAM_SUCCESS) {
		return err;
	}
	return conv->conv(count, msgs, responses, conv->appdata_ptr);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// MessageStyle is a style of Message
type MessageStyle int

const (
	// MessageEchoOff is for messages that shouldn't gave an echo.
	MessageEchoOff = MessageStyle(C.PAM_PROMPT_ECHO_OFF)

	// MessageEchoOn is for messages that should have an echo.
	MessageEchoOn = MessageStyle(C.PAM_PROMPT_ECHO_ON)

	// MessageErrorMsg is for messages that should be displayed as an error.
	MessageErrorMsg = MessageStyle(C.PAM_ERROR_MSG)

	// MessageTextInfo is for textual blurbs to be spat out.
	MessageTextInfo = MessageStyle(C.PAM_TEXT_INFO)
)

// Message represents something to ask / show in a Conv.Conversation call.
type Message struct {
	Style MessageStyle
	Msg   string
}

// Conversation passes on the specified messages.
func (hdl Handle) Conversation(_msgs ...Message) ([]string, error) {
	n := len(_msgs)
	if n == 0 {
		return nil, errors.New("must pass at least one Message")
	}

	msgs := []*C.struct_pam_message{}
	resps := []*C.struct_pam_response{}

	for _, _msg := range _msgs {
		// use malloc to allocate C structs to dodge stricter Go 1.6 cgo rules
		// which forbids nested Go pointers
		msgStruct := (*C.struct_pam_message)(C.malloc(C.sizeof_struct_pam_message))
		msgStruct.msg_style = C.int(_msg.Style)
		msgStruct.msg = C.CString(_msg.Msg)
		defer C.free(unsafe.Pointer(msgStruct.msg))
		defer C.free(unsafe.Pointer(msgStruct))

		// same for response
		respStruct := C.malloc(C.sizeof_struct_pam_response)
		defer C.free(respStruct)

		msgs = append(msgs, ((*C.struct_pam_message)(unsafe.Pointer(msgStruct))))
		resps = append(resps, ((*C.struct_pam_response)(respStruct)))
	}

	code := C.do_conv(hdl.pamh, C.int(len(_msgs)), &msgs[0], &resps[0])
	if code != C.PAM_SUCCESS {
		return nil, fmt.Errorf("Got non-success from the function: %d", code)
	}

	var ret []string
	for _, r := range resps {
		ret = append(ret, C.GoString(r.resp))
		C.free(unsafe.Pointer(r.resp))
	}

	return ret, nil
}
