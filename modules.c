#include "_cgo_export.h"
#include <security/pam_modules.h>

#define PAM_Mapping(c, go) \
  PAM_EXTERN int pam_sm_ ## c ( \
    pam_handle_t *pamh, int flags, int argc, const char **argv) { \
    return pam ## go (pamh, flags, argc, (char **)argv); \
  }

PAM_Mapping(authenticate,  Authenticate);
PAM_Mapping(setcred,       SetCredential);
PAM_Mapping(acct_mgmt,     AccountManagement);
PAM_Mapping(open_session,  OpenSession);
PAM_Mapping(close_session, CloseSession);
PAM_Mapping(chauthtok,     ChangeAuthToken);
