#include <sys/param.h>

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define UNUSED __attribute__((unused))

PAM_EXTERN int
pam_sm_authenticate(UNUSED pam_handle_t *pamh, UNUSED int flags,
		    UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_authenticate !\n");
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_setcred(UNUSED pam_handle_t *pamh, UNUSED int flags,
	       UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_setcred !\n");  
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(UNUSED pam_handle_t *pamh, UNUSED int flags,
		 UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_acct_mgmt !\n");
  return (PAM_SUCCESS);
}

// faire 3 essais pour tenter le pass du conteneur
// donner le nom du conteneur en parametre pam

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
  struct pam_conv		*conv;
  struct pam_message		msg;
  const struct pam_message	*msgp;
  struct pam_response		*resp;
  struct passwd			*pwd;
  const char			*user;
  char				*password;
  int				pam_err;

  /* identify user */
  if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
    return (pam_err);
  if ((pwd = getpwnam(user)) == NULL)
    return (PAM_USER_UNKNOWN);

  /* get password */
  printf("user = %s\n", user);
  pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (pam_err != PAM_SUCCESS)
    return (PAM_SYSTEM_ERR);
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg = "password for open container :";
  msgp = &msg;
  resp = NULL;

  // 3 essais ici
  pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
  if (resp != NULL) {
    if (pam_err == PAM_SUCCESS)
      password = resp->resp;
    else
      free(resp->resp);
    free(resp);
  }
  if (pam_err == PAM_CONV_ERR)
    return (pam_err);
  if (pam_err != PAM_SUCCESS)
    return (PAM_AUTH_ERR);
  printf("pass = %s\n", password);

  pid_t pid;

  if ((pid = fork()) == -1) {
    print("Fork err\n");
  }
  if (!pid) {

  } else {
    
  }


  free(password);
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(UNUSED pam_handle_t *pamh, UNUSED int flags,
		     UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_close_session !\n");
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(UNUSED pam_handle_t *pamh, UNUSED int flags,
		 UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_chauthtok !\n");
  return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("test");
#endif
