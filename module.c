#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <err.h>
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
  sleep(5);
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_setcred(UNUSED pam_handle_t *pamh, UNUSED int flags,
	       UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_setcred !\n");  
  sleep(5);
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(UNUSED pam_handle_t *pamh, UNUSED int flags,
		 UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_acct_mgmt !\n");
  sleep(5);
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
  const struct pam_message	*msgs[1];
  struct pam_response		*resp;
  struct passwd			*pwd;
  const char			*user;
  char				*password;
  int				pam_err;

  printf("pam_sm_open_session !\n");
  /* identify user */
  if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
    return (pam_err);
  if ((pwd = getpwnam(user)) == NULL)
    return (PAM_USER_UNKNOWN);

  /* get password */
  printf("user = %s\n", user);

  /*pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (pam_err != PAM_SUCCESS)
    return (PAM_SYSTEM_ERR);
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg = "password for open container :";
  msgs[0] = &msg;
  resp = NULL;

  printf("Demain on fais les bras\n");
  // pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
  //		    (const char **)&password, NULL); */
  // 3 essais ici
  /*pam_err = (*conv->conv)(1, msgs, &resp, conv->appdata_ptr);
  
  password = resp->resp;
  free(resp->resp);
  free(resp);

  if (pam_err == PAM_CONV_ERR) {
    printf("DAAAAMN\n");
    //return (pam_err);
  }
  if (pam_err != PAM_SUCCESS) {
    printf("%s\n", pam_strerror(pamh, pam_err));
    // return (PAM_AUTH_ERR);
  }*/
  printf("pass = %s\n", password);

  pid_t pid;
  int status;

  if ((pid = fork()) == -1) {
    printf("Fork err\n");
  }
  if (!pid) {
    execlp("truecrypt",
	   "truecrypt",
	   "--non-interactive",
	   "--password=toto",
	   "/home/bridou_n/toto",
	   NULL);
    warn("execve()");
    exit(1);
  }
  waitpid(pid, &status, 0);
  free(password);
  if (WEXITSTATUS(status))
    return (PAM_SESSION_ERR);
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(UNUSED pam_handle_t *pamh, UNUSED int flags,
		     UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_close_session !\n");

  pid_t pid;
  int status;

  if ((pid = fork()) == -1) {
    printf("Fork err\n");
  }
  if (!pid) {
    execlp("truecrypt",
	   "truecrypt",
	   "-d",
	   NULL);
    warn("execve()");
    exit(1);
  }
  waitpid(pid, &status, 0);
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(UNUSED pam_handle_t *pamh, UNUSED int flags,
		 UNUSED int argc, UNUSED const char *argv[])
{
  printf("pam_sm_chauthtok !\n");
  sleep(5);
  return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("test");
#endif
