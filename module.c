#include <sys/param.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

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

int converse(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  char buf[PAM_MAX_RESP_SIZE];
  int i;

  data = data;
  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return (PAM_CONV_ERR);
  if ((aresp = calloc(n, sizeof *aresp)) == NULL)
    return (PAM_BUF_ERR);
  for (i = 0; i < n; ++i) {
    aresp[i].resp_retcode = 0;
    aresp[i].resp = NULL;
    switch (msg[i]->msg_style) {
    case PAM_PROMPT_ECHO_OFF:
      aresp[i].resp = strdup(getpass(msg[i]->msg));
      if (aresp[i].resp == NULL)
	goto fail;
      break;
    case PAM_PROMPT_ECHO_ON:
      fputs(msg[i]->msg, stderr);
      if (fgets(buf, sizeof buf, stdin) == NULL)
	goto fail;
      aresp[i].resp = strdup(buf);
      if (aresp[i].resp == NULL)
	goto fail;
      break;
    case PAM_ERROR_MSG:
      fputs(msg[i]->msg, stderr);
      if (strlen(msg[i]->msg) > 0 &&
	  msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
	fputc('\n', stderr);
      break;
    case PAM_TEXT_INFO:
      fputs(msg[i]->msg, stdout);
      if (strlen(msg[i]->msg) > 0 &&
	  msg[i]->msg[strlen(msg[i]->msg) - 1] != '\n')
	fputc('\n', stdout);
      break;
    default:
      goto fail;
    }
  }
  *resp = aresp;
  return (PAM_SUCCESS);
 fail:
  for (i = 0; i < n; ++i) {
    if (aresp[i].resp != NULL) {
      memset(aresp[i].resp, 0, strlen(aresp[i].resp));
      free(aresp[i].resp);
    }
  }
  memset(aresp, 0, n * sizeof *aresp);
  *resp = NULL;
  return (PAM_CONV_ERR);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, UNUSED int flags,
		    UNUSED int argc, UNUSED const char *argv[])
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
  pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (pam_err != PAM_SUCCESS)
    return (PAM_SYSTEM_ERR);
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg = "password for open container :";
  msgs[0] = &msg;
  resp = NULL;

  // conv->conv = converse;
  pam_err = pam_get_authtok(pamh, PAM_AUTHTOK, (const char **)&password, NULL);

  /* pam_err = (*conv->conv)(1, msgs, &resp, conv->appdata_ptr);
  password = resp->resp;
  free(resp->resp);
  free(resp); */

  if (pam_err == PAM_CONV_ERR) {
    return (pam_err);
  }
  if (pam_err != PAM_SUCCESS) {
    return (PAM_AUTH_ERR);
  }
  printf("pass = {%s}\n", password);

  pid_t	pid;
  int	status;

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
    warn("execlp()");
    exit(1);
  }
  waitpid(pid, &status, 0);
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
  return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("test");
#endif
