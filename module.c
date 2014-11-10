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

#define UNUSED			__attribute__((unused))
#define DEFAULT_VOLUME_NAME	"secret"

PAM_EXTERN int
pam_sm_authenticate(UNUSED pam_handle_t *pamh, UNUSED int flags,
		    UNUSED int argc, UNUSED const char *argv[])
{
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_setcred(UNUSED pam_handle_t *pamh, UNUSED int flags,
	       UNUSED int argc, UNUSED const char *argv[])
{
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(UNUSED pam_handle_t *pamh, UNUSED int flags,
		 UNUSED int argc, UNUSED const char *argv[])
{
  return (PAM_SUCCESS);
}

static int	encrypt_volume(struct passwd *pwd,
			       const char *volume_name, char *password)
{
  pid_t		pid;
  int		status;
  char		*path;
  char		*pass;

  if (!(path = malloc(sizeof(char) *
		      (strlen(pwd->pw_name) + strlen(volume_name) + 8))) ||
      !(pass = malloc(sizeof(char) * (strlen(password) + 12)))) {
    warn("malloc()");
    return (PAM_SESSION_ERR);
  }
  strcpy(path, "/home/");
  strcat(path, pwd->pw_name);
  strcat(path, "/");
  strcat(path, volume_name);
  strcpy(pass, "--password=");
  strcat(pass, password);
  if ((pid = fork()) == -1) {
    warn("fork()");
    return (PAM_SESSION_ERR);
  }
  if (!pid) {
    if (setuid(pwd->pw_uid) == -1) {
      warn("setuid()");
      exit(PAM_SESSION_ERR);
    }
    execlp("truecrypt", "truecrypt", "--non-interactive", pass, path, NULL);
    warn("execlp()");
    exit(1);
  }
  waitpid(pid, &status, 0);
  free(path);
  free(password);
  /* if (WEXITSTATUS(status))
     return (PAM_SESSION_ERR); */
  return (PAM_SUCCESS);

}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, UNUSED int flags,
		    UNUSED int ac, UNUSED const char *av[])
{
  struct pam_conv		*conv;
  struct pam_message		msg;
  const struct pam_message	*msgp;
  struct pam_response		*resp;
  struct passwd			*pwd;
  const char			*user;
  char				*password;
  int				pam_err;

  if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
    return (pam_err);
  if ((pwd = getpwnam(user)) == NULL)
    return (PAM_USER_UNKNOWN);

  pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  if (pam_err != PAM_SUCCESS)
    return (PAM_SYSTEM_ERR);
  msg.msg_style = PAM_PROMPT_ECHO_OFF;
  msg.msg = "password for unlock volume: ";
  msgp = &msg;
  resp = NULL;
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
  return (encrypt_volume(pwd, ac == 1 ?
			 av[0] : DEFAULT_VOLUME_NAME, password));
}

PAM_EXTERN int
pam_sm_close_session(UNUSED pam_handle_t *pamh, UNUSED int flags,
		     UNUSED int argc, UNUSED const char *argv[])
{
  pid_t		pid;
  int		status;
  int		pam_err;
  struct passwd	*pwd;
  const char	*user;

  if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
    return (pam_err);
  if ((pwd = getpwnam(user)) == NULL)
    return (PAM_USER_UNKNOWN);

  if ((pid = fork()) == -1) {
    warn("fork()");
    return (PAM_SESSION_ERR);
  }
  if (!pid) {
    if (setuid(pwd->pw_uid) == -1) {
      warn("setuid()");
      exit(PAM_SESSION_ERR);
    }
    execlp("truecrypt", "truecrypt", "-d", NULL);
    warn("execlp()");
    exit(PAM_SESSION_ERR);
  }
  if (waitpid(pid, &status, 0) == -1) {
    warn("waitpid()");
    return (PAM_SESSION_ERR);
  }
  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(UNUSED pam_handle_t *pamh, UNUSED int flags,
		 UNUSED int argc, UNUSED const char *argv[])
{
  return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("my_module");
#endif
