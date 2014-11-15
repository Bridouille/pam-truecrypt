#include <sys/param.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <utmp.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

#ifndef PAM_EXTERN
# define PAM_EXTERN
#endif

#define UNUSED			__attribute__((unused))
#define DEFAULT_VOLUME_NAME	"secret"
#define UTMP_PATH		"/var/run/utmp"

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

static int	get_nb_of_users(char *name)
{
  struct utmp	buf;
  int		nb = 0;
  int		fd;

  if ((fd = open(UTMP_PATH, O_RDONLY)) == -1) {
    warn("open");
    return -1;
  }
  while (read(fd, &buf, sizeof(struct utmp)) > 0)
    if (buf.ut_type == USER_PROCESS && !strcmp(buf.ut_user, name))
      ++nb;
  return nb;
}

static char	*gen_path(char *user_name, char *volume_name)
{
  char		*path;

  if (!volume_name || !user_name || !(path = malloc(sizeof(char) *
     (strlen(user_name) + strlen(volume_name) + 8))))
    return (NULL);
  strcpy(path, "/home/");
  strcat(path, user_name);
  strcat(path, "/");
  strcat(path, volume_name);
  return (path);
}

static int	encrypt_volume(struct passwd *pwd,
			       char *volume_name, char *password)
{
  pid_t		pid;
  int		status;
  char		*path;
  char		*pass;

  if (!(path = gen_path(pwd->pw_name, volume_name))||
      !(pass = malloc(sizeof(char) * (strlen(password) + 12)))) {
    warn("malloc()");
    return (PAM_SESSION_ERR);
  }
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
  free(volume_name);
  return (PAM_SUCCESS);
}

static void	load_conf(char **volume_name, int *autocreate,
			  struct passwd *pwd)
{
  char		*conf_file;
  char		*line;
  size_t	n;
  FILE		*stream;

  *volume_name = strdup(DEFAULT_VOLUME_NAME);
  *autocreate = 0;
  if (!(conf_file = malloc(sizeof(char) * (strlen("/home/") + strlen(pwd->pw_name) + strlen("/.my_modulerc") + 1))))
    return (warn("malloc()"));
  strcpy(conf_file, "/home/");
  strcat(conf_file, pwd->pw_name);
  strcat(conf_file, "/.my_modulerc");
  if ((stream = fopen(conf_file, "r")) == NULL)
    return (warn("fopen()"));
  line = NULL;
  while (getline(&line, &n, stream) != -1) {
    line[strlen(line) - 1] = '\0';
    if (!strncmp(line, "autocreate=", strlen("autocreate=")) &&
	!strncmp(&line[strlen("autocreate=")], "true", 4))
      *autocreate = 1;
    if (!strncmp(line, "volume_name=", strlen("volume_name="))) {
      free(*volume_name);
      *volume_name = strdup(&line[strlen("volume_name=")]);
    }
    free(line);
    line = NULL;
  }
  fclose(stream);
}

static int	create_volume(struct passwd *pwd)
{
  pid_t		pid;
  int		status;

  if ((pid = fork()) == -1) {
    warn("fork()");
    return (1);
  }
  if (!pid) {
    if (setuid(pwd->pw_uid) == -1) {
      warn("setuid()");
      exit(PAM_SESSION_ERR);
    }
    execlp("truecrypt", "truecrypt", "-c", NULL);
    warn("execlp()");
    exit(PAM_SESSION_ERR);
  }
  if (waitpid(pid, &status, 0) == -1) {
    warn("waitpid()");
    return (1);
  }
  return (WEXITSTATUS(status));
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
  char				*volume_name;
  char				*password = NULL;
  char				*path;
  int				pam_err;
  int				autocreate;

  if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
    return (pam_err);
  if ((pwd = getpwnam(user)) == NULL)
    return (PAM_USER_UNKNOWN);
  if (get_nb_of_users(pwd->pw_name) >= 1)
    return PAM_SUCCESS;
  load_conf(&volume_name, &autocreate, pwd);
  if (!(path = gen_path(pwd->pw_name, volume_name)))
    return (PAM_SESSION_ERR);
  printf("\n\n");
  if (access(path, F_OK) == -1) {
    printf("Volume at %s doesn't exist\n", path);
    if (autocreate) {
      printf("Creating volume...\n");
      pam_err = create_volume(pwd);
      printf("%s\n", pam_err ? "Well done, opening volume now..." :
	     "Error while creating volume");
      if (pam_err) {
	free(path);
	return (PAM_SESSION_ERR);
      }
    } else {
      free(path);
      return (PAM_SUCCESS);
    }
  }
  free(path);
  pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
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
    return (PAM_CONV_ERR);
  if (pam_err != PAM_SUCCESS)
    return (PAM_AUTH_ERR);
  return (encrypt_volume(pwd, volume_name, password));
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

  if (get_nb_of_users(pwd->pw_name) > 1)
    return PAM_SUCCESS;
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
