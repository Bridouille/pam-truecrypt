#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

int su_conv(int, const struct pam_message **, struct pam_response **, void *);

static struct pam_conv pam_conv = { &su_conv, NULL };

int	main(__attribute__((unused))int argc, char **argv)
{
  pam_handle_t *pamh;
  int ret;
  struct passwd *pwd;

  /* assume arguments are correct and argv[1] is the username */

  ret = pam_start("test", "bridou_n", &pam_conv, &pamh);
  if ( ret == PAM_SUCCESS ) {
    ret = pam_authenticate(pamh, 0);
    printf("after pam_authenticate\n");
    if (ret != PAM_SUCCESS)
      printf("ERR authenticate\n");
  }
  if ( ret == PAM_SUCCESS ) {
    ret = pam_acct_mgmt(pamh, 0);
    printf("aftetr pam_acct_mgmt\n");
  }

  if ( ret == PAM_SUCCESS ) {
    if ( (pwd = getpwnam("bridou_n")) != NULL ) {
      printf("OK\n");
      setuid(pwd->pw_uid);
    } else {
      pam_end(pamh, PAM_AUTH_ERR);
      exit(1);
    }
  }
  pam_end(pamh, PAM_SUCCESS);

  /* return 0 on success, !0 on failure */
  return ( ret == PAM_SUCCESS ? 0 : 1 );
}

int	su_conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
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

/*int	su_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata)
{
  struct pam_message *m = *msg;
  struct pam_response *r = *resp;

  while ( num_msg-- )
    {
      switch(m->msg_style) {

      case PAM_PROMPT_ECHO_ON:
	printf("TOTO\n");
	fprintf(stdout, "%s", m->msg);
	r->resp = (char *)malloc(PAM_MAX_RESP_SIZE);
	fgets(r->resp, PAM_MAX_RESP_SIZE-1, stdin);
	m++; r++;
	break;

      case PAM_PROMPT_ECHO_OFF:
	r->resp = getpass(m->msg);
	m++; r++;
	break;

      case PAM_ERROR_MSG:
	fprintf(stderr, "%s\n", m->msg);
	m++; r++;
	break;

      case PAM_TEXT_INFO:
	fprintf(stdout, "%s\n", m->msg);
	m++; r++;
	break;

      default:
	break;
      }
    }
  return PAM_SUCCESS;
  }*/
