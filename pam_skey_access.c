/* 
 * (c) 2001 Dinko Korunic, kreator@fly.srk.fer.hr
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *
 * S/KEY is a trademark of Bellcore.
 * Mink is the former name of the S/KEY authentication system.
 *
 * Programs that had some influence in development of this source:
 *  Wietse Venema's logdaemon package
 *  Olaf Kirch's Linux S/Key package
 *  Linux-PAM modules and templates
 *  Wyman Miles' pam_securid module
 *
 * Should you choose to use and/or modify this source code, please do so
 * under the terms of the GNU General Public License under which this
 * program is distributed.
 */

static char rcsid[] = "$Id: pam_skey_access.c,v 1.12 2001/08/16 08:22:37 kreator Exp $";

#include "defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef STRING_WITH_STRINGS
# include <strings.h>
#endif
#include <unistd.h>
#include <pwd.h> 
#include <sys/types.h>
#include <syslog.h>

#define PAM_EXTERN extern
#undef PAM_STATIC

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "skey.h"
#include "pam_skey.h"
#include "misc.h"

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags,
  int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
  int argc, const char **argv)
{
  char *username = NULL; /* will point to username */
  unsigned mod_opt = _MOD_NONE_ON; /* module options */
  char *host; /* will point to host */
  char *port; /* will point to port */
  struct passwd *pwuser;

  /* Get module options */
  mod_getopt(&mod_opt, argc, argv);

  /* Get username */
#if defined LINUX || defined BSD
  if (pam_get_user(pamh, (const char **)&username, "login:")!=PAM_SUCCESS)
#else
  if (pam_get_user(pamh, (char **)&username, "login:")!=PAM_SUCCESS)
#endif
  {
    fprintf(stderr, "cannot determine username\n");
    if (mod_opt & _MOD_DEBUG)
      syslog(LOG_DEBUG, "cannot determine username");
    return PAM_AUTHINFO_UNAVAIL;
  }

  if (mod_opt & _MOD_DEBUG)
    syslog(LOG_DEBUG, "got username %s", username);

  /* Check S/Key access permissions - user, host and port. Also include
   * sanity checks */
  /* Get host.. */
#if defined LINUX || defined BSD
  if (pam_get_item(pamh, PAM_RHOST, (const void **)&host)
#else
  if (pam_get_item(pamh, PAM_RHOST, (void **)&host)
#endif
    != PAM_SUCCESS)
      host = NULL;
  /* ..and port */
#ifdef LINUX
  if (pam_get_item(pamh, PAM_TTY, (const void **)&port)
#else
  if (pam_get_item(pamh, PAM_TTY, (void **)&port)
#endif
    != PAM_SUCCESS)
      port = NULL;

  if (mod_opt & _MOD_DEBUG)
    syslog(LOG_DEBUG, "checking s/key access for user %s,"
      " host %s, port %s", username,
      (host != NULL) ? host : "*unknown*",
      (port != NULL) ? port : "*unknown*");

  /* Get information from passwd file */
  if ((pwuser = getpwnam(username)) == NULL)
  {
    fprintf(stderr, "no such user\n");
    syslog(LOG_NOTICE, "cannot find user %s",
      username);
    return PAM_AUTHINFO_UNAVAIL;
  }

#ifdef HAVE_SKEYACCESS

  /* Do actual checking - we assume skeyaccess() returns PERMIT which is
   * by default 1. Notice 4th argument is NULL - we will not perform
   * address checks on host itself */
  if (skeyaccess(pwuser, port, host, NULL) != 1)
  {
    fprintf(stderr, "no s/key access permissions\n");
    syslog(LOG_NOTICE, "no s/key access permissions for %s",
        username);
    return PAM_AUTH_ERR;
  }

#endif /* HAVE_SKEYACCESS */

  return PAM_SUCCESS;
}

/* Get module optional parameters */
static void mod_getopt(unsigned *mod_opt, int mod_argc, const char **mod_argv)
{
  int i;

  /* Setup runtime defaults */
  *mod_opt |= _MOD_DEFAULT_FLAG;
  *mod_opt &= _MOD_DEFAULT_MASK;

  /* Setup runtime options */
  while (mod_argc--)
  {
    for (i = 0; i < _MOD_ARGS; ++i)
    {
      if (mod_args[i].token != NULL &&
          !strncmp(*mod_argv, mod_args[i].token,
            strlen(mod_args[i].token)))
        break;
    }
    if (i >= _MOD_ARGS)
      syslog(LOG_ERR, "unknown option %s", *mod_argv);
    else
    {
      *mod_opt &= mod_args[i].mask; /* Turn off */
      *mod_opt |= mod_args[i].flag; /* Turn on */
    }
    ++mod_argv;
  }
}
