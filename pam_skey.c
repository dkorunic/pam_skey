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

static char rcsid[]="$Id: pam_skey.c,v 1.29 2001/03/03 19:47:40 kreator Exp $";

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

#define PAM_EXTERN   extern
#undef PAM_STATIC

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "skey.h"
#include "pam_skey.h"

PAM_EXTERN int pam_sm_setcred (pam_handle_t *pamh, int flags,
  int argc, const char **argv)
{
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
  int argc, const char **argv)
{
  char challenge[CHALLENGE_MAXSIZE], msg_text[PAM_MAX_MSG_SIZE],
    *username=NULL, *response=NULL;
  struct skey skey;
  int status;
  unsigned mod_opt=0U;

  /* Get module options */
  mod_getopt(&mod_opt, argc, argv);

  /* Get username */
  if (pam_get_user(pamh, (char **)&username, "login:")!=PAM_SUCCESS)
  {
    fprintf(stderr, "cannot determine username\n");
    if (mod_opt & _MOD_DEBUG)
      syslog(LOG_DEBUG, "cannot determine username");
    return PAM_SERVICE_ERR;
  }

  if (mod_opt & _MOD_DEBUG)
    syslog(LOG_DEBUG, "got username %s", username);

  /* Check S/Key access permissions - user, host and port. Also include
   * sanity checks */
  if (mod_opt & _MOD_ACCESS_CHECK)
  {
    char *host, *port;
    struct passwd *pwuser;

    /* Get host.. */
    if (pam_get_item(pamh, PAM_RHOST, (void **)&host)
        !=PAM_SUCCESS)
      host=NULL;
    /* ..and port */
    if (pam_get_item(pamh, PAM_TTY, (void **)&port)
        !=PAM_SUCCESS)
      port=NULL;

    if (mod_opt & _MOD_DEBUG)
      syslog(LOG_DEBUG, "checking s/key access for user %s,"
        " host %s, port %s", username, (host!=NULL)?host:"*unknown*",
        (port!=NULL)?port:"*unknown*");

    /* Get information from passwd file */
    if ((pwuser=getpwnam(username))==NULL)
    {
      fprintf(stderr, "cannot find passwd info\n");
      syslog(LOG_NOTICE, "cannot find passwd info for %s",
        username);
      return PAM_SERVICE_ERR;
    }

    /* Do actual checking - we assume skeyaccess() returns PERMIT which is
     * by default 1. Notice 4th argument is NULL - we will not perform
     * address checks on host itself */
    if (skeyaccess(pwuser, port, host, NULL)!=1)
    {
      fprintf(stderr, "no s/key access permissions\n");
      syslog(LOG_NOTICE, "no s/key access permissions for %s",
          username);
      return PAM_SERVICE_ERR;
    }
  }
  else
  /* Only do check whether user has passwd entry */
  if (getpwnam(username)==NULL)
  {
    fprintf(stderr, "no password info available\n");
    if (mod_opt & _MOD_DEBUG)
      syslog(LOG_DEBUG, "no password info available for %s",
          username);
    return PAM_USER_UNKNOWN;
  }

  /* Get S/Key information on user with skeyinfo() */
  switch (skeyinfo(&skey, username, NULL))
  {
  /* 0: OK */
  case 0:
    break;
  /* -1: File error */
  case -1:
    fprintf(stderr, "s/key database error\n");
    syslog(LOG_NOTICE, "s/key database error");
    return PAM_AUTHINFO_UNAVAIL;
  /* 1: No such user in database */
  case 1:
    fprintf(stderr, "no s/key for %s\n", username);
    if (mod_opt & _MOD_DEBUG)
      syslog(LOG_DEBUG, "no s/key for %s\n", username);
    return PAM_USER_UNKNOWN;
  }

  /* Make challenge string */
  snprintf(challenge, CHALLENGE_MAXSIZE, "s/key %d %s",
      skey.n-1, skey.seed);

  if (mod_opt & _MOD_DEBUG)
    syslog(LOG_DEBUG, "got challenge %s for %s", challenge,
        username);

  /* Read response from last module's PAM_AUTHTOK */
  if (mod_opt & _MOD_USE_FIRST_PASS)
  {
    /* Try to extract authtoken */
    if (pam_get_item(pamh, PAM_AUTHTOK, (void **)&response)
        !=PAM_SUCCESS)
    {
      if (mod_opt & _MOD_DEBUG)
        syslog(LOG_DEBUG, "could not get PAM_AUTHTOK");
      mod_opt&=~_MOD_USE_FIRST_PASS;
    }
    else
    {
      /* Got AUTHTOK, but it was empty */
      if (empty_authtok(response))
      {
        if (mod_opt & _MOD_DEBUG)
          syslog(LOG_DEBUG, "empty PAM_AUTHTOK");
        mod_opt&=~_MOD_USE_FIRST_PASS;
      }
      else
        /* All OK, print challenge information */
        fprintf(stderr, "challenge %s\n", challenge);
    }
  }

  /* There was no PAM_AUTHTOK, or there was no such option in pam-conf
   * file */
  if (!(mod_opt & _MOD_USE_FIRST_PASS))
  {
    /* Prepare a complete message for conversation */
    snprintf(msg_text, PAM_MAX_MSG_SIZE,
        "challenge %s\npassword: ", challenge);

    /* Talk with user */
    if (mod_talk_touser(pamh, &mod_opt, msg_text, &response)
        !=PAM_SUCCESS)
      return PAM_SERVICE_ERR;

    /* Simulate standard S/Key login procedure - if empty token, turn on
     * ECHO and prompt again */
    if (empty_authtok(response) && !(mod_opt & _MOD_ONLY_ONE_TRY))
    {
      /* Was there echo off? */
      if (mod_opt & _MOD_ECHO_OFF)
      {
        _pam_delete(response);
        fprintf(stderr, "(turning echo on)\n");
        mod_opt &= ~_MOD_ECHO_OFF;
        /* Prepare a complete message for conversation */
        snprintf(msg_text, PAM_MAX_MSG_SIZE, "password: ");
        /* Talk with user */
          if (mod_talk_touser(pamh, &mod_opt, msg_text, &response)
          !=PAM_SUCCESS)
          return PAM_SERVICE_ERR;
      }
      else
      /* There was echo on already - just get out and don't save auth token
       * for other modules */
        return PAM_IGNORE;
    }

    /* Got again empty response. Bailout and don't save auth token */
    /* XXX - next retry puts \n at the end? */
    if (empty_authtok(response))
      return PAM_IGNORE;
  
    /* Store auth token - that next module can use with `use_first_pass' */
    if (pam_set_item(pamh, PAM_AUTHTOK, response)
        !=PAM_SUCCESS)
    {
      syslog(LOG_NOTICE, "unable to save auth token");
      return PAM_SERVICE_ERR;
    }
  } 

  /* Verify S/Key */
  status=skeyverify(&skey, response);
  _pam_delete(response);

  switch(status)
  {
    /* 0: Verify successful, database updated */
    case 0:
      break;
    /* -1: Error of some sort; database unchanged */
    /*  1: Verify failed, database unchanged */
    case -1:
    case 1:
      if (mod_opt & _MOD_DEBUG)
        syslog(LOG_DEBUG, "verify for %s failed, database"
            " unchanged", username);
      return PAM_AUTH_ERR;
  }

  /* Success by default */
  return PAM_SUCCESS;
}

/* Get module optional parameters */
static void mod_getopt(unsigned *mod_opt, int mod_argc, const char **mod_argv)
{
  int i;

  /* Setup runtime defaults */
  *mod_opt|=_MOD_DEFAULT_FLAG;
  *mod_opt&=_MOD_DEFAULT_MASK;

  /* Setup runtime options */
  while (mod_argc--)
  {
    for (i=0; i<_MOD_ARGS; ++i)
    {
      if (mod_args[i].token!=NULL &&
          !strncmp(*mod_argv, mod_args[i].token,
            strlen(mod_args[i].token)))
        break;
    }
    if (i>=_MOD_ARGS)
      syslog(LOG_ERR, "unknown option %s", *mod_argv);
    else
    {
      *mod_opt&=mod_args[i].mask; /* Turn off */
      *mod_opt|=mod_args[i].flag; /* Turn on */
    }
    ++mod_argv;
  }
}

/* This will talk to user through PAM_CONV */
static int mod_talk_touser(pam_handle_t *pamh, unsigned *mod_opt,
    char *msg_text, char **response)
{
  struct pam_message message;
  const struct pam_message *pmessage=&message;
  struct pam_conv *conv=NULL;
  struct pam_response *presponse=NULL;

  /* Better safe than sorry */
  *response=NULL;

  /* Be paranoid */
  memset(&message, 0, sizeof(message));

  /* Turn on/off PAM echo */
  if (*mod_opt & _MOD_ECHO_OFF)
    message.msg_style=PAM_PROMPT_ECHO_OFF;
  else
    message.msg_style=PAM_PROMPT_ECHO_ON;
  
  /* Point to conversation text */
  message.msg=msg_text;

  /* Do conversation and see if all is OK */
  if (pam_get_item(pamh, PAM_CONV, (void **)&conv)
      !=PAM_SUCCESS)
  {
    if (*mod_opt & _MOD_DEBUG)
      syslog(LOG_DEBUG, "error in conversation");
    return PAM_SERVICE_ERR;
  }

  /* Convert into pam_response - only 1 reply expected */
  if (conv->conv(1, (struct pam_message **)&pmessage, &presponse,
        conv->appdata_ptr)!=PAM_SUCCESS)
  {
    _pam_delete(presponse->resp);
    return PAM_SERVICE_ERR;
  }

  if (presponse!=NULL)
  {
    /* Save address */
    *response=presponse->resp;
    /* To ensure that response address will not be erased */
    presponse->resp=NULL;
    _pam_drop(presponse);
  }
  else
    return PAM_SERVICE_ERR;

  return PAM_SUCCESS;
}
