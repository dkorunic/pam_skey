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
 * Programs that had some influence on development:
 *  Wietse Venema's logdaemon package
 *  Olaf Kirch's Linux S/Key package
 *  Linux-PAM modules and templates
 *  Wyman Miles' pam_securid module
 *
 * Should you choose to use and/or modify this source code, please do so
 * under the terms of the GNU General Public License under which this
 * program is distributed.
 *
 * $Id: pam_skey.h,v 1.15 2001/08/16 08:22:37 kreator Exp $
 */

/* Prototypes */
#ifndef BSD
extern int skeyinfo(struct skey *, char *, char *); /* ORGH! Not in skey.h */
#endif

static void mod_getopt(unsigned *, int, const char **);
static int mod_talk_touser(pam_handle_t *, unsigned *, char *, char **);

/* free() macro */
#define _pam_drop(X)  \
if (X != NULL)        \
{                     \
  free(X);            \
  X = NULL;           \
}

/* Secure overwrite */
#define _pam_overwrite(x)   \
{                           \
  register char *__xx__;    \
  if ((__xx__ = (x)))       \
    while (*__xx__)         \
    *__xx__++ = '\0';       \
}

/* Drop-in secure replacement - we do not want cleartext passwords lying
 * scattered around */
#define _pam_delete(xx)   \
{                         \
  _pam_overwrite(xx);     \
  _pam_drop(xx);          \
}

/* This will get us rid of first '\n' in response string and cut-off the
 * rest of the string. It should be ASCIIZ, of course */
#define _pam_degarbage(x)      \
{                              \
  register char *__xx__;       \
    if ((__xx__ = (x)))        \
      while (*__xx__)          \
      {                        \
        if ((*__xx__) == '\n') \
        {                      \
          *__xx__ = 0;         \
          break;               \
        }                      \
        else                   \
          __xx__++;            \
      }                        \
}

/* Handy empty AUTHTOK macro */
#define empty_authtok(a) (a == NULL || !*a || *a == '\n')

/* Maximum challenge size. It should be 64, but be sure */
#define CHALLENGE_MAXSIZE 128

/* Define module flags */
#define _MOD_NONE_ON        0x0000      /* Generic flag */
#define _MOD_ALL_ON    (~_MOD_NONE_ON)  /* Generic mask */
#define _MOD_DEBUG          0x0001      /* Debugging options on */
#define _MOD_ECHO_OFF       0x0002      /* PAM_ECHO_OFF */
#define _MOD_ACCESS_CHECK   0x0004      /* Check S/Key access permissions */
#define _MOD_USE_FIRST_PASS 0x0008      /* Use PAM_AUTHTOK */
#define _MOD_ONLY_ONE_TRY   0x0010      /* Only one try, no matter of echo */
#define _MOD_SPACER         0x0020      /* Currently unused */

/* Setup defaults - use echo off only */
#define _MOD_DEFAULT_FLAG   _MOD_ECHO_OFF
#define _MOD_DEFAULT_MASK   _MOD_ALL_ON

/* Number of parameters currently known */
#define _MOD_ARGS           8

/* Structure for flexible argument parsing */
typedef struct
{
  const char *token; /* string value to search for */
  unsigned mask; /* which bits to mask */
  unsigned flag; /* which bits to set */
} _MOD_Ctrls;

/* Various options recognised by this pam module */
static const _MOD_Ctrls mod_args[_MOD_ARGS] =
{
  /* String            Mask                           Flag */
  {"debug",            _MOD_ALL_ON,                   _MOD_DEBUG},
  {"echo=off",         _MOD_ALL_ON,                   _MOD_ECHO_OFF},
  {"echo=on",          _MOD_ALL_ON^_MOD_ECHO_OFF,     _MOD_NONE_ON},
  {"access_check=on",  _MOD_ALL_ON,                   _MOD_ACCESS_CHECK},
  {"access_check=off", _MOD_ALL_ON^_MOD_ACCESS_CHECK, _MOD_NONE_ON},
  {"use_first_pass",   _MOD_ALL_ON,                   _MOD_USE_FIRST_PASS},
  {"try_first_pass",   _MOD_ALL_ON,                   _MOD_USE_FIRST_PASS},
  {"only_one_try",     _MOD_ALL_ON,                   _MOD_ONLY_ONE_TRY}
};
