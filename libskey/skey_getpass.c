 /* Author: Wietse Venema, Eindhoven University of Technology. */

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <termios.h>
#include <pwd.h>

#include "skey.h"

static struct termios saved_ttymode;

/* restore - restore terminal modes when user aborts command */

static void restore_ttymode(sig)
int     sig;
{
    tcsetattr(0, TCSANOW, &saved_ttymode);
    exit(1);
}

/* skey_getpass - read regular or s/key password */

char   *skey_getpass(prompt, pwd, pwok)
char   *prompt;
struct passwd *pwd;
int     pwok;
{
    static char buf[128];
    struct skey skey;
    void    rip();
    struct termios noecho_ttymode;
    char   *username = pwd ? pwd->pw_name : ":";
    int     sflag;
    void    (*oldsig) ();

    /* Attempt an s/key challenge. */

    if ((sflag = skeyinfo(&skey, username, buf)) == 0) {
	if (skey.n < 5)
	    printf("Warning! Change s/key password soon\n");
	printf("%s\n", buf);
    }
    if (!pwok) {
	printf("(s/key required)\n");
    }
    fputs(prompt, stdout);
    fflush(stdout);

    /* Save current input modes and turn echo off. */

    tcgetattr(0, &saved_ttymode);
    if ((oldsig = signal(SIGINT, SIG_IGN)) != SIG_IGN)
	signal(SIGINT, restore_ttymode);
    tcgetattr(0, &noecho_ttymode);
    noecho_ttymode.c_lflag &= ~ECHO;
    tcsetattr(0, TCSANOW, &noecho_ttymode);

    /* Read password. */

    buf[0] = 0;
    fgets(buf, sizeof(buf), stdin);
    rip(buf);

    /* Restore previous input modes. */

    tcsetattr(0, TCSANOW, &saved_ttymode);
    if (oldsig != SIG_IGN)
	signal(SIGINT, oldsig);

    /* Give S/Key users a chance to do it with echo on. */

    if (sflag == 0 && feof(stdin) == 0 && buf[0] == 0) {
	fputs(" (turning echo on)\n", stdout);
	fputs(prompt, stdout);
	fflush(stdout);
	fgets(buf, sizeof(buf), stdin);
	rip(buf);
    } else {
	putchar('\n');
    }
    return (buf);
}
