 /*
  * Figure out if UNIX passwords are permitted for any combination of user
  * name, group member, terminal port, host_name or network:
  * 
  * Programmatic interface: skeyaccess(user, port, host, addr)
  * 
  * The user argument is a struct passwd pointer. All other arguments are
  * null-terminated strings. Specify a null pointer where information is not
  * available.
  * 
  * When no address information is given this code performs the host (internet)
  * address lookup itself. It rejects addresses that appear to belong to
  * someone else.
  * 
  * When compiled with -DPERMIT_CONSOLE always permits UNIX passwords with
  * console logins, no matter what the configuration file says.
  * 
  * To build a stand-alone test version, compile with -DTEST and run it off an
  * skey.access file in the current directory:
  * 
  * Command-line interface: ./skeyaccess user port [host_or_ip_addr]
  * 
  * Errors are reported via syslogd.
  * 
  * Author: Wietse Venema, Eindhoven University of Technology.
  */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>

#include "skey.h"

 /*
  * Token input with one-deep pushback.
  */
static char *prev_token = 0;		/* push-back buffer */
static char *first_token();
static int line_number;
static void unget_token();
static char *get_token();
static char *need_token();
static char *need_internet_addr();

 /*
  * Various forms of token matching.
  */
#define match_host_name(l)	match_token((l)->host_name)
#define match_port(l)		match_token((l)->port)
#define match_user(l)		((l)->user && match_token((l)->user->pw_name))
static int match_internet_addr();
static int match_group();
static int match_token();
static int is_internet_addr();
static struct in_addr *convert_internet_addr();
static struct in_addr *lookup_internet_addr();

 /*
  * In case not defined in sys/param.h
  */
#if (MAXHOSTNAMELEN < 64)		/* AIX weirdness */
#undef MAXHOSTNAMELEN
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 255
#endif

#ifndef INADDR_NONE
#define INADDR_NONE     (-1)		/* XXX should be 0xffffffff */
#endif

 /*
  * For stand-alone testing, use the skey.access file in the current
  * directory and print some stuff as we scan through the table.
  */

#ifdef TEST
#undef KEYACCESS
#define KEYACCESS 	"./skey.access"
#endif

#ifndef KEYACCESS
#define KEYACCESS       "/etc/skey.access"
#endif

#define MAX_ADDR	32
#define PERMIT		1
#define DENY		0

#ifndef CONSOLE
#define CONSOLE		"console"
#endif

struct login_info {
    char   *host_name;			/* host name */
    struct in_addr *internet_addr;	/* null terminated list */
    struct passwd *user;		/* user name/group/etc */
    char   *port;			/* login port */
};

/* skeyaccess - find out if UNIX passwords are permitted */

int     skeyaccess(user, port, host, addr)
struct passwd *user;
char   *port;
char   *host;
char   *addr;
{
    FILE   *fp;
    struct login_info login_info;
    int     result;

    /*
     * Assume no restriction on the use of UNIX passwords when the s/key
     * access table does not exist.
     */
    if ((fp = fopen(KEYACCESS, "r")) == 0) {
#ifdef TEST
	fprintf(stderr, "No file %s, thus no access control\n", KEYACCESS);
#endif
	return (PERMIT);
    }

    /*
     * Bundle up the arguments in a structure so we won't have to drag around
     * boring long argument lists.
     * 
     * Look up the host address when only the name is given. We try to reject
     * addresses that belong to someone else.
     */
    login_info.user = user;
    login_info.port = port;

    if (host != 0 && !is_internet_addr(host)) {
	login_info.host_name = host;
    } else {
	login_info.host_name = 0;
    }

    if (addr != 0 && is_internet_addr(addr)) {
	login_info.internet_addr = convert_internet_addr(addr);
    } else if (host != 0) {
	if (is_internet_addr(host)) {
	    login_info.internet_addr = convert_internet_addr(host);
	} else {
	    login_info.internet_addr = lookup_internet_addr(host);
	}
    } else {
	login_info.internet_addr = 0;
    }

    /*
     * Print what we think the user wants us to do.
     */
#ifdef TEST
    {
	struct group *grp;

	printf("port: %s\n", login_info.port);
	printf("user: %s\n", login_info.user->pw_name);
	printf("gid:  %d (%s)\n", login_info.user->pw_gid,
	       (grp = getgrgid(login_info.user->pw_gid)) ?
	       grp->gr_name : "no primary group name");
	printf("host: %s\n", login_info.host_name ?
	       login_info.host_name : "none");
	printf("addr: ");
	if (login_info.internet_addr == 0) {
	    printf("none\n");
	} else {
	    int     i;

	    for (i = 0; login_info.internet_addr[i].s_addr; i++)
		printf("%s%s", login_info.internet_addr[i].s_addr == -1 ?
		 "(see error log)" : inet_ntoa(login_info.internet_addr[i]),
		       login_info.internet_addr[i + 1].s_addr ? " " : "\n");
	}
    }
#endif
    result = _skeyaccess(fp, &login_info);
    fclose(fp);
    return (result);
}

/* _skeyaccess - find out if UNIX passwords are permitted */

int     _skeyaccess(fp, login_info)
FILE   *fp;
struct login_info *login_info;
{
    char    buf[BUFSIZ];
    char   *tok;
    int     match;
    int     permission;

#ifdef PERMIT_CONSOLE
    if (login_info->port != 0 && strcasecmp(login_info->port, CONSOLE) == 0)
	return (1);
#endif

    /*
     * Scan the s/key access table until we find an entry that matches. If no
     * match is found, assume that UNIX passwords are disallowed.
     */
    match = 0;
    while (match == 0 && (tok = first_token(buf, sizeof(buf), fp))) {
	if (strncasecmp(tok, "permit", 4) == 0) {
	    permission = PERMIT;
	} else if (strncasecmp(tok, "deny", 4) == 0) {
	    permission = DENY;
	} else {
	    syslog(LOG_ERR, "%s: line %d: bad permission: %s",
		   KEYACCESS, line_number, tok);
	    continue;				/* error */
	}

	/*
	 * Process all conditions in this entry until we find one that fails.
	 */
	match = 1;
	while (match != 0 && (tok = get_token())) {
	    if (strcasecmp(tok, "hostname") == 0) {
		match = match_host_name(login_info);
	    } else if (strcasecmp(tok, "port") == 0) {
		match = match_port(login_info);
	    } else if (strcasecmp(tok, "user") == 0) {
		match = match_user(login_info);
	    } else if (strcasecmp(tok, "group") == 0) {
		match = match_group(login_info);
	    } else if (strcasecmp(tok, "internet") == 0) {
		match = match_internet_addr(login_info);
	    } else if (is_internet_addr(tok)) {
		unget_token(tok);
		match = match_internet_addr(login_info);
	    } else {
		syslog(LOG_ERR, "%s: line %d: bad condition: %s",
		       KEYACCESS, line_number, tok);
		match = 0;
	    }
	}
    }
    return (match ? permission : DENY);
}

/* match_internet_addr - match internet network address */

static int match_internet_addr(login_info)
struct login_info *login_info;
{
    char   *tok;
    long    pattern;
    long    mask;
    struct in_addr *addrp;

    if (login_info->internet_addr == 0)
	return (0);
    if ((tok = need_internet_addr()) == 0)
	return (0);
    pattern = inet_addr(tok);
    if ((tok = need_internet_addr()) == 0)
	return (0);
    mask = inet_addr(tok);

    /*
     * See if any of the addresses matches a pattern in the control file. We
     * have already tried to drop addresses that belong to someone else.
     */

    for (addrp = login_info->internet_addr; addrp->s_addr; addrp++)
	if (addrp->s_addr != -1 && (addrp->s_addr & mask) == pattern)
	    return (1);
    return (0);
}

/* match_group - match username against primary or auxiliary group */

static int match_group(login_info)
struct login_info *login_info;
{
    struct group *group;
    char   *tok;
    char  **memp;

    if (login_info->user == 0)
	return (0);
    if ((tok = need_token()) && (group = getgrnam(tok))) {
	if (login_info->user->pw_gid == group->gr_gid)
	    return (1);
	for (memp = group->gr_mem; *memp; memp++)
	    if (strcmp(login_info->user->pw_name, *memp) == 0)
		return (1);
    }
    return (0);					/* XXX endgrent() */
}

/* match_token - get and match token */

static int match_token(str)
char   *str;
{
    char   *tok;

    return (str && (tok = need_token()) && strcasecmp(str, tok) == 0);
}

/* first_token - read line and return first token */

static char *first_token(buf, len, fp)
char   *buf;
int     len;
FILE   *fp;
{
    char   *cp;

    prev_token = 0;
    for (;;) {
	if (fgets(buf, len, fp) == 0)
	    return (0);
	line_number++;
	buf[strcspn(buf, "\r\n#")] = 0;
#ifdef TEST
	if (buf[0])
	    printf("rule: %s\n", buf);
#endif
	if (cp = strtok(buf, " \t"))
	    return (cp);
    }
}

/* unget_token - push back last token */

static void unget_token(cp)
char   *cp;
{
    prev_token = cp;
}

/* get_token - retrieve next token from buffer */

static char *get_token()
{
    char   *cp;

    if (cp = prev_token) {
	prev_token = 0;
    } else {
	cp = strtok((char *) 0, " \t");
    }
    return (cp);
}

/* need_token - complain if next token is not available */

static char *need_token()
{
    char   *cp;

    if ((cp = get_token()) == 0)
	syslog(LOG_ERR, "%s: line %d: premature end of rule",
	       KEYACCESS, line_number);
    return (cp);
}

/* need_internet_addr - complain if next token is not an internet address */

static char *need_internet_addr()
{
    char   *cp;

    if ((cp = get_token()) == 0) {
	syslog(LOG_ERR, "%s: line %d: internet address expected",
	       KEYACCESS, line_number);
	return (0);
    } else if (!is_internet_addr(cp)) {
	syslog(LOG_ERR, "%s: line %d: bad internet address: %s",
	       KEYACCESS, line_number, cp);
	return (0);
    } else {
	return (cp);
    }
}

/* is_internet_addr - determine if string is a dotted quad decimal address */

static int is_internet_addr(str)
char   *str;
{
    int     in_run = 0;
    int     runs = 0;

    /* Count the number of runs of characters between the dots. */

    while (*str) {
	if (*str == '.') {
	    in_run = 0;
	} else {
	    if (!isdigit(*str))
		return (0);
	    if (in_run == 0) {
		in_run = 1;
		runs++;
	    }
	}
	str++;
    }
    return (runs == 4);
}

/* lookup_internet_addr - look up internet addresses with extreme prejudice */

static struct in_addr *lookup_internet_addr(host)
char   *host;
{
    struct hostent *hp;
    static struct in_addr list[MAX_ADDR + 1];
    char    buf[MAXHOSTNAMELEN + 1];
    int     length;
    int     i;

    if ((hp = gethostbyname(host)) == 0 || hp->h_addrtype != AF_INET)
	return (0);

    /*
     * Save a copy of the results before gethostbyaddr() clobbers them.
     */

    for (i = 0; i < MAX_ADDR && hp->h_addr_list[i]; i++)
	memcpy((char *) &list[i],
	       hp->h_addr_list[i], sizeof(*list));
    list[i].s_addr = 0;

    strncpy(buf, hp->h_name, MAXHOSTNAMELEN);
    buf[MAXHOSTNAMELEN] = 0;
    length = sizeof(*list);

    /*
     * Wipe addresses that appear to belong to someone else. We will get
     * false alarms when when the hostname comes from DNS, while its
     * addresses are listed under different names in local databases.
     */
#define NEQ(x,y)	(strcasecmp((x),(y)) != 0)
#define NEQ3(x,y,n)	(strncasecmp((x),(y), (n)) != 0)

    while (--i >= 0) {
	if ((hp = gethostbyaddr((char *) &list[i], length, AF_INET)) == 0) {
	    syslog(LOG_ERR, "address %s not registered for host %.100s",
		   inet_ntoa(list[i]), buf);
	    list[i].s_addr = -1;
	} else if (NEQ(buf, hp->h_name) && NEQ3(buf, "localhost.", 10)) {
	    syslog(LOG_ERR, "address %s registered for host %.100s and %.100s",
		   inet_ntoa(list[i]), hp->h_name, buf);
	    list[i].s_addr = -1;
	}
    }
    return (list);
}

/* convert_internet_addr - convert string to internet address */

static struct in_addr *convert_internet_addr(string)
char   *string;
{
    static struct in_addr list[2];

    list[0].s_addr = inet_addr(string);
    list[1].s_addr = 0;
    return (list);
}

#ifdef TEST

main(argc, argv)
int     argc;
char  **argv;
{
    struct hostent *hp;
    char    host[MAXHOSTNAMELEN + 1];
    int     verdict;
    struct passwd *user;
    char   *port;

    if (argc != 3 && argc != 4) {
	fprintf(stderr, "usage: %s user port [host_or_ip_address]\n", argv[0]);
	exit(0);
    }
    if (KEYACCESS[0] != '/')
	printf("Warning: this program uses control file: %s\n", KEYACCESS);
#ifdef LOG_AUTH
    openlog("login", LOG_PID, LOG_AUTH);
#else
    openlog("login", LOG_PID);
#endif

    if ((user = getpwnam(argv[1])) == 0) {
	fprintf(stderr, "User %s does not exist\n", argv[1]);
	exit(1);
    }
    port = argv[2];
    if (argv[3]) {
	strncpy(host, (hp = gethostbyname(argv[3])) ?
		hp->h_name : argv[3], MAXHOSTNAMELEN);
	host[MAXHOSTNAMELEN] = 0;
    }
    verdict = skeyaccess(user, port, argv[3] ? host : (char *) 0, (char *) 0);
    printf("UNIX passwords %spermitted\n", verdict ? "" : "NOT ");
    return (0);
}

#endif
