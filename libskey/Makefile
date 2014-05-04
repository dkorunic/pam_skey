# Beware, gnumake preserves whitespace between macrodefns and comments
KEY_DIR	= /etc
BIN_DIR	= /usr/local/bin
MAN_DIR	= /usr/local/man
KEYACCESS= $(KEY_DIR)/skey.access
KEYFILE	= $(KEY_DIR)/skeykeys
CFLAGS	= -O2 $(XFLAGS) -DPERMIT_CONSOLE -DKEYACCESS=\"$(KEYACCESS)\" \
	-DKEYFILE=\"$(KEYFILE)\" -DMD4 -fPIC -DPIC
OBJS	= skeylogin.o skeysubr.o mdx.o put.o skeyaccess.o skey_getpass.o \
	skey_crypt.o $(MISSING)
BINS	= key keyinfo keyinit
DOCS	= skey.access.5 keyinit.1
LIB	= libskey.a
RANLIB	= ranlib
EXTRA	=
SYSLIBS	=
SHELL	= /bin/sh
MAKE	= make
LDFLAGS = -s

what:
	@echo This Makefile is not to be invoked directly 1>&2; exit 1

bsd44 bsdi ultrix4 sunos4 decosf1:
	@$(MAKE) all

freebsd:
	@$(MAKE) all SYSLIBS=-lcrypt

newsos4:
	$(MAKE) all MISSING=strftime.o

sysv4 sunos5:
	@$(MAKE) all SYSLIBS=-lnsl RANLIB=echo

irix5:
	@$(MAKE) all RANLIB=echo

irix4:
	@$(MAKE) all XFLAGS=-cckr RANLIB=echo SYSLIBS=-lsun

linux:
	@$(MAKE) all XFLAGS="-I/usr/include/bsd" SYSLIBS="-lbsd"

hpux9 hpux10 hpux10t:
	@$(MAKE) all RANLIB=echo

all: skeyaccess $(LIB) $(BINS) $(DOCS)

$(LIB): ${OBJS}
	ar rv $@ $?
	$(RANLIB) $@

clean:
	rm -f *.o $(LIB) skeyaccess $(BINS) $(DOCS)

install: all
	cp $(BINS) $(BIN_DIR)
	cd $(BIN_DIR); chmod 4755 keyinit; chmod 755 key keyinfo
	touch $(KEYFILE); chmod 644 $(KEYFILE)
#	touch $(KEYACCESS); chmod 644 $(KEYACCESS)
	cp keyinfo.1 keyinit.1 key.1 $(MAN_DIR)/man1
	cd $(MAN_DIR)/man1; chmod 644 keyinfo.1 keyinit.1 key.1
	cp skey.access.5 $(MAN_DIR)/man5
	cd $(MAN_DIR)/man5; chmod 644 skey.access.5

keyinit: skeyinit.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o keyinit skeyinit.o $(LIB) $(SYSLIBS)

key:    skey.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -s -o key skey.o $(LIB) $(SYSLIBS)

keyinfo: keyinfo.SH Makefile
	sed -e "s;KEYFILE;$(KEYFILE);" keyinfo.SH > keyinfo
	chmod 755 keyinfo

keyinit.1: keyinit.1.SH Makefile
	sed -e "s;KEYFILE;$(KEYFILE);" keyinit.1.SH > keyinit.1

skey.access.5: skey.access.5.SH Makefile
	sed -e "s;KEYACCESS;$(KEYACCESS);" skey.access.5.SH > skey.access.5

skeyaccess: skeyaccess.c Makefile skey.h
	$(CC) -DTEST $(CFLAGS) $(LDFLAGS) -s -o $@ skeyaccess.c $(SYSLIBS)

skeylogin.o keyinit.o skey.o $(OBJS):	skey.h Makefile
skeysubr.o mdx.o:	mdx.h
mdx.o:	md4c.c md5c.c md4.h md5.h
