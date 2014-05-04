#!/bin/sh
# search $KEYS for the skey string for this user OR user specified
# in 1st parameter

KEYS=KEYFILE
PATH=/bin:/usr/bin

test -f $KEYS && {
	WHO=${1-$USER}
	awk '/^'$WHO'[ 	]/ { print $2-1, $3 }' $KEYS
}
