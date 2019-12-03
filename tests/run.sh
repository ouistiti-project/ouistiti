#!/bin/sh

CONTINUE=0
while [ -n "$1" ]; do
case $1 in
	-D)
		DEBUG=1
		;;
	-C)
		CONTINUE=1
		;;
	*)
		TEST=$1
		;;
esac
shift
done

TESTDIR=$(dirname $TEST)/
SRCDIR=$TESTDIR../src/
PWD=$(pwd)

TESTRESPONSE=$(basename ${TEST})_rs.txt
TMPRESPONSE=/tmp/ouistiti.test

. $TEST

TARGET=ouistiti

AWK=awk
SED=sed
WC=wc
CURL=curl
USER=$(ls -l ${SRCDIR}/${TARGET} | ${AWK} '{print $3}')
TESTCLIENT="./host/utils/testclient"
LD_LIBRARY_PATH=${SRCDIR}:$TESTDIR../libhttpserver/src/:$TESTDIR../libhttpserver/src/httpserver/
if [ -z "$DEBUG" ]; then
HTTPPARSER="./host/utils/httpparser"
CURLOUT="-o /dev/null"
fi


echo $DESC

if [ -n "$FILEDATA" ]; then
	cp ${TESTDIR}htdocs/${FILE}.in ${TESTDIR}htdocs/${FILE}
	${SED} -i "s/\%FILEDATA\%/$(echo $FILEDATA | ${SED} 's/\//\\\//g')/g" ${TESTDIR}htdocs/${FILE}
	TESTCONTENTLEN=$(cat ${TESTDIR}htdocs/${FILE} | ${WC} -c)
fi

cp ${TESTDIR}conf/${CONFIG}.in ${TESTDIR}conf/${CONFIG}
${SED} -i "s/\%PWD\%/$(echo $PWD | ${SED} 's/\//\\\//g')/g" ${TESTDIR}conf/${CONFIG}
${SED} -i "s/\%USER\%/$USER/g" ${TESTDIR}conf/${CONFIG}

if [ -n "$PREPARE" ]; then
	$PREPARE
fi

if [ -n "$DEBUG" ]; then
	echo ${SRCDIR}${TARGET} -f ${TESTDIR}conf/${CONFIG}
fi

WHOAMI=$(whoami)
if [ -n $WHOAMI -a x$WHOAMI = xroot ]; then
	${SRCDIR}${TARGET} -s 1 -f ${TESTDIR}conf/${CONFIG} &
	PID=$!

	echo "${TARGET} started with pid ${PID}"
	sleep 2
else
	echo "${TARGET} must be running or relaunch as root"
fi


if [ -n "$DEBUG" ]; then
	echo "******************************"
	cat ${TESTDIR}conf/${CONFIG}
fi
echo "******************************"
if [ -n "$CURLPARAM" ]; then
	$CURL $CURLOUT -f -s -S $CURLPARAM > $TMPRESPONSE
fi
if [ -n "$TESTREQUEST" ]; then
	if [ -n "$DEBUG" ]; then
		cat ${TESTDIR}$TESTREQUEST
		echo "******************************"
		echo
	fi
	cat ${TESTDIR}$TESTREQUEST | $TESTCLIENT > $TMPRESPONSE
fi
if [ -n "$CMDREQUEST" ]; then
	if [ -n "$DEBUG" ]; then
		$CMDREQUEST
		echo "******************************"
		echo
	fi
	$CMDREQUEST | $TESTCLIENT > $TMPRESPONSE
fi
if [ -n "$DEBUG" ]; then
	cat $TMPRESPONSE
	echo "******************************"
	echo $DESC
	rescode=$TESTCODE
	resheaderlen=$TESTHEADERLEN
	rescontentlen=$TESTCONTENTLEN
else
	cat $TMPRESPONSE | diff - ${TESTDIR}${TESTRESPONSE} | grep '^>'
	rescode=$(cat $TMPRESPONSE | ${AWK} '/^HTTP\/1\.1 .* .*/{print $2}')
	resheaderlen=$(echo $result | ${AWK} -F= 't$0 == t {print $0}' | wc -c)
	rescontentlen=$(echo $result | ${AWK} -F= 't$0 != t {print $0}' | wc -c)
fi
ERR=0
if [ -n "$TESTCODE" -a x$rescode != x$TESTCODE ]; then
	echo "result code error $rescode instead $TESTCODE"
	ERR=1
	kill $PID 2> /dev/null
fi
if [ -n "$TESTHEADERLEN" -a x$resheaderlen != x$TESTHEADERLEN ]; then
	echo "header error received $resheaderlen instead $TESTHEADERLEN"
	ERR=2
	kill $PID 2> /dev/null
fi
if [ -n "$TESTCONTENTLEN" -a x$rescontentlen != x$TESTCONTENTLEN ]; then
	echo "content error received $rescontentlen instead $TESTCONTENTLEN"
	ERR=3
	kill $PID 2> /dev/null
fi
if [ ! $ERR -eq 0 ]; then
	exit $ERR
else
	echo "test $1 complete"
	echo "status        : $TESTCODE"
	if [ x"$TESTHEADERLEN" != x ]; then
		echo "header  length: $TESTHEADERLEN"
	fi
	if [ x"$TESTCONTENTLEN" != x ]; then
		echo "content length: $TESTCONTENTLEN"
	fi
fi
if [ $CONTINUE -eq 0 ]; then
	kill $PID 2> /dev/null
fi
