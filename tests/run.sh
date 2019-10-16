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

. $TEST

TARGET=ouistiti

AWK=awk
SED=sed
WC=wc
CURL=curl
TESTDIR=$(dirname $TEST)/
SRCDIR=$TESTDIR../src/
PWD=$(pwd)
USER=$(ls -l ${SRCDIR}/${TARGET} | ${AWK} '{print $3}')
TESTCLIENT="./host/utils/testclient"
LD_LIBRARY_PATH=${SRCDIR}:$TESTDIR../libhttpserver/src/:$TESTDIR../libhttpserver/src/httpserver/
if [ -z "$DEBUG" ]; then
HTTPPARSER="./host/utils/httpparser"
CURLOUT="-o /dev/null"
else
HTTPPARSER="tee /dev/null"
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


echo $DESC
echo "******************************"
cat ${TESTDIR}conf/${CONFIG}
echo "******************************"
if [ -n "$DEBUG" ]; then
	if [ -n "$CURLPARAM" ]; then
		$CURL $CURLOUT -f -s -S $CURLPARAM
	fi
	if [ -n "$TESTREQUEST" ]; then
		cat ${TESTDIR}$TESTREQUEST
		echo "******************************"
		echo
		cat ${TESTDIR}$TESTREQUEST | $TESTCLIENT
	fi
	if [ -n "$CMDREQUEST" ]; then
		$CMDREQUEST
		echo "******************************"
		echo
		$CMDREQUEST | $TESTCLIENT
	fi
	echo "******************************"
	echo $DESC
	echo "expected result  $TESTCODE"
	if [ -n $TESTHEADERLEN ]; then
		echo "expected header  $TESTHEADERLEN"
	fi
	if [ -n $TESTCONTENTLEN ]; then
		echo "expected content $TESTCONTENTLEN"
	fi
else
	if [ -n "$CURLPARAM" ]; then
		result=$($CURL $CURLOUT -f -s -S -w "%{http_code} %{size_header} %{size_download}" $CURLPARAM)

	fi
	if [ -n "$TESTREQUEST" ]; then
		#result=$(printf "$(cat ${TESTDIR}$TESTREQUEST)" | $TESTCLIENT | $HTTPPARSER)
		result=$(cat ${TESTDIR}$TESTREQUEST | $TESTCLIENT | $HTTPPARSER)
	fi
	if [ -n "$CMDREQUEST" ]; then
		result=$($CMDREQUEST | $TESTCLIENT | $HTTPPARSER)
	fi
	rescode=$(echo $result | ${AWK} '{print $1}')
	resheaderlen=$(echo $result | ${AWK} '{print $2}')
	rescontentlen=$(echo $result | ${AWK} '{print $3}')

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
	fi
fi
if [ $CONTINUE -eq 0 ]; then
	kill $PID 2> /dev/null
fi
