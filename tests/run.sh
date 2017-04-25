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

CURL=curl
TESTDIR=$(dirname $TEST)/
SRCDIR=$TESTDIR../src/
PWD=$(pwd)
USER=$(ls -l $TEST | gawk '{print $3}')
TESTCLIENT=./host/testclient
LD_LIBRARY_PATH=${SRCDIR}:$TESTDIR../libhttpserver/src/:$TESTDIR../libhttpserver/src/httpserver/
if [ -z "$DEBUG" ]; then
HTTPPARSER="./host/httpparser"
CURLOUT="-o /dev/null"
else
HTTPPARSER="tee /dev/null"
fi

TARGET=ouistiti

if [ -n "$FILEDATA" ]; then
	cp ${TESTDIR}htdocs/${FILE}.in ${TESTDIR}htdocs/${FILE}
	sed -i "s/\%FILEDATA\%/$(echo $FILEDATA | sed 's/\//\\\//g')/g" ${TESTDIR}htdocs/${FILE}
fi

cp ${TESTDIR}conf/${CONFIG}.in ${TESTDIR}conf/${CONFIG}
sed -i "s/\%PWD\%/$(echo $PWD | sed 's/\//\\\//g')/g" ${TESTDIR}conf/${CONFIG}
sed -i "s/\%USER\%/$USER/g" ${TESTDIR}conf/${CONFIG}

if [ -n "$DEBUG" ]; then
	echo LD_LIBRARY_PATH=${LD_LIBRARY_PATH} ${SRCDIR}${TARGET} -f ${TESTDIR}conf/${CONFIG}
fi
LD_LIBRARY_PATH=${LD_LIBRARY_PATH} ${SRCDIR}${TARGET} -f ${TESTDIR}conf/${CONFIG} &
PID=$!

echo "${TARGET} started with pid ${PID}"
sleep 2

if [ -n "$CURLPARAM" ]; then
	result=$($CURL $CURLOUT -f -s -S -w "%{http_code} %{size_header} %{size_download}" $CURLPARAM)

fi
if [ -n "$TESTREQUEST" ]; then
	result=$(cat ${TESTDIR}$TESTREQUEST | $TESTCLIENT | $HTTPPARSER)
fi

if [ -n "$DEBUG" ]; then
	echo $result
fi
rescode=$(echo $result | gawk '{print $1}')
resheaderlen=$(echo $result | gawk '{print $2}')
rescontentlen=$(echo $result | gawk '{print $3}')

echo ""

ERR=0
if [ -n "$TESTCODE" -a x$rescode != x$TESTCODE ]; then
	echo "result code error $rescode instead $TESTCODE"
	ERR=-1
	kill $PID 2> /dev/null
fi
if [ -n "$TESTHEADERLEN" -a x$resheaderlen != x$TESTHEADERLEN ]; then
	echo "header error received $resheaderlen instead $TESTHEADERLEN"
	ERR=-1
	kill $PID 2> /dev/null
fi
if [ -n "$TESTCONTENTLEN" -a x$rescontentlen != x$TESTCONTENTLEN ]; then
	echo "content error received $rescontentlen instead $TESTCONTENTLEN"
	ERR=-1
	kill $PID 2> /dev/null
fi
if [ $CONTINUE -eq 0 -a $ERR -eq 0 ]; then
	echo "test $1 complete"
	kill $PID 2> /dev/null
fi
exit $ERR
