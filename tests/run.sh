#!/bin/sh

. $1

CURL=curl
SRCDIR=./src/
TESTDIR=./tests/
PWD=$(pwd)
USER=$(ls -l $1 | gawk '{print $3}')
TESTCLIENT=./utils/testclient
HTTPPARSER=./utils/httpparser

TARGET=ouistiti

if [ -n "$FILEDATA" ]; then
	cp ${TESTDIR}htdocs/${FILE}.in ${TESTDIR}htdocs/${FILE}
	sed -i "s/\%FILEDATA\%/$(echo $FILEDATA | sed 's/\//\\\//g')/g" ${TESTDIR}htdocs/${FILE}
fi

cp ${TESTDIR}conf/${CONFIG}.in ${TESTDIR}conf/${CONFIG}
sed -i "s/\%PWD\%/$(echo $PWD | sed 's/\//\\\//g')/g" ${TESTDIR}conf/${CONFIG}
sed -i "s/\%USER\%/$USER/g" ${TESTDIR}conf/${CONFIG}

${SRCDIR}${TARGET} -f ${TESTDIR}conf/${CONFIG} &
PID=$!

echo "${TARGET} started with pid ${PID}"
sleep 0.5

if [ -n "$CURLPARAM" ]; then
	result=$($CURL -o /dev/null -f -s -S -w "%{http_code} %{size_header} %{size_download}" $CURLPARAM)

fi
if [ -n "$TESTREQUEST" ]; then
	result=$(cat ${TESTDIR}$TESTREQUEST | $TESTCLIENT | $HTTPPARSER)
fi
rescode=$(echo $result | gawk '{print $1}')
resheaderlen=$(echo $result | gawk '{print $2}')
rescontentlen=$(echo $result | gawk '{print $3}')

echo ""

if [ -n "$TESTCODE" -a x$rescode != x$TESTCODE ]; then
	echo "result code error $rescode instead $TESTCODE"
	kill $PID 2> /dev/null
	exit -1
fi
if [ -n "$TESTHEADERLEN" -a x$resheaderlen != x$TESTHEADERLEN ]; then
	echo "header error receive $resheaderlen instead $TESTHEADERLEN"
	kill $PID 2> /dev/null
	exit -1
fi
if [ -n "$TESTCONTENTLEN" -a x$rescontentlen != x$TESTCONTENTLEN ]; then
	echo "content error receive $rescontentlen instead $TESTCONTENTLEN"
	kill $PID 2> /dev/null
	exit -1
fi
echo "test $1 complete"
kill $PID 2> /dev/null
