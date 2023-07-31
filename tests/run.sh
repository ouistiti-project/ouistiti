#!/bin/sh

TESTDIR=$(dirname $0)/
SRCDIR=src/
PWD=$(pwd)
DEFAULTPORT=8080
. ./.config

CONTINUE=0
GCOV=0
ALL=0
NOERROR=0
while [ -n "$1" ]; do
case $1 in
	-D)
		DEBUG=1
		;;
	-C)
		CONTINUE=1
		;;
	-GCOV)
		GCOV=1
		;;
	-V)
		ENV="valgrind --leak-check=full --show-leak-kinds=all"
		;;
	-I)
		INFO=1
		;;
	-A)
		ALL=1
		TESTS=$(find $TESTDIR -maxdepth 1 -name test*[0-9] | sort)
		;;
	-N)
		NOERROR=1
		;;
	-P)
		DEFAULTPORT=$1
		shift
		;;
	-h)
		printf "$0 <-I> <-D> <-C> <-GCOV> test/test[09]*\n"
		printf "\t-D    run test on an existing server\n"
		printf "\t-A    run all tests\n"
		printf "\t-N    continue running after error\n"
		printf "\t-I    display information about test and the response\n"
		printf "\t-C    leave ouistiti running for the next test\n"
		printf "\t-GCOV run lcov to display the code coverage\n"
		exit 1
		;;
	*)
		TESTS=$1
		;;
esac
shift
done

echo $TESTS

TMPRESPONSE=/tmp/ouistiti.test

AWK=awk
SED=sed
WC=wc
CURL=curl
WGET=wget
#USER=$(ls -l $0 | ${AWK} '{print $3}')
USER=$(ps -p $$ -o user --no-headers)
TESTCLIENT="./host/utils/testclient"
LD_LIBRARY_PATH=${SRCDIR}:$TESTDIR../libhttpserver/src/:$TESTDIR../libhttpserver/src/httpserver/:$TESTDIR../utils/
LD_PRELOAD=libouistiti.so:libouibsocket.so:libouihash.so:libouiutils.so

export LD_LIBRARY_PATH LD_PRELOAD

if [ -z "$INFO" ]; then
CURLOUT="-o /dev/null"
fi

TESTERROR=""

rm -f ${TESTDIR}run.pid

config () {
	CONFIG=$1

	cp ${TESTDIR}conf/${CONFIG}.in ${TESTDIR}conf/${CONFIG}
	${SED} -i "s/\%PWD\%/$(echo $PWD | ${SED} 's/\//\\\//g')/g" ${TESTDIR}conf/${CONFIG}
	${SED} -i "s/\%USER\%/$USER/g" ${TESTDIR}conf/${CONFIG}

}

start () {
	TARGET=$1
	CONFIG=$2

	export OUISTITI_MODULES_PATH=./src:./staging
	ARGUMENTS=$ARGUMENTS" -s 1"
	ARGUMENTS=$ARGUMENTS" -f ${TESTDIR}conf/${CONFIG}"
	ARGUMENTS=$ARGUMENTS" -P ${TESTDEFAULTPORT}"
	ARGUMENTS=$ARGUMENTS" -M \"\""
	ARGUMENTS=$ARGUMENTS" -p ${TESTDIR}run.pid"
	if [ -n "$INFO" ]; then
		echo ${SRCDIR}${TARGET} ${ARGUMENTS}
		echo "******************************"
		cat ${TESTDIR}conf/${CONFIG}
	fi
	${ENV} ${SRCDIR}${TARGET} ${ARGUMENTS} -D
	PID=$(cat ${TESTDIR}run.pid)
	echo "${TARGET} started with pid ${PID}"
	sleep 1
}

stop () {
	TARGET=$1

	if [ -f ${TESTDIR}run.pid ]; then
		${SRCDIR}${TARGET} -p ${TESTDIR}run.pid -K
	else
		killall $(echo $TARGET | ${AWK} '{print $1}')
	fi
	sleep 1
	if [ -f ${TESTDIR}run.pid ]; then
		killall -9 $(echo $TARGET | ${AWK} '{print $1}')
		rm -f ${TESTDIR}run.pid
	fi
}

test () {
	TEST=$1

	unset CMDREQUEST
	unset FILEDATA
	unset PREPARE
	unset CURLPARAM
	unset TESTREQUEST
	unset TESTRESPONSE
	unset TESTCODE
	unset TESTHEADERLEN
	unset TESTCONTENTLEN
	unset TESTOPTION
	unset ASYNC_PID
	unset PREPARE_ASYNC
	unset PREPARE
	unset PID
	TESTDEFAULTPORT=$DEFAULTPORT
	TESTRESPONSE=$(basename ${TEST})_rs.txt
	if [ -e ${TESTDIR}$(basename ${TEST})_rq.txt ]; then
		TESTREQUEST=$(basename ${TEST})_rq.txt
	fi
	DISABLED=0
	. $TEST
	TESTOPTION="${TESTOPTION} -p ${TESTDEFAULTPORT}"

	echo
	echo "******************************"
	echo $TEST
	echo $DESC
	if [ $DISABLED -eq 1 ]; then
		return
	fi

	if [ -n "$FILEDATA" ]; then
		cp ${TESTDIR}htdocs/${FILE}.in ${TESTDIR}htdocs/${FILE}
		${SED} -i "s/\%FILEDATA\%/$(echo $FILEDATA | ${SED} 's/\//\\\//g')/g" ${TESTDIR}htdocs/${FILE}
		TESTCONTENTLEN=$(cat ${TESTDIR}htdocs/${FILE} | ${WC} -c)
	fi

	config $CONFIG

	if [ -n "$PREPARE_ASYNC" ]; then
		$PREPARE_ASYNC &
		ASYNC_PID=$!
		sleep 1
	fi

	if [ -n "$PREPARE" ]; then
		eval $PREPARE
	fi

	if [ $CONTINUE -eq 0 ] && [ -z $DEBUG ]; then
		start "$TARGET" $CONFIG
	fi

	echo "******************************"
	if [ -n "$CURLPARAM" ]; then
		$CURL $CURLOUT -f -s -S $CURLPARAM > $TMPRESPONSE
	fi
	if [ -n "$WGETURL" ]; then
		$WGET --no-check-certificate --user $USER --password foobar -S -q -O - $WGETURL 2> $TMPRESPONSE.tmp
		#$WGET --no-check-certificate --user $USER --password foobar -S -O - $WGETURL
		cat $TMPRESPONSE.tmp | sed 's/^  //g' > $TMPRESPONSE
	fi
	if [ -n "$TESTREQUEST" ]; then
		if [ -n "$INFO" ]; then
			cat ${TESTDIR}$TESTREQUEST
			echo "******************************"
			echo
		fi
		echo cat ${TESTDIR}$TESTREQUEST' |' $TESTCLIENT $TESTOPTION
		cat ${TESTDIR}$TESTREQUEST | $TESTCLIENT $TESTOPTION > $TMPRESPONSE
	fi
	if [ -n "$CMDREQUEST" ]; then
		if [ -n "$INFO" ]; then
			$CMDREQUEST
			echo "******************************"
			echo
		fi
		$CMDREQUEST | $TESTCLIENT $TESTOPTION > $TMPRESPONSE
	fi
	ERR=0
	if [ -n "$INFO" ]; then
		cat $TMPRESPONSE
		echo "******************************"
		echo $TEST
		echo $DESC
		rescode=$TESTCODE
		resheaderlen=$TESTHEADERLEN
		rescontentlen=$TESTCONTENTLEN
	else
		if [ -e ${TMPRESPONSE} -a ${TESTRESPONSE} != "none" ]; then
			diff -a ${TMPRESPONSE} ${TESTDIR}${TESTRESPONSE} | grep -a '^>.*$'
			if [ ! $? -eq 1 ]; then
				ERR=4
			fi
		fi
		rescode=$(cat $TMPRESPONSE | ${AWK} '/^HTTP\/1\.1 .* .*/{print $2}' )
		resheaderlen=$TESTHEADERLEN
		rescontentlen=$TESTCONTENTLEN
		#resheaderlen=$(echo $result | ${AWK} -F= 't$0 == t {print $0}' | wc -c)
		#rescontentlen=$(echo $result | ${AWK} -F= 't$0 != t {print $0}' | wc -c)
	fi
	if [ -n "$TESTCODE"  ]; then
		if [ "x$rescode" = "x" ]; then
			rescode="none"
		fi
		echo $rescode | grep $TESTCODE > /dev/null
		if [ $? -eq 1 ]; then
			echo "result code error $rescode instead $TESTCODE"
			ERR=1
		fi
	fi
	if [ -n "$TESTHEADERLEN" -a x$resheaderlen != x$TESTHEADERLEN ]; then
		echo "header error received $resheaderlen instead $TESTHEADERLEN"
		ERR=2
	fi
	if [ -n "$TESTCONTENTLEN" -a x$rescontentlen != x$TESTCONTENTLEN ]; then
		echo "content error received $rescontentlen instead $TESTCONTENTLEN"
		ERR=3
	fi
	if [ ! $ERR -eq 0 ]; then
		echo "$TEST quits on error"
		stop $TARGET
		if [ $NOERROR -eq 1 ]; then
			TESTERROR="${TESTERROR} $TEST"
		else
			exit 1
		fi
	else
		echo "$TEST completed"
		echo "status        : $TESTCODE"
		if [ x"$TESTHEADERLEN" != x ]; then
			echo "header  length: $TESTHEADERLEN"
		fi
		if [ x"$TESTCONTENTLEN" != x ]; then
			echo "content length: $TESTCONTENTLEN"
		fi
	fi
	if [ $CONTINUE -eq 0 ]; then
		stop $TARGET
	fi
	if [ x$ASYNC_PID != x ]; then
		kill $ASYNC_PID
	fi
}

TARGET="ouistiti"
stop ${TARGET}
for TEST in ${TESTS}
do
	test $TEST
done

if [ ${ALL} -eq 1 ]; then
	${SRCDIR}${TARGET} -h
	${SRCDIR}${TARGET} -V
	${SRCDIR}${TARGET} -C -f ${TESTDIR}conf/test1.conf
fi
if [ ${GCOV} -eq 1 ]; then
	make DEBUG=y gcov
	lcov --directory . -c -o rapport.info
	genhtml -o ./rapport -t "couverture de code des tests" rapport.info
	firefox ./rapport/index.html
fi
if [ -n "$TESTERROR" ]; then
	echo $TESTERROR
	exit 1
fi
