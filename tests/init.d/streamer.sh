#!/bin/sh

PATH=./utils/
SERVICE=streamer
OPTIONS="-R /tmp"
OPTIONS="${OPTIONS} -s 10 -t"
if [ x$USER != x ]; then
	OPTIONS="${OPTIONS} -u $USER"
fi
case "$1" in
	start)
                echo ${PATH}${SERVICE} -n reverse ${OPTIONS} -D
                ${PATH}${SERVICE} -n reverse ${OPTIONS} -D
                ${PATH}${SERVICE} -n dummy ${OPTIONS} -D
		;;
	stop)
		killall ${SERVICE}
		;;
	*)
		echo "Usage: $0 {start|stop}"
	        exit 1
esac
