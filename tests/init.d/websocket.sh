#!/bin/sh

PATH=./utils/
SERVICE=websocket_echo
OPTIONS="-R /tmp"
OPTIONS="${OPTIONS} -t"
if [ x$USER != x ]; then
	OPTIONS="${OPTIONS} -u $USER"
fi
case "$1" in
	start)
		echo ${PATH}${SERVICE} -n echo ${OPTIONS} -D
		${PATH}${SERVICE} -n echo ${OPTIONS} -D
		;;
	stop)
		killall ${SERVICE}
		;;
	*)
		echo "Usage: $0 {start|stop}"
	        exit 1
esac
