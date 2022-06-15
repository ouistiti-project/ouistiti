#!/bin/sh
#
# Starts ouistiti.
#

SYSCONFDIR=/etc/ouistiti
RUNDIR=/var/run
SBINDIR=/usr/sbin
BINDIR=/usr/bin
LIBDIR=/usr/lib/ouistiti
SERVER=ouistiti
ORGANISATION=ouistiti
COUNTRY=fr

DAEMON=ouistiti
PIDFILE="${RUNDIR}/$DAEMON.pid"

DAEMON_ARGS="${DAEMON_ARGS} -f ${SYSCONFDIR}/${DAEMON}.conf"
DAEMON_ARGS="${DAEMON_ARGS} -W /"
DAEMON_ARGS="${DAEMON_ARGS} -D"

[ -r "/etc/default/$DAEMON" ] && . "/etc/default/$DAEMON"

init() {
	if [ ! -f ${SYSCONFDIR}/ouistiti_srv.key -a -x ${BINDIR}/gen_key ]; then
		${BINDIR}/gen_key type=rsa rsa_keysize=4096 filename=${SYSCONFDIR}/ouistiti_srv.key
	fi
	if [ ! -f  ${SYSCONFDIR}/ouistiti_srv.crt -a -x ${BINDIR}/cert_write ]; then
		AFTER=$(date +%Y%m%d%H%M%S)
		BEFORE=$(( ${AFTER} + 10000000000 ))
		${BINDIR}/cert_write selfsign=1 issuer_key=${SYSCONFDIR}/ouistiti_srv.key \
			issuer_name=CN=${SERVER},O=${ORGANISATION},C=${COUNTRY} \
			not_before=${AFTER} not_after=${BEFORE} \
			is_ca=1 max_pathlen=0 output_file=${SYSCONFDIR}/ouistiti_srv.crt
	fi
	if [ ! -f ${SYSCONFDIR}/ouistiti_srv.csr ]; then
		#CSR file useless for self-certificated website
		#send this file to SSL vendor to receive a Certificate (ouistiti_srv.crt)
		${BINDIR}/cert_req filename=${SYSCONFDIR}/ouistiti_srv.key \
			subject_name=CN=${SERVER},O=${ORGANISATION},C=${COUNTRY} \
			output_file=${SYSCONFDIR}/ouistiti_srv.csr
	fi
	if [ ! -f ${SYSCONFDIR}/ouistiti_dhparam.key ]; then
		cd ${SYSCONFDIR}
		${BINDIR}/dh_genprime
		mv dh_prime.txt ouistiti_dhparam.key
	fi
}

start() {
	printf "Starting %s: " "$DAEMON"
	start-stop-daemon -S -q -p "${PIDFILE}" -x ${DAEMON} -- ${DAEMON_ARGS}
#	${DAEMON} -p ${PIDFILE} ${DAEMON_ARGS}
	status=$?
	if [ "$status" -eq 0 ]; then
		echo "OK"
	else
		echo "FAILED"
	fi
	return $status
}
stop() {
	printf "Stopping %s: " "$DAEMON"
	status=1
	if [ -e "${PIDFILE}" ]; then
		start-stop-daemon -K -q -p "${PDIFILE}"
		status=$?
	fi
	if [ "$status" -eq 0 ]; then
		rm -f ${PIDFILE}
		echo "OK"
	else
		echo "FAILED"
	fi
	return $status
}
restart() {
	stop
	start
}

case "$1" in
  start)
	#init
	start
	;;
  stop)
	stop
	;;
  restart|reload)
	restart
	;;
  *)
	echo "Usage: $0 {start|stop|restart}"
	exit 1
esac

exit $?

