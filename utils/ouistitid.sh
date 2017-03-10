#!/bin/sh
# Start/stop/restart ouistiti, a small and fast HTTP server

# Start ouistiti:
DAEMONDIR=/usr/sbin
DAEMON=ouistiti
DAEMONPARAMS=-D
daemon_start() {
  if [ -x ${DAEMONDIR}/${DAEMON} ]; then
    echo "Starting ${DAEMON} daemon:  ${DAEMONDIR}/${DAEMON}"
    ${DAEMONDIR}/${DAEMON} ${DAEMONPARAMS}
    #nohup ${DAEMONDIR}/${DAEMON} &
  fi
}

# Stop inetd:
daemon_stop() {
  killall ${DAEMON}
}

# Restart inetd:
daemon_restart() {
  daemon_stop
  sleep 1
  daemon_start
}

case "$1" in
'start')
  daemon_start
  ;;
'stop')
  daemon_stop
  ;;
'restart')
  daemon_restart
  ;;
*)
  echo "usage $0 start|stop|restart"
esac
