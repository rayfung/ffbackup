#! /bin/sh

### BEGIN INIT INFO
# Provides:          ffbackup-server
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs $remote_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start/stop ffbackup server
### END INIT INFO

# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="ffbackup system"
NAME=ffbackup-server
DAEMON=/opt/ffbackup/$NAME
DAEMON_ARGS="-d"
SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
    su ffbackup -s /bin/sh -c "$DAEMON $DAEMON_ARGS"
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
    killall "$DAEMON"
}

case "$1" in
  start)
	log_daemon_msg "Starting $DESC" "$NAME"
	do_start
	case "$?" in
		0) log_end_msg 0 ;;
		*) log_end_msg 1 ;;
	esac
	;;
  stop)
	log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0) log_end_msg 0 ;;
		*) log_end_msg 1 ;;
	esac
	;;
  status)
       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
       ;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|status}" >&2
	exit 3
	;;
esac

:
