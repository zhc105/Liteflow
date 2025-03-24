#!/bin/bash

# This script is used for crontab and manual operation.
# There are two modes: local, global (by default):
#   local: Start liteflow from a local folder and all configuration/log/pid
#       files are placed in local folder. This mode is typically used when you
#       have multiple liteflow copies on the same machine, which have different
#       binaries or configurations.
#   global: This is the default mode. If you have installed liteflow in global
#       position, use this mode.

# **NOTE** bash will not exit even if any command exits with non-zero.
#           the script will take care of the workflow.
set +e

PACKAGE_NAME=liteflow
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:${PATH}

# https://stackoverflow.com/a/246128
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PACKAGE_DIR=$(dirname "$SCRIPT_DIR")
PACKAGE_KEY=$(echo "$PACKAGE_DIR" | sed 's|/|_|g')

# Detect original user if running under sudo
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(eval echo ~$REAL_USER)

BIN_FILE="/usr/local/bin/liteflow"
CONF_FILE="/usr/local/etc/liteflow.conf"
LOG_FILE="/var/log/liteflow.log"
PID_FILE="/var/run/liteflow.pid"

log() {
    if [ "$1" = "-n" ]; then
        shift
        printf "[%s] %s" "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
    elif [ "$1" = "-r" ]; then
        shift
        printf "%s\n" "$*"
    else
        printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
    fi
}

# Loop through all passed arguments
# Skip the first argument (subcommand)
shifted_args=("${@:2}")
for arg in "${shifted_args[@]}"; do
  case "${arg,,}" in
    --local)
      BIN_FILE="$PACKAGE_DIR/bin/liteflow"
      CONF_FILE="$PACKAGE_DIR/etc/liteflow.conf"
      LOG_FILE="$PACKAGE_DIR/log/liteflow.log"
      PID_FILE="$PACKAGE_DIR/run/liteflow.pid"

      mkdir -p "$(dirname "$LOG_FILE")"
      mkdir -p "$(dirname "$PID_FILE")"
      ;;
  esac
done

CMD="$BIN_FILE -c $CONF_FILE"

check_pid() {
    # Check if PID file exists
    if [ ! -f "$PID_FILE" ]; then
        return 1
    fi

    PID=$(cat "$PID_FILE")
    if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
        log "Error: Invalid PID value in $PID_FILE"
        return 2
    fi

    if kill -0 "$PID" 2>/dev/null; then
        return 0  # Process is running
    else
        return 3  # PID file exists but process not running
    fi
}

start() {
    check_pid
    case $? in
        0)
            log "${PACKAGE_NAME} is already running (PID $(cat $PID_FILE))"
            return 1
            ;;
        2)
            return 1
            ;;
        3)
            log "Stale PID file found, removing."
            rm -f "$PID_FILE"
            ;;
    esac

    log -n "Starting ${PACKAGE_NAME}: "
    ulimit -c unlimited
    ulimit -n 65536

    if [ ! -d /etc/logrotate.d ]; then
        log -r "Logrotate directory not found, using logger output. Please install logrotate if needed."

        # Don't use nohup directly since it will print "nohup: redirecting stderr to stdout".
        # But if we use:
        # nohup bash -c "/usr/bin/env TZ=Asia/Shanghai $CMD 2>&1 | /usr/bin/logger -t ${PACKAGE_NAME}" >/dev/null 2>&1 &
        # Then the PID $! will be the parent "bash -c" PID.
        # That's why we use `disown` here.
        /usr/bin/env TZ=Asia/Shanghai $CMD 2>&1 | /usr/bin/logger -t ${PACKAGE_NAME} &
        disown
    else
        ROTATE_CONFIG="$LOG_FILE {
    daily
    rotate 7
    size=100k
    compress
    copytruncate
    missingok
    notifempty
    nocreate
    postrotate
    endscript
}"
        ROTATE_FILE="/etc/logrotate.d/liteflow.$PACKAGE_KEY"

        write_rotate_config() {
            echo "$ROTATE_CONFIG" | sudo tee "$ROTATE_FILE" > /dev/null
        }

        if [ -f "$ROTATE_FILE" ]; then
            CURRENT_CONTENT=$(cat "$ROTATE_FILE")
            if [ "$CURRENT_CONTENT" != "$ROTATE_CONFIG" ]; then
                if [ -w "$ROTATE_FILE" ]; then
                    echo "$ROTATE_CONFIG" > "$ROTATE_FILE"
                else
                    write_rotate_config
                fi
                log -r "Updated logrotate config at $ROTATE_FILE."
            else
                log -r "Logrotate config unchanged, skipping update."
            fi
        else
            if [ -w "$(dirname "$ROTATE_FILE")" ]; then
                echo "$ROTATE_CONFIG" > "$ROTATE_FILE"
            else
                write_rotate_config
            fi
            log -r "Created new logrotate config at $ROTATE_FILE."
        fi

        /usr/bin/env TZ=Asia/Shanghai $CMD 2>&1 >> $LOG_FILE &
        disown
    fi

    echo $! > "$PID_FILE"
    log "${PACKAGE_NAME} started (PID $(cat $PID_FILE))."
}

stop() {
    log -n "Stopping ${PACKAGE_NAME}: "
    check_pid
    case $? in
        0)
            pid=$(cat $PID_FILE)
            kill -9 $pid >/dev/null 2>&1 || true
            rm -f "$PID_FILE"
            log -r "${PACKAGE_NAME} stopped (PID $pid)."
            ;;
        1)
            log -r "No PID file found."
            return 1
            ;;
        2)
            return 1
            ;;
        3)
            log -r "Stale PID file, removing."
            rm -f "$PID_FILE"
            log "${PACKAGE_NAME} has not started."
            ;;
    esac
}

restart() {
    stop || true
    sleep 1
    start
}

reload() {
    log -n "Reloading ${PACKAGE_NAME}: "
    check_pid
    case $? in
        0)
            kill -10 $(cat "$PID_FILE") >/dev/null 2>&1 || true
            log -r "${PACKAGE_NAME} reloaded (PID $(cat $PID_FILE))."
            ;;
        1)
            log -r "No PID file found."
            return 1
            ;;
        2)
            return 1
            ;;
        3)
            log -r "Stale PID file, removing."
            rm -f "$PID_FILE"
            return 1
            ;;
    esac
}

status() {
    check_pid
    case $? in
        0)
            log "${PACKAGE_NAME} is running (PID $(cat $PID_FILE))"
            ;;
        1)
            log "${PACKAGE_NAME} is not running (no PID file)"
            ;;
        2)
            log "${PACKAGE_NAME}: PID file is corrupt"
            ;;
        3)
            log "${PACKAGE_NAME} is not running (stale PID file)"
            ;;
    esac
}

revive() {
    check_pid
    case $? in
        0)
            log "${PACKAGE_NAME} is already running (PID $(cat $PID_FILE))."
            ;;
        *)
            log "${PACKAGE_NAME} not running. Starting..."
            start
            ;;
    esac
}

usage() {
    N=$(basename "$0")
    log "Usage: $N {start|stop|restart|reload|status|revive}" >&2
    exit 1
}

# `readlink -f` won't work on Mac, this hack should work on all systems.

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    reload)
        reload
        ;;
    restart | force-reload)
        restart
        ;;
    status)
        status
        ;;
    revive)
        revive
        ;;
    *)
        usage
        ;;
esac

exit 0
