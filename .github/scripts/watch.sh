#!/usr/bin/env bash
# Usage: watch.sh [options] [cfg file] [app and command....]
#
# Options:
#   --tee-out-to FILE    Tee stdout to FILE
#   --tee-err-to FILE    Tee stderr to FILE
#

# Kill a process, if it is still running.
# Use:
#  silent_kill $PID
silent_kill() {
    local pid=$1
    if kill -0 "$pid" 2>/dev/null && ! kill "$pid" 2>/dev/null; then
        echo "[WARN] Failed to kill process $pid" >&2
    fi
}

quitter() {
    silent_kill "$PID"
    exit
}
trap quitter SIGINT

# Parse optional tee arguments
tee_stdout=""
tee_stderr=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --tee-out-to)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --tee-out-to requires a file path argument." >&2
                exit 1
            fi
            tee_stdout="$2"
            shift 2
            ;;
        --tee-err-to)
            if [[ -z "$2" || "$2" == --* ]]; then
                echo "Error: --tee-err-to requires a file path argument." >&2
                exit 1
            fi
            tee_stderr="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

file_to_watch="$1"
shift

file_signature() {
    if [[ ! -e "$1" ]]; then
        echo "missing"
        return
    fi

    if stat -c '%i:%s:%Y' "$1" >/dev/null 2>&1; then
        stat -c '%i:%s:%Y' "$1"
        return
    fi

    stat -f '%i:%z:%m' "$1"
}

wait_for_change_to() {
    if command -v inotifywait >/dev/null 2>&1; then
        local watch_dir
        local watch_name
        local changed_file

        watch_dir=$(dirname "${file_to_watch}")
        watch_name=$(basename "${file_to_watch}")

        echo "[INFO] inotifywaiting to [${file_to_watch}] via [${watch_dir}]"
        while true; do
            changed_file=$(inotifywait -q \
                -e close_write \
                -e moved_to \
                -e delete \
                -e attrib \
                --format '%f' \
                "${watch_dir}")

            if [[ "${changed_file}" == "${watch_name}" ]]; then
                return
            fi
        done
    else
        local m
        local n

        m=$(file_signature "${file_to_watch}")
        echo "[INFO] stat checking [${file_to_watch}] from [${m}]"
        while true; do
            sleep 1
            n=$(file_signature "${file_to_watch}")
            echo "[INFO] stat checking [${file_to_watch}] from [${m} != ${n}]"
            if [[ "${m}" != "${n}" ]]; then
                return
            fi
        done
    fi
}

while true; do
    # Build command with optional tee for stdout/stderr
    if [[ -n "$tee_stdout" ]] || [[ -n "$tee_stderr" ]]; then
        # Ensure log directories exist
        [[ -n "$tee_stdout" ]] && mkdir -p "$(dirname "$tee_stdout")"
        [[ -n "$tee_stderr" ]] && mkdir -p "$(dirname "$tee_stderr")"

        # Run command with tee for stdout and/or stderr
        if [[ -n "$tee_stdout" ]] && [[ -n "$tee_stderr" ]]; then
            # Both stdout and stderr tee
            "$@" > >(tee -a "$tee_stdout") 2> >(tee -a "$tee_stderr" >&2) &
        elif [[ -n "$tee_stdout" ]]; then
            # Only stdout tee
            "$@" > >(tee -a "$tee_stdout") &
        else
            # Only stderr tee
            "$@" 2> >(tee -a "$tee_stderr" >&2) &
        fi
    else
        # No tee, run normally
        "$@" &
    fi

    PID=$!
    wait_for_change_to "${file_to_watch}"
    silent_kill "$PID"
    echo "[INFO] restarting [${PID}] due to modified file"
done
