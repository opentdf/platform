#!/usr/bin/env bash
# Usage: watch.sh [cfg file] [app and command....]
#

quitter() {
  kill "$PID"
  exit
}
trap quitter SIGINT

file_to_watch="$1"
shift

wait_for_change_to() {
  if which inotifywait; then
    echo "[INFO] inotifywaiting to [${file_to_watch}]"
    inotifywait -e modify -e move -e create -e delete -e attrib -r "${file_to_watch}"
  else
    m=$(date -r "${file_to_watch}" +%s)
    echo "[INFO] stat checking [${file_to_watch}] from [${m}]"
    while true; do
      sleep 1
      n=$(date -r "${file_to_watch}" +%s)
      echo "[INFO] stat checking [${file_to_watch}] from [${m} < ${n}]"
      if [[ $m < $n ]]; then
        return
      fi
    done
  fi
}

while true; do
  "$@" &
  PID=$!
  wait_for_change_to "${file_to_watch}"
  kill $PID
  echo "[INFO] restarting [${PID}] due to modified file"
done
