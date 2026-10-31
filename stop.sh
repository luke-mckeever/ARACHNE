#!/usr/bin/env sh
# ARACHNE OSINT - stop the running server (Linux / macOS)
# Usage: ./stop.sh          stops the server started from this folder
#        ./stop.sh 9000     stops whatever ARACHNE is listening on port 9000
cd "$(dirname "$0")" || exit 1
PIDFILE="data/arachne.pid"
PID=""
PORT="$1"

if [ -z "$PORT" ] && [ -f "$PIDFILE" ]; then
  read -r PID PORT < "$PIDFILE"
  # ignore a stale PID file left by a crashed server
  kill -0 "$PID" 2>/dev/null || PID=""
fi
PORT="${PORT:-8777}"

# fall back to whatever is listening on the port
if [ -z "$PID" ]; then
  if command -v lsof >/dev/null 2>&1; then
    PID=$(lsof -ti "tcp:$PORT" -sTCP:LISTEN 2>/dev/null | head -n 1)
  elif command -v fuser >/dev/null 2>&1; then
    PID=$(fuser "$PORT/tcp" 2>/dev/null | awk '{print $1}')
  fi
fi

if [ -z "$PID" ]; then
  echo "ARACHNE is not running on port $PORT."
  rm -f "$PIDFILE"
  exit 0
fi

kill "$PID" 2>/dev/null
for _ in 1 2 3 4 5; do
  kill -0 "$PID" 2>/dev/null || break
  sleep 1
done
kill -0 "$PID" 2>/dev/null && kill -9 "$PID" 2>/dev/null
rm -f "$PIDFILE"
echo "ARACHNE stopped (process $PID, port $PORT)."
