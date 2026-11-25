#!/bin/bash
# with-key.sh: hand Apple's tools the App Store Connect key as a file, for one
# command. xcodebuild, altool and notarytool take a key path only.
#
#   with-key.sh <command> [args...]   run <command>; every @ASC_KEY@ in its
#                                     arguments becomes the key file's path
#   with-key.sh --check               exit 0 when the Keychain holds ASC_KEY_ID's
#                                     key, 1 when it does not, 3 when it is locked
#                                     (4: cannot tell, stop; attributes only)
#
# Run it as `storekeeper with-key`. The key comes from the Keychain (key.py beside
# this file owns where). It is written to AuthKey_<ASC_KEY_ID>.p8 in a fresh
# folder (mktemp -d, mode 700; the file 600), and the folder is deleted when this
# script exits, on INT, TERM, HUP and QUIT too (a command that ignores TERM is
# killed after 5 seconds). SIGKILL and a power loss cannot be caught, so each run
# first deletes this user's own key folders (storekeeper-key.<PID>.XXXXXXXX,
# folders only) older than STALE_MINUTES whose PID is no longer alive. The arguments are substituted, never evaluated.
# The command's exit code is this script's. The key is never printed. Every tool
# is called by its absolute path: PATH is not trusted with the key.
set -u
# This file's folder by parameter expansion and builtins: no tool from PATH.
src="${BASH_SOURCE[0]}"
case "$src" in
  */*) here="${src%/*}" ;;
  *) here="." ;;
esac
here="$(cd "$here" && pwd)"
py="${STOREKEEPER_PYTHON:-/usr/bin/python3}"
STALE_MINUTES=360

if [[ "${1:-}" == "--check" ]]; then
  exec "$py" -I "$here/_run.py" key check
fi
if [[ $# -eq 0 ]]; then
  /usr/bin/sed -n '4,9p' "$0" >&2
  exit 2
fi
if [[ ! "${ASC_KEY_ID:-}" =~ ^[A-Z0-9]+$ ]]; then
  echo "with-key: ASC_KEY_ID is not set (or is not a key ID)" >&2
  echo "fix: export ASC_KEY_ID" >&2
  exit 2
fi

tmp="${TMPDIR:-/tmp}"
swept=0
while IFS= read -r -d '' old; do
  # The name holds the PID of the run that made it: a run still alive keeps its
  # folder, however old (a long upload). A dead run's folder goes.
  [[ "${old##*/}" =~ ^storekeeper-key\.([0-9]+)\.[A-Za-z0-9]{8}$ ]] || continue
  if kill -0 "${BASH_REMATCH[1]}" 2>/dev/null; then
    continue
  fi
  /bin/rm -rf -- "$old" && swept=$((swept + 1))
done < <(/usr/bin/find "$tmp" -mindepth 1 -maxdepth 1 -type d \
  -name 'storekeeper-key.*.*' -user "$(/usr/bin/id -u)" -mmin +"$STALE_MINUTES" \
  -print0 2>/dev/null)
if [[ $swept -gt 0 ]]; then
  echo "with-key: removed $swept stale key folder(s) left by a hard kill" >&2
fi

umask 077
dir="$(/usr/bin/mktemp -d "$tmp/storekeeper-key.$$.XXXXXXXX")" || exit 1
/bin/chmod 700 "$dir"
child=""
trap '/bin/rm -rf "$dir"' EXIT
stop() {
  if [[ -n "$child" ]]; then
    kill -TERM "$child" 2>/dev/null
    # A command that ignores TERM gets 5 seconds, then KILL: the folder must go.
    local tries=0
    while [[ $tries -lt 50 ]] && kill -0 "$child" 2>/dev/null; do
      /bin/sleep 0.1
      tries=$((tries + 1))
    done
    kill -KILL "$child" 2>/dev/null
    wait "$child" 2>/dev/null
  fi
  exit "$1"
}
trap 'stop 129' HUP
trap 'stop 130' INT
trap 'stop 143' TERM
trap 'stop 131' QUIT

key="$dir/AuthKey_$ASC_KEY_ID.p8"
# key.py's errors name the fix, never the value.
"$py" -I "$here/_run.py" key pem >"$key" || exit 1
/bin/chmod 600 "$key"

args=()
for arg in "$@"; do
  # Cut and join, no ${x//pat/rep}: bash 5.2 reads & in a replacement as the
  # match, and macOS's bash 3.2 keeps quotes put around it to stop that.
  out="" rest="$arg"
  while [[ "$rest" == *@ASC_KEY@* ]]; do
    out+="${rest%%@ASC_KEY@*}$key"
    rest="${rest#*@ASC_KEY@}"
  done
  args+=("$out$rest")
done
# In the background so a signal reaches the traps at once; <&0 keeps stdin.
"${args[@]}" <&0 &
child=$!
# Its exit is this script's: the last command's status (no `exit`, which would
# hide the traps' calls of stop from shellcheck).
wait "$child"
