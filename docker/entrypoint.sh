#!/usr/bin/env bash
#
# Starts the whole exchange inside one container and ties their lifetimes
# together: if any single service exits, this kills the rest and exits
# non-zero so the container restarts as a unit.
#
# That is deliberate. A container whose feed has died but whose UI still
# answers is worse than one that is down: it looks alive, serves a frozen
# market, and nothing tells a visitor the difference. Docker's restart policy
# is the supervisor; this script only makes sure a partial failure becomes a
# whole-container failure.
#
# Everything is configured by environment variable so the image is the same
# locally and deployed. Defaults are the loopback values, so running the image
# with no configuration behaves like ./demo.sh.

set -euo pipefail

BIN=/usr/local/bin/services
DATA=${DATA_DIR:-/data}

BIND=${BIND:-0.0.0.0}
RATE=${RATE:-2}
NUM_ACCOUNTS=${NUM_ACCOUNTS:-20}
START_BOT=${START_BOT:-yes}

# What the browser is told to talk to. These are public addresses and are not
# the addresses these services use to reach each other, which stay loopback.
#
# Both spellings of the UI address, and they must stay equal to
# DEFAULT_UI_ORIGINS in services/src/cors.rs. A browser treats
# http://localhost:3001 and http://127.0.0.1:3001 as two different origins, so
# with only one listed the visitor who types the other one loads the page,
# signs an order, and the browser then refuses to send it. Passing this as
# --ui-origin below replaces the binary default, so a single value here would
# undo the reason the binary has two.
UI_ORIGIN=${UI_ORIGIN:-http://127.0.0.1:3001,http://localhost:3001}
PUBLIC_FEED_URL=${PUBLIC_FEED_URL:-http://127.0.0.1:3000}
PUBLIC_INBOX_URL=${PUBLIC_INBOX_URL:-http://127.0.0.1:3002}

# The reverse proxy whose X-Forwarded-For may be believed. Empty means believe
# nobody and rate limit on the socket address, which is the safe default: with
# no value set, a misconfigured deployment is no worse than no deployment.
TRUSTED_PROXY=${TRUSTED_PROXY:-}

pids=()

shutdown() {
  trap - TERM INT EXIT
  # The supervisor is deliberately not in `pids`, so it is stopped by name.
  [ -n "${anchor_pid:-}" ] && kill "$anchor_pid" 2>/dev/null || true
  for ((i = ${#pids[@]} - 1; i >= 0; i--)); do
    kill "${pids[$i]}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap shutdown TERM INT EXIT

# How long a service may take to answer before this gives up on it, in
# seconds. Fifteen minutes, and the reason it is not three is written below.
STARTUP_LIMIT=${STARTUP_LIMIT:-900}

# Wait for a service to answer rather than sleeping on a guess.
#
# The budget is long on purpose, and the third argument is why this is not just
# a bigger number. It used to be 150 rounds of a one-second curl and a 0.2s
# sleep, which is 180 seconds, and it was applied to the matcher, whose startup
# is not a constant: the matcher replays the log into state.db before it
# answers /market, so its startup grows with the log.
#
# Measured on the deploy of 0dae644: the replay passed 180 seconds, this
# function gave up, the entrypoint exited, and the container restarted -- four
# times, over eleven minutes, with every request in that window getting a 404
# because Traefik does not route to a container whose health check has not
# passed. Each restart threw away a replay that was making progress and started
# the clock again. That restart loop is the "six minute deploy gap": two rounds
# of it is six minutes, and the site came back when one round finally finished
# inside the budget.
#
# A timeout here prevents nothing that is not already prevented. A service that
# is dead is caught by its process exiting, which is what the third argument
# watches and what the supervisor at the end of this file watches, and it is
# caught in the same second rather than three minutes later. So the short
# budget never caught a failure earlier; it only turned a slow start into a
# restart loop. The long budget is the backstop for a process that is alive and
# wedged, which is the one case neither check sees.
wait_for() {
  local url=$1 name=$2 pid=${3:-} waited=0
  while :; do
    if curl -sf --max-time 2 "$url" > /dev/null 2>&1; then
      [ "$waited" -ge 10 ] && echo "entrypoint: $name answered after ${waited}s"
      return 0
    fi
    # The failure that matters, and it is reported in the second it happens.
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
      echo "entrypoint: $name exited before it answered at $url" >&2
      exit 1
    fi
    sleep 1
    waited=$((waited + 1))
    # So a slow start is a line in the log rather than a container that looks
    # hung. This is the only place that says a replay is running.
    if [ $((waited % 30)) -eq 0 ]; then
      echo "entrypoint: still waiting for $name at $url (${waited}s)"
    fi
    if [ "$waited" -ge "$STARTUP_LIMIT" ]; then
      echo "entrypoint: $name never came up at $url after ${waited}s" >&2
      exit 1
    fi
  done
}

start() {
  "$BIN" "$@" &
  pids+=("$!")
}

# The pid of the service `start` started last, for wait_for's third argument.
last_started() {
  echo "${pids[${#pids[@]} - 1]}"
}

proxy_args=()
if [ -n "$TRUSTED_PROXY" ]; then
  proxy_args=(--trusted-proxy "$TRUSTED_PROXY")
else
  echo "entrypoint: TRUSTED_PROXY is unset. Behind a reverse proxy every" \
       "visitor shares one rate-limit bucket. Set it to the proxy's address" \
       "or network to rate limit on the real client." >&2
fi

cd "$DATA"

# The operator key: the one key whose messages this sequencer publishes, and
# so the only key that can open a market, close one, or change the rule set.
#
# One thing here is inverted from the anchor key below, and the reason is what
# each key is for. A missing anchor key means "do not anchor", because an
# anchor is evidence about the exchange and an exchange that is not anchored
# still trades. A missing operator key cannot mean "do not open the market",
# because the market is the product: the deployment would serve an empty log,
# with no rule set and no listed symbol, and every order it received would be
# ignored. So a key is minted when none is mounted.
#
# The minted key sits on the data volume, so anybody who can read that volume
# can open and close markets on this deployment. That is said out loud below.
# A production deployment mounts the secret and never reaches that branch.
OPERATOR_KEY_FILE=${OPERATOR_KEY_FILE:-/run/secrets/operator_key}
if [ ! -f "$OPERATOR_KEY_FILE" ] || [ ! -s "$OPERATOR_KEY_FILE" ] \
   || [ ! -r "$OPERATOR_KEY_FILE" ]; then
  # Missing, empty, a directory Docker made for a host path that does not
  # exist, or a mounted file this uid cannot read. All four mean the same
  # thing here: there is no key to open the log with.
  echo "entrypoint: no readable operator key at $OPERATOR_KEY_FILE, so one is" \
       "minted at $DATA/operator.key. Anybody who can read the data volume" \
       "can then open and close markets on this deployment. Mount the secret" \
       "to keep that key off the volume." >&2
  OPERATOR_KEY_FILE=$DATA/operator.key
  # Kept across restarts. The log's first messages were signed by this key, so
  # a restart that minted a second one would name an operator the log does not
  # know. 32 bytes of hex is the shape the binary reads.
  if [ ! -s "$OPERATOR_KEY_FILE" ]; then
    (umask 077; head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' \
      > "$OPERATOR_KEY_FILE")
  fi
fi
# Read from the key file rather than configured beside it, so the sequencer
# cannot end up trusting a key nobody holds. A key file that is not a key
# stops the container here, with the reason the binary prints.
OPERATOR_PUBLIC_KEY=$("$BIN" --operator-public-key \
  --operator-key-file "$OPERATOR_KEY_FILE")
echo "entrypoint: operator key from $OPERATOR_KEY_FILE, public key $OPERATOR_PUBLIC_KEY"

# The inbox first: the feed needs its URL to drain it.
start --start-inbox --bind "$BIND" --inbox-port 3002 --inbox-db inbox.db \
  --ui-origin "$UI_ORIGIN" "${proxy_args[@]}"
wait_for http://127.0.0.1:3002/status inbox "$(last_started)"

start --start-feed --bind "$BIND" --feed-port 3000 \
  --num-accounts "$NUM_ACCOUNTS" --rate "$RATE" --feed-db feed.db \
  --inbox-url http://127.0.0.1:3002 \
  --operator-key "$OPERATOR_PUBLIC_KEY" \
  --ui-origin "$UI_ORIGIN" "${proxy_args[@]}"
wait_for http://127.0.0.1:3000/head feed "$(last_started)"

for i in 1 2 3; do
  start --start-validator --bind "$BIND" \
    --validator-port $((3009 + i)) --validator-db "validator$i.db" \
    --feed-url http://127.0.0.1:3000
done
# The three validators were started in order, so their pids are the last three
# in `pids`, oldest first.
for i in 1 2 3; do
  wait_for "http://127.0.0.1:$((3009 + i))/attest" "validator$i" \
    "${pids[${#pids[@]} - 4 + i]}"
done

start --start-matcher --bind "$BIND" --matcher-port 3001 --state-db state.db \
  --feed-url http://127.0.0.1:3000 \
  --public-feed-url "$PUBLIC_FEED_URL" \
  --public-inbox-url "$PUBLIC_INBOX_URL" \
  --validators http://127.0.0.1:3010,http://127.0.0.1:3011,http://127.0.0.1:3012
wait_for http://127.0.0.1:3001/market matcher "$(last_started)"

# Open the log, if nothing has opened it yet.
#
# After the exchange and not right after the sequencer, because the rule set
# published as message 1 is read from the exchange's /market. The exchange
# reports the newest rule set its build can run, and it is the only service
# that reports it, so the number cannot be read before it answers. The
# sequencer publishes nothing of its own while its log is empty, so waiting
# here costs no generated message and no order lands before the rules do.
#
# Not in `pids` and not run in the background: it is four short commands that
# end. A failure leaves the exchange running and says so. A container restart
# is no repair: an opening that failed on the first message leaves an empty
# log the next start opens, and one that failed later leaves a log the head
# test will refuse to touch, which the operator finishes by hand.
if ! /usr/local/bin/open-the-log.sh "$BIN" http://127.0.0.1:3000 \
     http://127.0.0.1:3001 "$OPERATOR_KEY_FILE"; then
  echo "entrypoint: the log was not opened. The exchange is up and matching," \
       "but a market that was never listed trades nothing, so orders in it" \
       "are ignored. Finish it with services --engine-rule and" \
       "services --list-symbol." >&2
fi

if [ "$START_BOT" = "yes" ]; then
  start --start-bot --bot-key bot.key
fi

# The anchor sender, if this deployment has a key to write with.
#
# Optional on purpose. An exchange with no anchor is a valid deployment: the
# matcher answers /anchor-config with 404 and the UI hides the anchor section
# entirely. Requiring a key here would break every local run of this image for
# a feature that is additional evidence, not a dependency of the exchange.
#
# NOT tied to `wait -n`, and that is a correction. It used to be, and a wrong
# contract address took the whole market down.
#
# The reasoning that put it there was that a misconfigured anchor should fail
# loudly rather than run for days looking anchored while writing nothing. The
# first half is right and the second half does not follow. The exchange is the
# product; the anchor is evidence about it. Not anchoring is already visible,
# because the strip shows the age of the last anchor. So the choice was never
# between loud and silent. It was between an exchange that is up and one that
# is down.
#
# Supervised instead: restarted with a growing delay, every failure reported.
# A refused RPC recovers by itself. A wrong contract address repeats in the log
# until somebody fixes it, and the market keeps running.
ANCHOR_KEY_FILE=${ANCHOR_KEY_FILE:-/run/secrets/anchor_key}
if [ -f "$ANCHOR_KEY_FILE" ] && [ -s "$ANCHOR_KEY_FILE" ] && [ -r "$ANCHOR_KEY_FILE" ]; then
  # Loopback for what it reads, because it reads this container's own exchange;
  # the cache goes on the data volume so a restart does not re-anchor a
  # position that is already on chain.
  export ANCHOR_KEY_FILE
  export ANCHOR_EXCHANGE_URL=${ANCHOR_EXCHANGE_URL:-http://127.0.0.1:3001}
  export ANCHOR_FEED_URL=${ANCHOR_FEED_URL:-http://127.0.0.1:3000}
  export ANCHOR_DEPLOYMENT=${ANCHOR_DEPLOYMENT:-/etc/exchange/anchor-deployment.json}
  export ANCHOR_CACHE=${ANCHOR_CACHE:-$DATA/anchor-cache.json}
  export ANCHOR_INTERVAL=${ANCHOR_INTERVAL:-5m}
  (
    delay=5
    while true; do
      /usr/local/bin/anchor-sender
      echo "entrypoint: the anchor sender exited with status $?." \
           "The exchange keeps running and is not anchoring." \
           "Retrying in ${delay}s." >&2
      sleep "$delay"
      # Back off to a minute, so a permanent misconfiguration does not fill the
      # log, but keep reporting so it cannot be missed.
      [ "$delay" -lt 60 ] && delay=$((delay * 2))
    done
  ) &
  anchor_pid=$!
  echo "entrypoint: anchoring every $ANCHOR_INTERVAL, key from $ANCHOR_KEY_FILE"
elif [ -d "$ANCHOR_KEY_FILE" ]; then
  # Docker creates a DIRECTORY when a bind mount names a host path that does
  # not exist. Worth its own message: the mount looks configured, the key is
  # not there, and nothing else would say so.
  echo "entrypoint: $ANCHOR_KEY_FILE is a directory, not a key. The host path" \
       "behind this mount does not exist, so Docker created it. Not anchoring." >&2
elif [ -e "$ANCHOR_KEY_FILE" ] && [ ! -r "$ANCHOR_KEY_FILE" ]; then
  # The key is mounted and this user cannot read it. Outside Swarm, a compose
  # secret is a bind mount and nothing else: the `uid`, `gid` and `mode` keys
  # are accepted and ignored, and the file keeps the host's ownership. This
  # container runs as uid 10001, so a key left as root:root 0600 on the host
  # arrives unreadable.
  #
  # Checked here rather than left to the sender because of what the sender
  # does about it: it exits, and every process in this container shares one
  # lifetime, so an anchor that cannot start would take the exchange down with
  # it. The exchange is the thing being served; the anchor is evidence about
  # it. Not anchoring is visible, because the UI shows the age of the last
  # anchor and /anchor-config still answers. A crash loop serves nobody.
  echo "entrypoint: cannot read $ANCHOR_KEY_FILE as uid $(id -u). A compose" \
       "secret keeps the host file's ownership, so give the host file to this" \
       "uid: chown 10001:10001 <host path> && chmod 0400 <host path>." \
       "Running without anchoring." >&2
else
  echo "entrypoint: no anchor key at $ANCHOR_KEY_FILE; not anchoring." \
       "The exchange runs normally and the UI hides the anchor section." >&2
fi

echo "entrypoint: all services up; UI on :3001, feed on :3000, inbox on :3002"

# Exit as soon as anything does, so a partial failure restarts the container
# rather than leaving a market that looks alive and is not.
# Only the services in `pids`. A bare `wait -n` waits for ANY background job,
# which would include the supervised anchor sender and undo the point of
# supervising it.
wait -n "${pids[@]}"
echo "entrypoint: a service exited; stopping the rest" >&2
exit 1
