#!/usr/bin/env bash
#
# Brings up the whole exchange on one machine: the feed that sequences, the
# matcher that executes, an inbox the feed does not control, three validators
# that check the feed independently, and a bot to generate real order flow.
#
#   ./demo.sh            # default rate, runs until Ctrl-C
#   ./demo.sh --rate 25  # faster, for watching
#
# Everything writes into ./run/, which is deleted on each start. Ctrl-C stops
# every process it started and nothing else.

set -euo pipefail

cd "$(dirname "$0")"

# These defaults match the switching case measured in docs/GENERATOR-RFC.md.
# Environment variables can change both values, and `--rate N` overrides RATE
# for comparing one local run with another.
RATE=${RATE:-69}
NUM_ACCOUNTS=${NUM_ACCOUNTS:-40}
if [ "${1:-}" = "--rate" ]; then RATE="${2:?--rate needs a number}"; fi

BIN=services/target/release/services
RUN_DIR=run
PIDS=()

cleanup() {
  echo ""
  echo "stopping…"
  # Reverse order: the bot and matcher read from the feed, so they go first.
  for ((i = ${#PIDS[@]} - 1; i >= 0; i--)); do
    kill "${PIDS[$i]}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  echo "stopped. logs and databases are in $RUN_DIR/"
}
trap cleanup EXIT INT TERM

# Wait for a port to answer rather than sleeping a guessed number of seconds.
wait_for() {
  local url=$1 name=$2
  for _ in $(seq 1 100); do
    if curl -sf --max-time 1 "$url" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  echo "error: $name never came up at $url. See $RUN_DIR/*.log" >&2
  exit 1
}

start() {
  local name=$1; shift
  "$BIN" "$@" >"$RUN_DIR/$name.log" 2>&1 &
  PIDS+=("$!")
}

echo "building (release)…"
(cd services && cargo build --release --quiet)

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"
cd "$RUN_DIR"
BIN="../$BIN"
RUN_DIR="."

# The inbox first: the feed needs its URL to drain it.
start inbox --start-inbox --inbox-port 3002 --inbox-db inbox.db
wait_for http://127.0.0.1:3002/status "inbox"

# The operator key: the one key whose messages the sequencer publishes. Minted
# here, exactly as the deployment mints one when no secret is mounted, so a
# local run opens its log the same way. run/ is deleted on each start, so this
# key lasts one run and anybody who can read run/ can use it.
if [ ! -s operator.key ]; then
  (umask 077; head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' > operator.key)
fi
OPERATOR_PUBLIC_KEY=$("$BIN" --operator-public-key --operator-key-file operator.key)

# The feed sequences messages and signs the head of its own log. It publishes
# nothing of its own until the operator has written message 1, so the log opens
# with the rules and not with whichever generated order won a race.
start feed --start-feed --num-accounts "$NUM_ACCOUNTS" --rate "$RATE" \
  --feed-db feed.db --inbox-url http://127.0.0.1:3002 \
  --operator-key "$OPERATOR_PUBLIC_KEY"
wait_for http://127.0.0.1:3000/head "feed"

# Three validators, each following the feed independently with its own key.
for i in 1 2 3; do
  start "validator$i" --start-validator \
    --validator-port $((3009 + i)) --validator-db "validator$i.db" \
    --feed-url http://127.0.0.1:3000
done
for i in 1 2 3; do wait_for "http://127.0.0.1:$((3009 + i))/attest" "validator$i"; done

# The matcher executes the feed and counts what the validators vouch for.
# --public-inbox-url is what puts the separate service on the page: the browser
# reaches the inbox directly, so it needs the address a browser can use, which
# is not necessarily the one the feed drains through. The inbox's own
# --ui-origin already defaults to this UI's two spellings of :3001.
start matcher --start-matcher --matcher-port 3001 \
  --feed-url http://127.0.0.1:3000 --state-db state.db \
  --public-inbox-url http://127.0.0.1:3002 \
  --validators http://127.0.0.1:3010,http://127.0.0.1:3011,http://127.0.0.1:3012
wait_for http://127.0.0.1:3001/market "matcher"

# Open the log: the rule set, then one listing per market. The same file the
# deployment runs, so a local log and a deployed log open the same way. After
# the matcher, because the rule set published as message 1 is read from the
# matcher's /market and no other service reports it.
if ! ../docker/open-the-log.sh "$BIN" http://127.0.0.1:3000 \
     http://127.0.0.1:3001 operator.key > open-the-log.log 2>&1; then
  echo "warning: the log was not opened. See $RUN_DIR/open-the-log.log." \
       "Orders in a market that was never listed are ignored." >&2
fi

# A bot, so the book has real flow instead of only generated noise.
start bot --start-bot --bot-key bot.key

cat <<EOF

  exchange   http://127.0.0.1:3001      trading UI, with the verification strip on top
                                        the Trade panel signs your orders in the browser
  feed       http://127.0.0.1:3000/head signed head of the log
  inbox      http://127.0.0.1:3002/status the separate service, and its overdue list
                                        the Trade panel can route an order through it

  check it yourself, from another terminal:

    cd $(pwd)
    $BIN --verify              # reconciles the trade log against the feed
    $BIN --audit               # re-executes every claim from the feed's history
    $BIN --audit-url http://127.0.0.1:3001   # same, over HTTP, no database needed

  Ctrl-C to stop.

EOF

wait
