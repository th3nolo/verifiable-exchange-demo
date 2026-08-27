#!/usr/bin/env bash
#
# Opens an empty log. Message 1 names the rule set the messages after it run
# under, and one message per market says that market is open.
#
# Until this runs, a fresh deployment has a log with nothing in it: no rule
# set, and no listed symbol. Every order the engine then reads names a symbol
# that is not listed, so the engine ignores it and the exchange trades nothing.
# This is the step that turns a running deployment into an exchange.
#
# It runs on an empty log and on no other. The test is the head: a log whose
# last id is 0 holds nothing, and any other value means the log was opened
# already, by an earlier run of this script, or by the operator by hand. A
# second run would list symbols that already trade, and the engine ignores
# those listings.
#
# Both ./demo.sh and docker/entrypoint.sh run this file, so a local run and a
# deployment open their logs the same way. services/tests/genesis.rs runs this
# same file, so what that test covers is this script and not a copy of it.
#
# Usage:
#   open-the-log.sh BINARY FEED_URL MATCHER_URL OPERATOR_KEY_FILE

set -euo pipefail

BIN=${1:?the path of the services binary}
FEED_URL=${2:?the URL of the sequencer}
MATCHER_URL=${3:?the URL of the exchange}
KEY_FILE=${4:?the operator key file}

# The quantity step every market opens with: one tenth. That is the finest
# quantity grid the engine holds, so it is the step that refuses the fewest
# orders, and it is the same for every market because a quantity of 1.5 means
# the same amount of work whatever the price is.
#
# It must match QUANTITY_SCALE in services/src/inbox.rs: 0.1 is
# 1/QUANTITY_SCALE. A step finer than the engine's grid is a listing the engine
# refuses, and then the market never opens at all.
#
# The price step is not here any more. It is per market: 0.01 for MERKLE-USDC,
# 0.10 for ETH-USDC, 1.00 for BTC-USDC. It is named in domain::SYMBOLS and
# nowhere else. GET /symbols reports it beside the market name, and this file
# reads it from there. That is the endpoint docs/PLAN.md step 5 asked for.
QUANTITY_STEP=${QUANTITY_STEP:-0.1}

# Reads one whole number field out of a JSON body. The runtime image has no
# jq, and both fields read here are numbers in a small flat object.
number_field() {
  sed -n 's/.*"'"$1"'":[[:space:]]*\([0-9][0-9]*\).*/\1/p'
}

# The head first, before anything else is asked. A log that is already open
# needs no rule set from the exchange and no symbol list from the sequencer.
last_id=$(curl -sf --max-time 5 "$FEED_URL/head" | number_field last_id)
if [ -z "$last_id" ]; then
  echo "open-the-log: $FEED_URL/head named no last_id, so it is not known" \
       "whether this log is empty. Publishing nothing." >&2
  exit 1
fi
if [ "$last_id" != "0" ]; then
  echo "open-the-log: this log already holds $last_id messages, so it was" \
       "opened already. Publishing nothing." >&2
  exit 0
fi

# Which rule set to publish comes from the running exchange and never from a
# number typed here. The exchange reports the newest rule set its build can
# run, so this file does not become a second place that has to be edited on
# every rule set.
rule_set=$(curl -sf --max-time 5 "$MATCHER_URL/market" | number_field newest_rule_set)
if [ -z "$rule_set" ]; then
  echo "open-the-log: $MATCHER_URL/market named no newest_rule_set, so it is" \
       "not known which rule set this build runs. Publishing nothing." >&2
  exit 1
fi

# The markets and their price steps come from the sequencer's own symbol list,
# which is domain::SYMBOLS. Naming either here would make this file a second
# place that says which markets this exchange has and what grid they trade on.
#
# The body is a JSON array of small flat objects:
#
#   [{"symbol":"MERKLE-USDC","price_step":0.01}, ...]
#
# The runtime image has no jq, so it is turned into one "SYMBOL STEP" line per
# market: spaces out, the brackets off, one object per line, then the two
# values off each line. A line that does not hold both is dropped by the `p`,
# so a body this script cannot read lists nothing rather than listing something
# wrong.
markets=$(curl -sf --max-time 5 "$FEED_URL/symbols" \
  | tr -d ' ' | sed -e 's/^\[//' -e 's/\]$//' -e 's/},{/}\n{/g' \
  | sed -n 's/^{"symbol":"\([^"]*\)","price_step":\([0-9.]*\)}$/\1 \2/p')
if [ -z "$markets" ]; then
  echo "open-the-log: $FEED_URL/symbols named no markets. Publishing nothing." >&2
  exit 1
fi

operator_args=(--feed-url "$FEED_URL" --matcher-url "$MATCHER_URL"
               --operator-key-file "$KEY_FILE" --sign-only)

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Sign first and publish second.
#
# The sequencer reserves the first four positions for this opening: one rule
# set and three listings. User, inbox and generated traffic waits until all
# four exist. Signing every body before the first POST keeps the opening short
# and ensures a signing failure publishes none of it.
#
# --sign-only is what makes this possible: it prints the body the sequencer
# takes on POST /operator instead of sending it. Every check the command makes
# still runs, so a symbol the engine would refuse still stops this script
# before anything is published.
echo "open-the-log: signing rule set $rule_set and the listings"
"$BIN" --engine-rule "$rule_set" "${operator_args[@]}" > "$work/1"
count=1
# One market a line, in the order /symbols served them, so the ids the listings
# take are that order too. `/market` serves its rows in that order.
while read -r symbol price_step; do
  count=$((count + 1))
  "$BIN" --list-symbol "$symbol" "$price_step" "$QUANTITY_STEP" \
    "${operator_args[@]}" > "$work/$count"
done <<< "$markets"

# Sends one signed body. The status is read rather than left to `curl -f`,
# because the three refusals need telling apart: 404 is a sequencer that names
# no operator, 403 is one that names another key, and 401 is a signature made
# for another history.
publish() {
  local file=$1 status
  status=$(curl -s -o "$work/answer" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' --data-binary @"$file" \
    "$FEED_URL/operator")
  case "$status" in
    2??) return 0 ;;
    *)
      echo "open-the-log: the sequencer answered $status to $(cat "$file"):" \
           "$(cat "$work/answer")" >&2
      return 1
      ;;
  esac
}

echo "open-the-log: publishing rule set $rule_set and $((count - 1)) listings"
for i in $(seq 1 "$count"); do
  publish "$work/$i"
done
