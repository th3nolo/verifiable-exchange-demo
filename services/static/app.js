// The Ed25519 signer this page submits orders with. Served by the matcher from
// the same binary as this page (`GET /ed25519.js`), never from a CDN: a page
// whose subject is that you do not have to trust the operator should not be
// asking a fourth party for the code that holds the visitor's key.
//
// It is @noble/ed25519 2.3.0 by Paul Miller, MIT licensed, unmodified. To check
// that for yourself:
//
//   npm pack @noble/ed25519@2.3.0 && tar xzf noble-ed25519-2.3.0.tgz
//   diff package/index.js services/static/ed25519.js
//
// sha256 of that file: 70cebecaaa6a126ced702198706c49d03f2d6f70317342b75e50e8d2d4951fe5
import * as ed from "./ed25519.js";

// How many levels a side the next request asks for. fitBook measures it from
// the panel; this is only what the first request uses before the first
// measurement. The server caps a request at 1000 levels a side
// (MAX_BOOK_DEPTH in services/src/matcher.rs), so a computed number is safe.
let depth = 12;
// The ceiling on the measured count. It never bites at a normal type size. It
// is there for browser zoom at 25%, where a row is about 5px and the panel is
// four times taller in CSS pixels: without it the page would ask for hundreds
// of levels that nobody can read.
const MAX_DEPTH = 50;
// The intervals the chart offers.
//
// There is no 1-second button. The market does not trade every second, so that
// chart drew gaps and a reader could not tell a quiet market from a broken
// page. Measured on the live exchange on 17 August 2026, at 24 messages a
// second, over 200 buckets in each of the three markets:
//
//   interval   buckets that hold a trade   longest flat run
//   1s              67% to 74%                 3s to 4s
//   5s             98% to 100%                 0s to 15s
//   15s               100%                        0s
//
// The cause was not the message rate. One order took every order at the best
// price, so its trades all landed in one second and the next seconds held none.
// The variance of trades a second was 4.1 to 4.8 times the mean, where
// independent arrivals give 1.0. Raising the rate made the bursts taller, not
// the gaps shorter.
//
// `TAKE_EVERY` in `services/src/feed/generate.rs` removed that cause. Crossing
// orders go out on a cadence, the three markets take turns, and one crossing
// order removes one resting order. Measured on ./demo.sh over 300 one-second
// buckets in each market, on 17 August 2026:
//
//   what is running                  buckets that hold a trade   longest flat run
//   the generator only                       99% to 100%                 1s
//   the generator and the bot                 86% to 92%                 3s
//
// The button stays out because of the second row. The bot sends limit orders
// priced to cross, and those take the generator's resting orders. The
// sequencer holds no book and does not execute orders, so it cannot learn
// which of its orders the bot took. Its next crossing order then names a price
// that has already gone and trades nothing. Measured over the same run: 466 of
// the generator's cancels named an order the exchange no longer held, against
// 1 with the bot stopped. Put the button back when that number is near 1 with
// the bot running.
//
// There is no 5-second button either, and that one is a display choice rather
// than a measurement. 5-second candles held a trade in 98% to 100% of buckets
// at the flat 24 messages a second the deployment ran then, so the chart was
// already continuous there. The deployment now runs a mean of 69 a second over
// three activity states of 24, 69 and 114, and 24 is the floor, so no state is
// quieter than the rate that measurement was taken at. It came
// out because 15 seconds is the fastest interval that holds a trade in every
// bucket, and because five buttons that step 15s, 5m, 15m, 1h, 4h cover a
// second to a day more evenly than two buttons five seconds apart. The server
// serves exactly these five intervals so it can maintain bounded projections;
// adding a button also means adding that interval to CANDLE_INTERVALS in
// services/src/matcher.rs.
const INTERVALS = [[15, "15s"], [300, "5m"], [900, "15m"], [3600, "1h"], [14400, "4h"]];
let interval = 15;
let symbol = null;
let lastTradeId = 0;
let lastMessageId = 0;
let lastCandles = [];
let candleLoading = false;
let candleError = null;
const candleControllers = new Set();
// The newest order this browser saw trade. The marker is drawn only after the
// candle API includes the same price range, so it points at recorded market
// data rather than painting a client-side guess onto the chart.
let lastOwnFill = null;
window.addEventListener("resize", () => { drawChart(lastCandles); drawPnl(); });

// ===========================================================================
// The window both charts draw
//
// Before this, both charts drew every point they had loaded and scaled the
// price axis over every point they had loaded. One 15m BTC-USDC candle closed
// near 1520 while the other 190 candles sat near 950. That one candle set the
// scale, so the other 190 were squashed into a band a few pixels tall and the
// reader could not read a price off any of them.
//
// The fix is one rule, used by both charts: the chart holds every point it has
// loaded, draws a slice of them, and scales the axis over the slice alone.
// Scroll past the 1520 candle and the rest of the candles get the full height.
//
// The two charts keep two separate windows. They do not share one value,
// because their x axes measure different things: the candle chart measures the
// selected symbol at the selected interval, and the profit chart measures every
// trade of the run. A pan on one is not a pan on the other. They do share the
// arithmetic below and the pointer and key handling in `attachChartInput`.

// The most candles one screen can show and still show candles.
//
// A candle needs 3 px to stay apart from the next one: a 2 px body and a 1 px
// gap. Below 3 px the candles merge into one block, and more of them buy
// nothing a reader can see.
//
// Measured in this page, not guessed. The chart panel is the middle column.
// At a 2560 px window the canvas is 1966 px and the price axis takes 52 px, so
// the plot is 1914 px and one screen holds 1914 / 3 = 638 candles. At a 1440 px
// window the canvas is 846 px, the plot 794 px, and one screen holds 264.
//
// This is a limit on the *drawn* count, worked out per draw from the real plot
// width. `MAX_LOOKBACK` below is the limit on the *loaded* count.
const MIN_SLOT_PX = 3;
// The widest a candle is drawn. Kept from the code this replaced.
const MAX_SLOT_PX = 24;
// How many candles the chart opens on.
//
// TradingView's own `lightweight-charts` opens at a `barSpacing` of 6 px, so
// 6 px is what a reader of that chart sees first. On the plots measured above
// that is 1914 / 6 = 319 candles at 2560 px and 794 / 6 = 132 at 1440 px.
//
// This page opens on 132 at every width, and not on `plotW / 6`. Two reasons.
//
// One: 132 makes one interval button mean one span of time on every screen.
// With `plotW / 6` the fastest chart opened on 5.3 minutes at 2560 px and on
// 2.2 minutes at 1440 px, so two readers who pressed the same button read two
// different charts. A wider screen now buys wider candles, not more history.
// Those two numbers were measured on the 1-second chart, which this page no
// longer offers. The ratio is what the argument rests on, and the ratio is the
// same at every interval.
//
// Two: `plotW / 6` grew to everything loaded whenever less than that was
// loaded, and "everything" is the wrong thing to open on. Measured against the
// live exchange on 16 August 2026: the 5-minute BTC-USDC chart held 273
// buckets, 273 is below 319, so a 2560 px reader opened on all 273, 22.8
// hours. That view held the candle that starts at 04:35, which has a high of
// 1500 against a market near 980, because 560 fresh accounts arrived and swept
// a book with asks up to 1500. The scale then ran from 940 to 1500 and the
// other 272 candles were a band about 12% of the plot tall. Opening on 132
// candles is 11 hours there, and 04:35 is outside it.
//
// The cap is on the opening window only. `hi` in `candleLimits` still reaches
// every loaded candle, so the minus button, the wheel, a drag, Home and the
// arrow keys all still reach the whole loaded history, and the 04:35 candle
// with it. Nothing loaded is out of reach.
//
// It does not help every interval, and no count can. The 1-hour chart holds 24
// candles for a run one day old, and 04:35 is 12 of them back. A count that hid
// it there would leave 11 candles on the screen, which is not a chart. So at 15
// minutes and 1 hour a reader still opens on the whole run, because the whole
// run is the span those intervals are for.
const OPEN_BARS = 132;

// How far back the candle chart ever loads.
//
// 1000 is the matcher's own `MAX_CANDLES` in services/src/matcher.rs. The
// matcher refuses to build more than 1000 buckets for one GET, and asking for
// more than it will build only makes the request look like it failed. So the
// server sets this number and the page repeats it.
//
// A bucket is one interval of wall time, empty or not, so 1000 buckets is 1000
// intervals: 4.2 hours at 15 seconds, 3.5 days at 5 minutes, and 41 days at one
// hour. To read further back, press a wider interval.
//
// What the arithmetic above says about it: the opening window is 132 candles,
// so 1000 is 7.6 opening windows of history at every interval and on every
// screen. Zoomed all the way out one screen holds 638 candles at a 2560 px
// window, so 1000 is still 1.6 of those.
const MAX_LOOKBACK = 1000;
// How many candles the first request asks for.
//
// The opening window is 132 candles, so a first request smaller than that would
// open on a chart with no candles on its left half. 200 is that window plus 68
// candles of slack, which is more than the 10 candles of slack that start a
// left-edge load, so opening the page does not immediately ask a second time.
// The slack also lets a reader zoom out to 200 candles before anything loads.
//
// It is also 20% of `MAX_LOOKBACK`. The matcher answers from a bounded candle
// projection, so the smaller first response saves JSON, parsing and drawing
// work. The page asks for the rest only when a reader pans towards it.
const FIRST_LOOKBACK = 200;
// How much more each left-edge load asks for. Two steps reach `MAX_LOOKBACK`:
// 200, then 600, then 1000.
const LOOKBACK_STEP = 400;
// How close to the oldest loaded candle the window gets before the page asks
// for more. `lightweight-charts` uses 10 bars of slack in its own
// infinite-history example, and the same number works here for the same
// reason: the answer lands before the reader reaches the front.
const LOAD_SLACK_BARS = 10;

// How many candles are loaded now, and whether a bigger request is in flight.
let candleLookback = FIRST_LOOKBACK;
let loadingOlder = false;

// A chart's window into what it has loaded.
//
// `bars` is how many points the window shows. `left` is the timestamp of the
// leftmost point in it, or `null` for "stay on the newest point".
//
// `left` holds a timestamp and not an array index on purpose. The candle array
// grows at both ends: at the right when a new bucket closes, at the left when
// a left-edge load answers. So an index means a different candle a second
// later, and the view would slide on its own. A timestamp names the same
// moment however the array grows.
//
// `left === null` is what stops the 500 ms refresh from pulling a reader back
// to the newest candle. While the window sits at the newest point, `left` stays
// null and each refresh redraws the newest `bars` points, which is what a
// reader watching the market wants. The first pan sets `left` to a timestamp,
// and from then on every refresh redraws that same moment. The reader is left
// where they put themselves until they press the button that goes back.
const newView = () => ({ bars: 0, left: null });
let candleView = newView();
let pnlView = newView();
// The points each chart drew last, oldest first. The input handlers below move
// the window over these, so a drag does not have to wait for a request.
let chartPoints = [];
let pnlPoints = [];

// One wheel step changes the width of a point by 10%, which is the step
// `lightweight-charts` uses in its own `zoom()`.
const ZOOM_STEP = 0.1;

const fmtP = (p) => p == null ? "-" : p.toFixed(2);
const fmtQ = (q) => q == null ? "-" : q.toFixed(1);
const fmtT = (ts) => new Date(ts).toLocaleTimeString("en-GB");
// Anything that rounds to zero is shown as plain "0.00". Without this the
// zero-sum line reads "−0.00", which looks like a rounding error in an
// invariant that is meant to be exact.
const ZERO = 0.005;
const fmtM = (m) => {
  const v = Math.abs(m) < ZERO ? 0 : m;
  return (v > 0 ? "+" : v < 0 ? "−" : "") + Math.abs(v).toFixed(2);
};
const fmtK = (v) => v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + "k" : v.toFixed(0);
const sign = (v) => v > ZERO ? "pos" : v < -ZERO ? "neg" : "dim";

// What an account still has at risk, valued at the last traded price. Shown
// beside profit because without it the leaderboard misleads: the simulated
// accounts trade at random and never flatten, so they carry many times a bot's
// inventory and their profit is mostly a coin flip on it. Two of them can hold
// the same notional and land on opposite sides of zero.
//
// The exchange makes this sum now and this reads it. It used to be made here,
// out of the per-symbol rows, which is why the page asked for every row of
// every account on the leaderboard: 24 numbers an account, 50 accounts, twice
// a second, to draw one number each. See `open_notional` and `totals` in
// matcher.rs.
const openNotional = (a) => a.open_notional ?? 0;

// The matcher cannot tell a bot's order from a generated one: the feed
// publishes both with only an account number, and `POST /order` accepts any
// number. So the split is a convention, stated on screen rather than hidden:
// the feed hands its simulated accounts out from 0 upward, so anything high is
// something a person pointed at the venue. Override with ?bots=999,777.
const BOT_ID_FLOOR = 100;
const botOverride = new URLSearchParams(location.search).get("bots");
const botSet = botOverride
  ? new Set(botOverride.split(",").map((s) => parseInt(s.trim(), 10)).filter(Number.isFinite))
  : null;
// People who came through this page are not bots. Their ids are derived into
// `1000000` and up (see RESERVED_ACCOUNTS below), so the split can exclude that
// range by name. Otherwise every visitor's profit would be counted on the bot
// side of the zero-sum line, and every visitor would be labelled a bot on their
// own screen.
const isVisitor = (id) => id >= Number(RESERVED_ACCOUNTS);
const isMe = (id) => identity !== null && id === identity.account;
const isBot = (id) => !isVisitor(id) && (botSet ? botSet.has(id) : id >= BOT_ID_FLOOR);

let selectedAccount = null;
// True once the visitor has clicked a row. A click beats the default choice
// above from that moment on, including the click that lands in the second
// before the first full account walk answers.
let userPickedAccount = false;
// Profit history for the selected account, rebuilt from that account's indexed
// fills and sampled market prices. It changes less often than the order book,
// so it has its own slower timer.
let pnlSeries = [];
let pnlTick = 0;
const PNL_EVERY = 8;
// Which account the newest /pnl request named, and which one is on screen.
let pnlAccount = null;
let pnlDrawn = null;

// How many samples one /pnl answer carries.
//
// A bigger number adds sampled price lookups and response bytes. The endpoint
// clamps it to 2000, so the answer stays bounded even if a caller asks for
// more.
//
// 900 is set by the opening window. `PNL_OPEN_PX` opens the chart on 194 to 370
// points, so 900 over the run holds two to four opening windows of history to
// pan back through, all at 2 px a point. It is also fewer points than this page
// used to ask for: six accounts at 300 points each was 1800.
const PNL_POINTS = 900;

// Every account this page has been told about, newest answer per account.
//
// /positions is paged now. It used to answer with every account, and one
// account costs 663 bytes: at the 600 accounts the markets need, that is
// 397,800 bytes twice a second. The table still shows every account, because
// the accounts come from two timers instead of one: the fast poll below
// replaces the first page, and the slow walk replaces all of them. An account
// outside the fast page is at most 30 seconds old on screen, which is the
// price of not sending 800 KB a second.
let accountsById = new Map();
// How many accounts the 500ms poll asks for. 50 accounts is 33,150 bytes a
// request, about what the route cost at the 42 accounts the exchange ran with
// before, so the page keeps the traffic it had rather than growing with the
// account count.
const ACCOUNTS_PAGE = 50;
// The most accounts the exchange answers one request with: PAGE_LIMIT in
// services/src/matcher.rs. The zero-sum walk asks for exactly this, so an
// exchange with fewer accounts than this answers the whole walk in one
// request and the total it adds up comes from one moment.
const POSITIONS_MAX_PAGE = 1000;
// How often the zero-sum check reads every account.
const ZERO_SUM_EVERY_MS = 30000;
// What the last zero-sum walk found, or null before the first one finishes.
let zeroSum = null;

async function get(path, options) {
  const r = await fetch(path, options);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}

async function getCandles(path) {
  const controller = new AbortController();
  candleControllers.add(controller);
  try {
    return await get(path, { signal: controller.signal });
  } finally {
    candleControllers.delete(controller);
  }
}

function abortCandleRequests() {
  for (const controller of candleControllers) controller.abort();
  candleControllers.clear();
}

// The same read, against another origin. The inbox is a separate service on a
// separate port, so its reads are cross-origin and only answer this page
// because the operator named this origin in the inbox's own --ui-origin.
async function getFrom(base, path) {
  const r = await fetch(base + path);
  if (!r.ok) throw new Error(base + path + " -> " + r.status);
  return r.json();
}

// ===========================================================================
// Placing and cancelling orders from this browser
//
// The feed accepts nothing that is not signed by the account it names
// (services/README.md, "Signing a submission"). Until this existed, the only
// signer in the project was the Rust CLI, so a visitor to this page could watch
// the market and do nothing else. What follows is the same signer, in the page,
// speaking the same protocol. No server-side rule was relaxed to let it in.
//
// Three things have to be exactly right or the signature verifies nowhere:
//
//  1. the statement is byte for byte the one `submission_statement` rebuilds
//     in services/src/inbox.rs;
//  2. the integers in it are the engine's grid units, computed the way
//     `on_grid` computes them: a price of 10.07 is 1007, and 10.005 is not on
//     the grid at all;
//  3. the nonce is 32 lowercase hex characters, fresh for every submission.
// ===========================================================================

/// The engine's grids, as services/src/inbox.rs defines them.
const PRICE_SCALE = 100;
const QUANTITY_SCALE = 10;
const MAX_GRID_UNITS = 1000000000;

// `on_grid` from services/src/inbox.rs, arithmetic for arithmetic: the same
// multiply, the same 1e-6 tolerance, the same bounds. Both halves matter.
// Rounding without the tolerance would sign 1000 for a price of 10.005, a
// number the visitor never asked for and the feed would refuse anyway. The
// tolerance without the rounding would refuse 10.07, whose product with 100 is
// 1006.9999999999999 in every IEEE-754 language including this one.
//
// The three constants above and the body of this function are pinned by
// `the_browser_rounds_on_the_same_grid_as_the_engine` in
// services/src/inbox.rs. Editing either fails that test, on purpose: whoever
// edits one has to compare it with `on_grid` again.
function toGrid(value, scale) {
  const scaled = value * scale;
  if (!Number.isFinite(scaled) || Math.abs(scaled - Math.round(scaled)) > 1e-6) return null;
  const units = Math.round(scaled);
  return units > 0 && units <= MAX_GRID_UNITS ? units : null;
}

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) =>
  typeof hex === "string" && hex.length % 2 === 0 && /^[0-9a-f]*$/.test(hex)
    ? Uint8Array.from(hex.match(/../g) || [], (pair) => parseInt(pair, 16))
    : null;
const encode = (text) => new TextEncoder().encode(text);

// The statements, exactly as `submission_statement` builds them: a versioned
// prefix, newline separated fields, no trailing newline. Every number here is
// an integer and String() prints those as plain digits.
//
// The bytes those two build are pinned by
// `the_account_statements_are_exactly_these_bytes` in services/src/inbox.rs.
// Nothing in CI runs this file, so that test is the only thing that notices a
// field moving or the version going to v4. Change one side and the two lines
// below have to change with it, or every submission from this page gets a 401.
//
// The session is the second line. It names the log. Without it the same signed
// bytes would still become a message after the sequencer's database was
// emptied and started again, which is a replay across the reset.
//
// The three order terms are always written, even when they hold their
// defaults. The wire form of a message skips a default term to keep the bytes
// the sequencer already hashed; a statement does not, because two possible
// statements for one order is an ambiguity, and a term the signature does not
// cover is a term the sequencer can change.
const orderStatement = (account, symbol, side, priceCents, qtyTenths, terms, session, nonce) =>
  encode(["exchange-account-order-v3", session, account, symbol, side, priceCents, qtyTenths,
          terms.order_type, terms.time_in_force, terms.post_only ? "true" : "false",
          nonce].join("\n"));
const cancelStatement = (account, targetId, session, nonce) =>
  encode(["exchange-account-cancel-v3", session, account, targetId, nonce].join("\n"));

// 128 bits from the operating system, spelled the one way the feed accepts:
// 32 lowercase hex characters, checked there by decoding and re-encoding.
const newNonce = () => toHex(crypto.getRandomValues(new Uint8Array(16)));

// Where a visitor may explicitly choose to keep the key. The page does not
// write this item on first visit. Its value is 32 bytes of seed as hex, the
// same file format `--account-key` uses, so a key made here can be pasted into
// account.key and driven from the command line as the same account.
const KEY_ITEM = "verifiable-exchange.account-key";

// Account ids below this belong to the demo itself: the feed generates traffic
// for accounts 0..--num-accounts (20 under demo.sh), the bot trades as 999, and
// the README's examples use 1000. Deriving a visitor into that range would hand
// them an id somebody else's key is already pinned to, and a 403 they did
// nothing to earn and cannot fix.
const RESERVED_ACCOUNTS = 1000000n;
// AccountId is a u32 on the wire, so what is left for visitors is everything
// from there to 2^32 - 1: 4,293,967,296 ids.
const ACCOUNT_SPAN = 4294967296n - RESERVED_ACCOUNTS;

// The account id is derived from the public key, never typed. An id a visitor
// chooses is an id another visitor can choose too, and the second one to submit
// is refused with 403 for as long as the feed exists. The first key to submit
// for an id is the only key that id will ever accept.
//
// SHA-512 of the public key, first 8 bytes big-endian, reduced into the range
// above. The reduction is over 64 bits and the range is 32, so the bias is
// about 2^-32 and every id is equally likely for practical purposes. Collisions
// are still possible and the arithmetic is worth stating plainly: with 4.29e9
// ids, a visitor arriving when 10,000 others hold one has a 2.3e-6 chance of
// landing on a taken id, and the chance that any two of 10,000 visitors collide
// at all is about 1.2%. Not zero, so a 403 offers a new key below, which
// derives a new id. One click, not a dead end.
async function deriveAccount(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", publicKey));
  let n = 0n;
  for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(digest[i]);
  return Number(RESERVED_ACCOUNTS + (n % ACCOUNT_SPAN));
}

// localStorage throws rather than returning null when a browser has storage
// switched off. A session-only account still works in that browser.
function readKey() {
  try { return localStorage.getItem(KEY_ITEM); } catch (e) { return null; }
}
function writeKey(hex) {
  try { localStorage.setItem(KEY_ITEM, hex); return true; } catch (e) { return false; }
}
function forgetKey() {
  try { localStorage.removeItem(KEY_ITEM); return true; } catch (e) { return false; }
}

let identity = null;      // { seed, publicHex, account, persisted }
let feedUrl = null;       // where submissions go; the matcher's /config says
let inboxUrl = null;      // the separate service, or null when the operator runs none
let side = "Buy";
let route = "feed";       // "feed" or "inbox": which door this order goes through
let myOpenOrders = [];
let sending = false;
let submissionsInFlight = 0;
// Once this key signs anything, an accidental reload can strand that account
// or a resting order unless the visitor chose to remember it.
let hasSignedActivity = false;
// Whether the Traders panel has already switched to the visitor once.
let sawMyAccount = false;
// One record per submission this page made through the inbox, newest first:
//   { id, what, t0, feed_id, sequenced_ms, overdue, missing }
// Kept for the life of the page. The transition it exists to show takes about
// as long as one feed tick, so a display that dropped the record once the
// entry closed would show the mechanism for less time than it takes to read.
let hatch = [];
// The inbox's own last answer to `GET /status`, for the verification strip.
// null before the first read, and reset to null when the inbox stops
// answering. An unreachable separate service is itself a failure of this layer.
let inboxStatus = null;
let inboxDown = null;
let inboxTick = 0;
// The newest /market answer, kept so the verification strip can be redrawn the
// moment the inbox answers. The inbox is asked for separately and later in the
// tick, and without this the strip would show the previous tick's overdue count,
// one tick of "0 overdue" after the alarm has already gone off.
let lastMarket = null;
// How often the strip refreshes the inbox while nothing is in flight. Every
// eighth tick is four seconds, the same idle cadence the profit series uses.
// An entry in flight overrides this and polls every tick.
const INBOX_EVERY = 8;

async function loadIdentity(fresh) {
  if (fresh && identity?.persisted && !forgetKey()) {
    throw new Error("The browser could not remove the saved key. It kept the current account.");
  }
  if (fresh) {
    lastOrder = null;
    lastOwnFill = null;
  }
  let seed = fresh ? null : fromHex(readKey() || "");
  let persisted = !fresh && seed !== null && seed.length === 32;
  if (!persisted) {
    seed = crypto.getRandomValues(new Uint8Array(32));
  }
  const publicKey = await ed.getPublicKeyAsync(seed);
  identity = { seed, publicHex: toHex(publicKey), account: await deriveAccount(publicKey), persisted };
  hasSignedActivity = false;
  sawMyAccount = false;
  myOpenOrders = [];
  // A new key derives a new account, so the entries the old one submitted are
  // no longer this browser's to report on.
  hatch = [];
  renderHatch();
  renderIdentity();
}

function renderIdentity() {
  document.getElementById("my-account").textContent = "#" + identity.account;
  // The sentence only. The buttons that act on it are in the panel heading, so
  // a browser with `explain` off can still control whether the key persists.
  document.getElementById("key-note").textContent = identity.persisted
    ? "This browser stores an unencrypted copy of this demo key. A person or script with " +
      "access to this browser profile can copy it. This is not a wallet."
    : "This key exists only in this tab. Reloading loses this account. Choose remember key " +
      "only on a device you control.";
  const remember = document.getElementById("remember-key");
  remember.disabled = false;
  remember.textContent = identity.persisted ? "forget key" : "remember key";
  remember.title = identity.persisted
    ? "Remove the saved copy. This tab keeps using the key until it closes."
    : "Store this unencrypted demo key in this browser profile.";
  remember.onclick = () => {
    if (identity.persisted) {
      if (!forgetKey()) {
        return showMessage("neg", "The browser could not remove the saved key.");
      }
      identity.persisted = false;
      renderIdentity();
      showMessage("why", "The saved copy is gone. This tab still holds the key.");
      return;
    }
    if (!writeKey(toHex(identity.seed))) {
      return showMessage("neg", "The browser could not save this key.");
    }
    identity.persisted = true;
    renderIdentity();
    showMessage("why", "This browser now stores the demo key unencrypted.");
  };
  document.getElementById("new-key").onclick = async () => {
    if (submissionsInFlight > 0) {
      return showMessage("neg", "Wait for the signed request to finish before changing keys.");
    }
    try {
      await loadIdentity(true);
      myOpenOrders = [];
      showMessage("why", "This page made a new session-only key. This tab now trades as account #" +
        identity.account + ".");
    } catch (e) {
      showMessage("neg", e.message);
    }
  };
}

// What the feed answers with, and what each answer means to whoever holds the
// key. The feed keeps these apart on purpose. A request built wrong, a
// signature that does not cover what was sent, and a key that is not this
// account's are three different problems. So this does not flatten them into
// "failed".
const REFUSALS = {
  400: "The page built the order wrong. Or the price is not on the price step.",
  401: "The signature does not cover what the page sent.",
  403: "A different key owns this account number.",
  409: "The sequencer has this signed order already.",
  429: "This address sent too many orders. Wait, then send it again.",
  503: "The sequencer could not write the order to disk. It did not publish the order.",
};

// Two of those mean something else on the separate service, because the inbox is
// not the party that publishes: nothing it accepts is a feed message yet, and
// it refuses at a cap on how many entries may be waiting rather than at a
// failed write.
const INBOX_REFUSALS = {
  ...REFUSALS,
  409: "The separate service recorded this order already.",
  503: "The separate service is full. The sequencer is not taking its entries.",
};

class Refusal extends Error {
  constructor(status, detail) {
    super(detail);
    this.status = status;
    this.detail = detail;
  }
}

// Signs one statement and sends the result to one of the two doors.
//
// The statement, the nonce and the signature are byte for byte the same
// whichever door is chosen. That is the whole point of the separate service, and
// the reason `wrap` is the only thing that differs here. The feed's endpoints
// take the submission's fields flat with the proof beside them; the inbox
// takes the submission as an object with the proof beside it. One signature,
// two envelopes.
async function send(url, service, statement, wrap) {
  hasSignedActivity = true;
  submissionsInFlight += 1;
  try {
    const signature = await ed.signAsync(statement, identity.seed);
    const payload = wrap(identity.publicHex, toHex(signature));
    let res;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      // A browser reports a blocked cross-origin request and an unreachable host
      // identically, and this is the likeliest thing to be wrong in a fresh
      // deployment, so it names the flag rather than saying "network error".
      throw new Refusal(0,
        "The browser cannot reach " + url + ". Two things do this. The " + service + " is not " +
        "running. Or the operator did not start it with --ui-origin " + location.origin + ", and " +
        "the browser then refuses to send the order.");
    }
    if (res.ok) return res.json();
    throw new Refusal(res.status, (await res.text()).trim());
  } finally {
    submissionsInFlight = Math.max(0, submissionsInFlight - 1);
  }
}

window.addEventListener("beforeunload", (event) => {
  const unpersistedAccountAtRisk = !identity?.persisted &&
    (hasSignedActivity || myOpenOrders.length > 0);
  if (submissionsInFlight === 0 && !unpersistedAccountAtRisk) return;
  event.preventDefault();
  event.returnValue = "";
});

// The front door: the submission's own fields, with the key and signature
// beside them, exactly as `feed_body` builds the body in services/src/main.rs.
async function submit(path, statement, body) {
  return send(feedUrl + path, "sequencer", statement,
    (public_key, signature) => ({ ...body, public_key, signature }));
}

// The separate service: the same statement and the same signature, wrapped in the
// `SignedSubmission` shape `POST /submit` takes. `submission` is the tagged
// enum services/src/inbox.rs serializes, so an order is {"Order": {...}} and a
// cancel is {"Cancel": {...}}.
async function submitViaInbox(statement, submission) {
  return send(inboxUrl + "/submit", "separate service", statement,
    (public_key, signature) => ({ submission, public_key, signature }));
}

// The panel scrolls inside itself when the column is short, so the answer to a
// click can be below the fold, which for a separate-service submission is the
// whole point of the click. Scrolled into view here, in the panel only: the
// page body does not scroll.
function resultSpan(className, text) {
  const span = document.createElement("span");
  span.className = className;
  span.textContent = String(text);
  return span;
}

function showResult(...nodes) {
  const el = document.getElementById("trade-result");
  el.replaceChildren(...nodes);
  // The panel scrolls inside itself when the column is short, so the answer to
  // a click can be below the fold, which for a separate-service submission is
  // the whole point of the click. The journey list sits directly under this
  // line and scrolls on its own with the newest first, so bringing this line
  // into view brings the newest entry with it. Nothing else moves: the page
  // body does not scroll.
  el.scrollIntoView({ block: "nearest" });
}

function showMessage(className, headline, detail) {
  const nodes = [resultSpan(className, headline)];
  if (detail !== undefined) {
    nodes.push(document.createElement("br"), resultSpan("why", detail));
  }
  showResult(...nodes);
}

// The receipt is the feed's signature over a history that contains the message
// it just assigned: proof of inclusion the submitter keeps. Shown in short, and
// the full chain is on the element for anyone who wants to copy it out.
function showAccepted(what, response) {
  const chain = response.receipt.chain;
  const detail = resultSpan("why", "The sequencer signed a receipt for it. The receipt covers the log up to " +
    "message " + response.receipt.last_id + " of session " + response.receipt.session + ". Chain hash ");
  const hash = document.createElement("code");
  hash.title = String(chain);
  hash.textContent = String(chain).slice(0, 12) + "…";
  detail.append(hash, ".");
  showResult(
    resultSpan("pos", what + " is message #" + response.id + " in the log."),
    document.createElement("br"),
    detail,
  );
}

// ===========================================================================
// What the exchange did with the last order
//
// A receipt says the order is in the log. It does not say what the exchange
// did with it, and for an order carrying terms that is most of the question: a
// post-only order that would have taken is refused, and until now this panel
// said "message #4211 in the log" and stopped there. The exchange had the
// answer and was keeping it.
//
// Three outcomes, in the order this can tell them apart:
//
//   1. the order is in `GET /open-orders` for this account: it is waiting;
//   2. it is in `GET /trades` for this account: it traded;
//   3. neither, so the exchange refused it, and `orders_ignored_by_reason` on
//      `GET /market` says which reasons fired while it was being read.
//
// The third answer is a count and not a name. The exchange counts refusals by
// reason and does not record which order each count was for, so this compares
// the counts before the order was sent with the counts now, and narrows the
// list to the reasons this order's own terms can produce. When exactly one
// reason moved by exactly one, that is this order and the line says so. When
// more moved, the line lists them and says plainly that it cannot pick.
let lastOrder = null;

// How many ticks an order stays watched before this gives up. The exchange
// reads the log continuously, so an order that is neither resting, nor traded,
// nor counted as refused is almost always one whose trade has not reached this
// page yet. Six ticks is three seconds.
const OUTCOME_TICKS = 6;
// `/trade-log` is paged at this size by the matcher. Ten pages keep one browser
// click bounded even if other accounts trade between submission and outcome.
const ORDER_TRADE_PAGE = 1000;
const MAX_ORDER_TRADE_PAGES = 10;

// Capture the trade cursor and refusal counters before the request leaves this
// page. Capturing them after the sequencer answers can miss a fast fill or
// refusal that the matcher has already applied.
function outcomeSnapshot(fields, priceCents, quantityTenths) {
  const rawTradesBefore = lastMarket && lastMarket.total_trades;
  const tradesBefore = rawTradesBefore == null ? null : Number(rawTradesBefore);
  const rawRunId = lastMarket && lastMarket.state_run_id;
  const runId = rawRunId == null ? null : Number(rawRunId);
  return {
    account: fields.account,
    symbol: fields.symbol,
    side: fields.side,
    session: fields.session,
    priceCents,
    quantityTenths,
    tradesBefore: tradesBefore !== null && Number.isSafeInteger(tradesBefore) && tradesBefore >= 0
      ? tradesBefore
      : null,
    runId: runId !== null && Number.isSafeInteger(runId) ? runId : null,
    before: { ...((lastMarket && lastMarket.orders_ignored_by_reason) || {}) },
  };
}

function watchOutcome(id, kind, snapshot) {
  lastOrder = {
    id,
    kind,
    ...snapshot,
    // The receipt or the entry line, whichever door this came through. The
    // outcome is added under it.
    receiptNodes: Array.from(
      document.getElementById("trade-result").childNodes,
      (node) => node.cloneNode(true),
    ),
    tries: 0,
    settled: false,
  };
}

// The receipt, with the outcome under it. It does not scroll the panel:
// `showResult` already brought the receipt into view, and this line arrives a
// tick or two later, under the visitor's eye rather than under their cursor.
function showOutcome(order, ...nodes) {
  const receiptNodes = order.receiptNodes.map((node) => node.cloneNode(true));
  document.getElementById("trade-result").replaceChildren(
    ...receiptNodes,
    document.createElement("br"),
    ...nodes,
  );
}

function ownsTrade(row, orderId) {
  return Number(row.maker_order) === orderId || Number(row.taker_order) === orderId;
}

// Turn either trade endpoint into the engine's integer units. `/trade-log`
// already carries those units. `/trades` is the no-state-db fallback and must
// make the same grid check the order form makes before its floats are trusted.
function checkedOrderTrade(row, order, integerFields) {
  const tradeId = Number(row.trade_id);
  const timestamp = Number(row.timestamp);
  const priceCents = integerFields
    ? Number(row.price_cents)
    : toGrid(Number(row.price), PRICE_SCALE);
  const qtyTenths = integerFields
    ? Number(row.qty_tenths)
    : toGrid(Number(row.quantity), QUANTITY_SCALE);
  if (!Number.isSafeInteger(tradeId) || tradeId <= 0 ||
      !Number.isSafeInteger(timestamp) || timestamp < 0 ||
      !Number.isSafeInteger(priceCents) || priceCents <= 0 ||
      !Number.isSafeInteger(qtyTenths) || qtyTenths <= 0 ||
      String(row.symbol) !== order.symbol) {
    throw new Error("the exchange returned a malformed fill for this order");
  }
  return { tradeId, timestamp, priceCents, qtyTenths };
}

// Read the exact interval between the trade count captured before submission
// and the count reported after the matcher has read the order. Other accounts'
// fills may sit inside that interval, so every page is filtered by order id.
async function loggedOrderTrades(order, through) {
  let cursor = order.tradesBefore;
  const rows = [];
  if (cursor === through) return { rows, complete: true };
  for (let pageNumber = 0; pageNumber < MAX_ORDER_TRADE_PAGES; pageNumber++) {
    const page = await get("/trade-log?since=" + cursor);
    if (!page || Number(page.run_id) !== order.runId || !Array.isArray(page.trades)) {
      throw new Error("the trade record changed runs or was malformed");
    }
    if (page.trades.length > ORDER_TRADE_PAGE) {
      throw new Error("the trade record exceeded its documented page size");
    }
    if (page.trades.length === 0) return { rows, complete: cursor >= through };
    let previous = cursor;
    for (const raw of page.trades) {
      const tradeId = Number(raw.trade_id);
      if (!Number.isSafeInteger(tradeId) || tradeId !== previous + 1) {
        throw new Error("the trade record is not contiguous and strictly ordered");
      }
      previous = tradeId;
      if (tradeId > through) return { rows, complete: true };
      cursor = tradeId;
      if (ownsTrade(raw, order.id)) rows.push(checkedOrderTrade(raw, order, true));
    }
    if (cursor >= through) return { rows, complete: true };
    if (page.trades.length < ORDER_TRADE_PAGE) return { rows, complete: false };
  }
  return { rows, complete: false };
}

// A matcher started with `--no-state-db` cannot serve `/trade-log`. Its recent
// endpoint can still prove a complete result when the response ends before the
// 1000-row cap, or when an older account trade appears before this order's
// first fill. Otherwise the answer is labelled incomplete.
async function recentOrderTrades(order) {
  const raw = await get("/trades?account=" + order.account + "&n=" + ORDER_TRADE_PAGE);
  if (!Array.isArray(raw)) throw new Error("the recent trade response was malformed");
  const rows = [];
  let firstMine = -1;
  for (let i = 0; i < raw.length; i++) {
    if (!ownsTrade(raw[i], order.id)) continue;
    if (firstMine < 0) firstMine = i;
    rows.push(checkedOrderTrade(raw[i], order, false));
  }
  return {
    rows,
    complete: raw.length < ORDER_TRADE_PAGE || firstMine > 0,
  };
}

async function orderTrades(order, market) {
  const through = Number(market.total_trades);
  const currentRun = market.state_run_id == null ? null : Number(market.state_run_id);
  if (String(market.feed_session || "") !== order.session) {
    return { rows: [], complete: false, runChanged: true };
  }
  const canReadLog = order.tradesBefore !== null && order.runId !== null &&
    Number.isSafeInteger(through) && through >= order.tradesBefore &&
    currentRun !== null && Number.isSafeInteger(currentRun) && currentRun === order.runId;
  if (canReadLog) {
    try {
      return await loggedOrderTrades(order, through);
    } catch (e) {
      // `--no-state-db` answers 503 here. The bounded recent-trades path below
      // is also the safe fallback for a transient or malformed audit response.
    }
  } else if (order.runId !== null &&
      (currentRun === null || !Number.isSafeInteger(currentRun) || currentRun !== order.runId ||
       (Number.isSafeInteger(through) && through < order.tradesBefore))) {
    return { rows: [], complete: false, runChanged: true };
  }
  return recentOrderTrades(order);
}

function summarizeOrderTrades(rows) {
  let quantityTenths = 0n;
  let notional = 0n;
  let minCents = null;
  let maxCents = null;
  const timestamps = new Set();
  for (const row of rows) {
    const price = BigInt(row.priceCents);
    const quantity = BigInt(row.qtyTenths);
    quantityTenths += quantity;
    notional += price * quantity;
    minCents = minCents === null || row.priceCents < minCents ? row.priceCents : minCents;
    maxCents = maxCents === null || row.priceCents > maxCents ? row.priceCents : maxCents;
    timestamps.add(row.timestamp);
  }
  return {
    quantityTenths,
    averageCents: Number((notional + quantityTenths / 2n) / quantityTenths),
    minCents,
    maxCents,
    timestamps: [...timestamps],
  };
}

function markOwnFill(order, summary) {
  lastOwnFill = {
    orderId: order.id,
    symbol: order.symbol,
    minCents: summary.minCents,
    maxCents: summary.maxCents,
    timestamps: summary.timestamps,
  };
  // The ordinary refresh may have started its candle request before this fill
  // resolved. Ask for the two-bucket tail once more for this order only.
  if (symbol === order.symbol) {
    refreshCandleChart().catch(() => {});
  }
}

function fillOutcome(order, found, resting) {
  const summary = summarizeOrderTrades(found.rows);
  if (summary.quantityTenths > BigInt(order.quantityTenths)) {
    return [
      resultSpan("neg", "The trade record assigns more than the requested quantity to this order."),
      document.createTextNode(" "),
      resultSpan("why", "The page will not display an impossible fill total."),
    ];
  }
  markOwnFill(order, summary);
  const filled = Number(summary.quantityTenths) / QUANTITY_SCALE;
  const requested = order.quantityTenths;
  const unfilledTenths = BigInt(requested) > summary.quantityTenths
    ? BigInt(requested) - summary.quantityTenths
    : 0n;
  const unfilled = Number(unfilledTenths) / QUANTITY_SCALE;
  const range = summary.minCents === summary.maxCents
    ? ""
    : " (" + fmtP(summary.minCents / PRICE_SCALE) + " to " +
      fmtP(summary.maxCents / PRICE_SCALE) + ")";
  const exact = found.complete ? "It traded " : "This page verified at least ";
  let why = "The signed " + fmtP(order.priceCents / PRICE_SCALE) + " " +
    order.side.toLowerCase() + " bound was the " +
    (order.side === "Buy" ? "most" : "least") +
    " you accepted, not the execution price. Resting orders set the fill prices.";
  if (!found.complete) {
    why += " The bounded history check did not cover the complete trade interval, so the final " +
      "filled and canceled quantities are unknown.";
  } else if (resting) {
    why += " " + fmtQ(resting.quantity) + " is still waiting in the book at " +
      fmtP(resting.price) + ".";
  } else if ((order.kind.id === "ioc" || order.kind.id === "market") && unfilled > 0) {
    why += " The exchange canceled the other " + fmtQ(unfilled) + ". " +
      (order.kind.id === "market"
        ? "A partial-fill market order never rests."
        : "An immediate-or-cancel order never rests.");
  } else {
    why += " Nothing is left of it in the book.";
  }
  if (symbol === order.symbol) {
    why += " Its candle is outlined in gold when that candle is in the chart window.";
  }
  return [
    resultSpan(
      "pos",
      exact + fmtQ(filled) +
        (found.complete ? " of " + fmtQ(requested / QUANTITY_SCALE) : "") + " " +
        order.symbol + " at an average of " + fmtP(summary.averageCents / PRICE_SCALE) + range +
        ".",
    ),
    document.createTextNode(" "),
    resultSpan("why", why),
  ];
}

async function resolveOutcome(market, openOrders) {
  const order = lastOrder;
  if (!order || order.settled) return;
  if (market.last_feed_id < order.id) {
    return showOutcome(
      order,
      resultSpan("why", "The exchange has not read message #" + order.id + " yet."),
    );
  }
  const resting = openOrders.find((row) => row.id === order.id);
  // It may both have traded and have a remainder waiting, so resting is not a
  // final answer until the fills in this order's exact trade interval are read.
  let found;
  try {
    found = await orderTrades(order, market);
  } catch (e) {
    return;
  }
  if (found.runChanged) {
    order.settled = true;
    return showOutcome(
      order,
      resultSpan(
        "why",
        "The exchange started another run before this page could read the outcome. This page " +
          "will not mix trades from two runs.",
      ),
    );
  }
  if (found.rows.length) {
    order.settled = true;
    return showOutcome(order, ...fillOutcome(order, found, resting));
  }
  if (resting && found.complete) {
    order.settled = true;
    return showOutcome(
      order,
      resultSpan("pos", "It is waiting in the book."),
      document.createTextNode(" "),
      resultSpan(
        "why",
        fmtQ(resting.quantity) + " left at " + fmtP(resting.price) +
          ". It has not traded, so it has not changed a candle.",
      ),
    );
  }
  if (!found.complete) {
    order.tries += 1;
    if (order.tries >= OUTCOME_TICKS) {
      order.settled = true;
      return showOutcome(
        order,
        resultSpan(
          "why",
          "Message #" + order.id + " is in the log, but this page's bounded history check " +
            "could not cover its complete trade interval.",
        ),
      );
    }
    return showOutcome(
      order,
      resultSpan("why", "The exchange has read it. Reading its complete fill interval."),
    );
  }
  // Refused. Only the reasons this order's terms can reach are considered: a
  // market order cannot be refused for being post-only, and counting that
  // reason against it would be a guess dressed as an answer.
  const candidates = (order.kind.refusals || []).concat(SHARED_REFUSALS);
  const now = market.orders_ignored_by_reason || {};
  const moved = candidates
    .map((key) => [key, (now[key] || 0) - (order.before[key] || 0)])
    .filter(([, count]) => count > 0);
  const named = (key) => String(DROP_REASONS[key] || key);
  if (moved.length === 1 && moved[0][1] === 1) {
    order.settled = true;
    return showOutcome(
      order,
      resultSpan("neg", "The exchange refused it: " + named(moved[0][0]) + "."),
      document.createElement("br"),
      resultSpan(
        "why",
        "It is in the log, and it is not in the book and it traded nothing. The exchange refused " +
          "exactly one order for that reason while it read yours, so that one was yours. " +
          "It changed no candle.",
      ),
    );
  }
  if (moved.length) {
    order.settled = true;
    return showOutcome(
      order,
      resultSpan("neg", "The exchange refused it."),
      document.createElement("br"),
      resultSpan(
        "why",
        "While it read your order it refused orders for these reasons: " +
          moved.map(([key, count]) => count + " " + named(key)).join(", ") +
          ". One of those is your order. This page cannot say which: the exchange counts " +
          "refusals by reason and does not record which order each count was for.",
      ),
    );
  }
  // Nothing counted, nothing traded, nothing resting. Almost always a fill
  // this page has not caught up with, so it waits rather than guessing.
  order.tries += 1;
  if (order.tries >= OUTCOME_TICKS) {
    order.settled = true;
    return showOutcome(
      order,
      resultSpan(
        "why",
        "Message #" + order.id + " is in the log. It is not in the book, it traded nothing " +
          "this page can see, and the exchange counted no refusal your order could have caused.",
      ),
    );
  }
  showOutcome(order, resultSpan("why", "The exchange has read it. Working out what it did."));
}

// The inbox's answer is a durable record, not a signature: it says the
// submission exists and when its inclusion clock started, and nothing more.
// Saying so is the honest version: the feed's receipt proves inclusion, and
// the entry has not been included yet. What happens to it next is the journey
// rendered underneath.
function showRecorded(what, entry, order, kind, outcome) {
  hatch.unshift({
    id: Number(entry.inbox_id),
    what,
    t0: performance.now(),
    feed_id: null,
    sequenced_ms: null,
    overdue: false,
    missing: false,
    // The order as it was signed, for `rememberSent` once this entry has a
    // feed id. Absent on a cancel, which has no price to record.
    order: order || null,
    // Which of the six kinds this was, so the outcome line can be worked out
    // once the sequencer gives the entry a message number. Absent on a cancel.
    kind: kind || null,
    // The matcher trade cursor from before this entry left the browser.
    outcome: outcome || null,
  });
  // Rendered before the result line, so the scroll that line triggers can
  // bring the new journey block into view with it.
  renderHatch();
  showMessage(
    "pos",
    "The separate service recorded " + what + " as entry #" + entry.inbox_id + ".",
    "The separate service has your order. The sequencer does not have it yet. " +
      "Only the sequencer signs a receipt.",
  );
}

function showRefusal(e, service) {
  if (!(e instanceof Refusal)) {
    showMessage("neg", "The page could not send the order.", e.message);
    return;
  }
  const meanings = service === "inbox" ? INBOX_REFUSALS : REFUSALS;
  const headline = e.status
    ? e.status + ": " + (meanings[e.status] || "The service refused the order.")
    : "The page did not send the order.";
  const nodes = [
    resultSpan("neg", headline),
    document.createElement("br"),
    resultSpan("why", e.detail),
  ];
  let reset = null;
  if (e.status === 403) {
    const pinned = resultSpan(
      "why",
      "A different key claimed account #" + identity.account +
        " first. A new key gives you a new account number. ",
    );
    reset = document.createElement("button");
    reset.className = "linkish";
    reset.textContent = "make a new key";
    pinned.append(reset);
    nodes.push(document.createElement("br"), pinned);
  }
  showResult(...nodes);
  if (reset) {
    reset.onclick = async () => {
      if (submissionsInFlight > 0) {
        return showMessage("neg", "Wait for the signed request to finish before changing keys.");
      }
      try {
        await loadIdentity(true);
        showMessage("why", "This page made a new session-only key. This tab now trades as account #" +
          identity.account + ".");
      } catch (error) {
        showMessage("neg", error.message);
      }
    };
  }
}

// Other panels still use bounded HTML templates. Values that enter those
// templates pass through this helper rather than being trusted as markup.
function escapeText(text) {
  const node = document.createElement("div");
  node.textContent = text;
  return node.innerHTML;
}

// What this browser sent, and which feed message it became.
//
// Kept so the anchors view can answer the question a visitor actually has:
// "where did my order end up". The feed message id is the whole point of the
// record. An anchor commits to a history up to some id, so an order is
// covered by the first anchor whose lastId reaches its id, and nothing else
// about the order is needed to establish that. The rest is here so the answer
// can name the order the way the visitor placed it rather than as a number.
//
// In storage rather than in a variable, because the wait for the next anchor
// is minutes and a reload inside that window is normal.
const SENT_ITEM = "verifiable-exchange.sent";
// Bounded like every other list on this page. Fifty is more orders than this
// demo's visitor will place, and it stops a bot pointed at this page from
// growing one origin's storage until the browser refuses to write at all.
const SENT_KEPT = 50;

// Anything read back out of storage is treated as untrusted input: it is this
// browser's own record, but it survives page versions and it ends up in
// markup, so every field is coerced here and nothing is interpolated raw.
function readSent() {
  try {
    const rows = JSON.parse(localStorage.getItem(SENT_ITEM) || "[]");
    if (!Array.isArray(rows)) return [];
    return rows
      .map((r) => ({
        id: Number(r.id),
        at: Number(r.at),
        account: Number(r.account),
        side: r.side === "Sell" ? "Sell" : "Buy",
        symbol: String(r.symbol ?? ""),
        price: Number(r.price),
        quantity: Number(r.quantity),
        route: r.route === "inbox" ? "inbox" : "feed",
      }))
      .filter((r) => Number.isFinite(r.id) && r.id > 0)
      .slice(0, SENT_KEPT);
  } catch (e) {
    return [];
  }
}

let sent = readSent();

// One record per order this browser got a feed id for. Called from both doors:
// the feed answers with the id immediately, the inbox answers with an entry
// that only becomes a feed message later, and an order that took the second
// route is no less anchored for it.
function rememberSent(rec) {
  if (!Number.isFinite(rec.id) || rec.id <= 0) return;
  sent = [rec, ...sent.filter((r) => r.id !== rec.id)].slice(0, SENT_KEPT);
  try { localStorage.setItem(SENT_ITEM, JSON.stringify(sent)); } catch (e) {}
  // The anchors view may be open while an order is placed in another tab, and
  // this is the list it is showing.
  if (anchorsOpen) renderSentOrders();
}

// ===========================================================================
// The kinds of order this page can send
//
// The exchange holds three fields: order_type, time_in_force and post_only.
// There are twelve ways to set them. Two of those twelve are orders it always
// refuses: post-only on a market order (`post_only_market`), and post-only on
// an order that may not rest (`post_only_not_resting`). Two more are a market
// order asking to rest, which step 6 cancels anyway, so they say nothing new.
//
// This list is the six that are left, named the way a trader names them. A
// visitor picks one name, and the page sets all three fields. That is why
// there is one control and not three: with three controls a visitor can build
// an order the exchange refuses on sight, and the page would have to explain a
// refusal it could have made impossible.
//
// `--order-terms` on the command line takes these same six ids, so an order
// sent from a terminal and an order sent from here are the same order.
const ORDER_KINDS = [
  {
    id: "limit", label: "Limit",
    terms: { order_type: "Limit", time_in_force: "GoodTillCancel", post_only: false },
    says: "It trades immediately against matching resting orders. Any remainder waits in the book.",
  },
  {
    id: "post-only", label: "Limit, post only",
    terms: { order_type: "Limit", time_in_force: "GoodTillCancel", post_only: true },
    says: "It must wait in the book. If it would trade the moment it arrives, the exchange " +
      "refuses it instead, so it makes no trade and changes no candle.",
    // Refusals a visitor can reach with this kind, for the outcome line.
    refusals: ["post_only_would_take"],
  },
  {
    id: "ioc", label: "Limit, immediate or cancel",
    terms: { order_type: "Limit", time_in_force: "ImmediateOrCancel", post_only: false },
    says: "It trades at matching resting prices now. The exchange drops the rest. Nothing waits.",
  },
  {
    id: "fok", label: "Limit, fill or kill",
    terms: { order_type: "Limit", time_in_force: "FillOrKill", post_only: false },
    says: "The whole quantity trades at matching resting prices now, or the exchange refuses it. " +
      "Nothing waits.",
    refusals: ["fill_or_kill_unavailable"],
  },
  {
    id: "market", label: "Market, partial fill",
    terms: { order_type: "Market", time_in_force: "GoodTillCancel", post_only: false },
    market: true,
    says: "Partial fill allowed. It trades what is available now and cancels the rest.",
    refusals: ["no_reference_price"],
  },
  {
    id: "market-fok", label: "Market, fill or kill",
    terms: { order_type: "Market", time_in_force: "FillOrKill", post_only: false },
    market: true,
    says: "All or none. The whole quantity trades at once, or the exchange refuses it.",
    refusals: ["fill_or_kill_unavailable", "no_reference_price", "fill_or_kill_collared"],
  },
];

// Refusals any order can reach, whatever its terms. Step 1 and step 4 read
// none of the three fields.
const SHARED_REFUSALS = [
  "unlisted_symbol", "off_grid", "off_price_step", "off_quantity_step",
  "self_trade", "position_overflow",
];

// Which kind is selected. The id, not the object, so a reload of the list
// cannot leave a stale reference behind.
let orderKind = "limit";
// The price the visitor typed for a limit order, kept while a market order has
// the field. A market order writes its own bound into the price field, and
// without this the visitor's own number would be gone when they switch back.
let typedPrice = "";
// Whether the page had to move the selection off a market kind because the
// book lost a side. It stays set until the visitor picks a kind themselves, or
// the book comes back, so the line saying what happened does not appear for
// one tick and vanish.
let marketWasDropped = false;

function kindOf(id) {
  return ORDER_KINDS.find((k) => k.id === id) || ORDER_KINDS[0];
}

// The symbol's own price step, as the exchange listed it. Read from /market
// and not assumed: BTC-USDC is listed on 1.00 and ETH-USDC on 0.01, and a page
// that assumed 0.01 would offer BTC prices the exchange drops.
function symbolRow(sym) {
  return lastMarket ? lastMarket.symbols.find((s) => s.symbol === sym) : undefined;
}

// The middle of the book, which is what the exchange's own reference price is
// an average of. `null` when one side of the book is empty.
//
// This is the page's answer to "can a market order work here". It is not the
// exchange's reference price: that is a time-weighted mid over the last thirty
// seconds and it is not served anywhere. The two agree on the question that
// matters: a symbol with both sides quoted has been feeding that average, and
// a symbol with one empty side has not.
function bookMid(sym) {
  const s = symbolRow(sym);
  if (!s || !(s.best_bid > 0) || !(s.best_ask > 0)) return null;
  return (s.best_bid + s.best_ask) / 2;
}

// The largest price range the page lets a visitor sign for a market order.
//
// The exchange's collar is 200 basis points from its reference price
// (`COLLAR_BASIS_POINTS` in step3_bound_the_price.rs), and a bound outside the
// collar is pulled back to it. For a fill-or-kill order that pullback is a
// refusal, `fill_or_kill_collared`, because the whole quantity was only
// promised at the price that arrived. So the page caps the visitor at 150 and
// not 200: it leaves room for the page's current mid and the exchange's
// time-weighted reference price to differ. The server's collar stays in force.
const MAX_MARKET_SLIPPAGE_BPS = 150;

// Reads a percent with at most two decimal places into whole basis points.
// This value becomes part of a signed integer price bound. Parsing the decimal
// spelling directly avoids rounding a value such as 0.29 through a binary
// float before deciding which bound the visitor chose.
function parseSlippageBps(text) {
  const match = String(text).trim().match(/^(\d+)(?:\.(\d{1,2}))?$/);
  if (!match) return null;
  const whole = Number(match[1]);
  const fraction = Number((match[2] || "").padEnd(2, "0"));
  const bps = whole * 100 + fraction;
  return Number.isSafeInteger(bps) && bps >= 1 && bps <= MAX_MARKET_SLIPPAGE_BPS
    ? bps
    : null;
}

function slippageText(bps) {
  return Math.floor(bps / 100) + "." + String(bps % 100).padStart(2, "0");
}

function selectedSlippageBps() {
  return parseSlippageBps(document.getElementById("slippage").value);
}

// The price a market order carries: the worst price it may fill at.
//
// ENGINE.md 4.2 says a market order is a limit order priced to cross, carrying
// a bound the client signs. So the page works one out, and the visitor signs
// it. `null` when there is no two-sided book to work it out from.
function marketBound(sym, forSide, slippageBps) {
  const mid = bookMid(sym);
  if (mid === null || !Number.isInteger(slippageBps)) return null;
  const step = (symbolRow(sym) || {}).price_step || 0.01;
  const raw = forSide === "Buy"
    ? mid * (1 + slippageBps / 10000)
    : mid * (1 - slippageBps / 10000);
  // Rounded away from the mid, so a step wider than the offset cannot round
  // the bound back inside the spread and stop it crossing at all.
  const steps = forSide === "Buy" ? Math.ceil(raw / step) : Math.floor(raw / step);
  const price = Math.round(steps * step * PRICE_SCALE) / PRICE_SCALE;
  return price > 0 ? price : null;
}

// A price written on the symbol's own step: two decimals for a step of 0.01,
// none for a step of 1.00.
function onStepText(price, step) {
  const decimals = step >= 1 ? 0 : String(step).split(".")[1].length;
  return (Math.round(price / step) * step).toFixed(decimals);
}

// Fills the dropdown, and says under the row what the selected kind does.
//
// The two market kinds are disabled when the selected symbol has no two-sided
// book. A market order on such a symbol is refused by step 3 with
// `no_reference_price`, every time, and a control that can only produce a
// refusal is worse than no control.
//
// A market kind that was already selected when the book went one-sided moves
// to Limit, because a browser will not hold a disabled option selected: the
// list is rebuilt with the two kinds disabled, the selection falls back to the
// first enabled one, and setting it back is refused. So the page follows the
// browser rather than pretending otherwise, and the price field is emptied
// with it. That is the safe end of it: a market order's bound is gone from the
// field, so a click sends nothing until the visitor types a price of their
// own. The line under the row says what happened and why.
function renderTerms() {
  const el = document.getElementById("terms");
  const sym = document.getElementById("sym").value;
  const canMarket = bookMid(sym) !== null;
  if (!canMarket && kindOf(orderKind).market) {
    orderKind = "limit";
    marketWasDropped = true;
    // The bound this page had worked out is not a price the visitor chose, so
    // it does not become their limit price.
    typedPrice = "";
  }
  if (canMarket) marketWasDropped = false;
  const wanted = ORDER_KINDS
    .map((k) => '<option value="' + k.id + '"' +
      (k.market && !canMarket ? " disabled" : "") + '>' + k.label + "</option>")
    .join("");
  if (el.innerHTML !== wanted) el.innerHTML = wanted;
  if (el.value !== orderKind) el.value = orderKind;

  const kind = kindOf(orderKind);
  const price = document.getElementById("price");
  const slippageBox = document.getElementById("slippage-box");
  const priceLabel = document.getElementById("price-label");
  const slippageBps = kind.market ? selectedSlippageBps() : null;
  slippageBox.hidden = !kind.market;
  priceLabel.textContent = kind.market
    ? (side === "Buy" ? "Max price" : "Min price")
    : "Price";
  if (kind.market) {
    // The visitor does not name the price of a market order, so the field
    // shows the bound made from their slippage choice and does not take typing.
    const bound = slippageBps === null ? null : marketBound(sym, side, slippageBps);
    price.disabled = true;
    price.value = bound === null ? "" : onStepText(bound, (symbolRow(sym) || {}).price_step || 0.01);
  } else if (price.disabled) {
    price.disabled = false;
    price.value = typedPrice;
  }

  // What the kind does is the page explaining itself, and it is off unless
  // `explain` is on. What can follow it is not: a market kind that is switched
  // off, and an order that has just become a limit order, are things that have
  // happened to the ticket on screen, and every operator has to read them.
  let note = kind.market
    ? kind.says + " "
    : '<span class="explains">' + kind.says + " </span>";
  if (!kind.market) {
    note += "A buy price is the most you accept; a sell price is the least. Fills use prices " +
      "already resting in the book, not necessarily the number in the Price field. ";
  }
  if (kind.market && slippageBps === null) {
    note += "Type max slippage from 0.01% to 1.50%.";
  } else if (kind.market) {
    const bound = marketBound(sym, side, slippageBps);
    if (bound !== null) {
      note += "Max slippage is " + slippageText(slippageBps) +
        "% from the displayed midpoint. The signed " +
        (side === "Buy" ? "max price is " : "min price is ") + fmtP(bound) +
        ". The exchange's 2% collar can only tighten it.";
    }
  }
  if (!canMarket) {
    note += "A market order needs a bid and an ask in " + escapeText(sym) +
      ". This book has only one side, so the exchange has no reference price to hold a market " +
      "order against, and the two market kinds are switched off.";
  }
  if (marketWasDropped) {
    note += " Your order was a market order and is now a limit order. The price field is empty: " +
      "type the price you want.";
  }

  document.getElementById("terms-note").innerHTML = '<span class="why">' + note + "</span>";
}

// Validated here, before anything is signed, against the rules the feed
// applies, so an off-grid price is one immediate sentence naming the value,
// not a round trip that comes back 400.
async function sendOrder() {
  const symbol = document.getElementById("sym").value;
  const kind = kindOf(orderKind);
  // Read before anything is signed. The statement names the log, so a page
  // that has not heard from the exchange yet has nothing to sign for. It is
  // read on every click and not once at load: a page left open across a reset
  // picks the new session up on the next tick, which is under half a second.
  const session = feedSession();
  if (!session) {
    return showMessage(
      "neg",
      "This page does not know which log the exchange is on yet.",
      "Every order is signed for one log. The page reads the session from the exchange twice a " +
        "second. Wait a moment and send it again.",
    );
  }
  const slippageBps = kind.market ? selectedSlippageBps() : null;
  if (kind.market && slippageBps === null) {
    return showMessage("neg", "Type max slippage from 0.01% to 1.50%.");
  }
  // A market order carries a bound made from the visitor's slippage choice,
  // not a price typed into the disabled price field.
  const priceText = kind.market
    ? String(marketBound(symbol, side, slippageBps) ?? "")
    : document.getElementById("price").value.trim();
  const qtyText = document.getElementById("qty").value.trim();
  const price = Number(priceText);
  const quantity = Number(qtyText);
  if (kind.market && priceText === "") {
    return showMessage(
      "neg",
      symbol + " has no two-sided book, so a market order has nothing to trade against.",
      "The exchange refuses a market order in a symbol it has no reference price for. Pick a " +
        "limit order, or a symbol with a bid and an ask.",
    );
  }
  if (priceText === "" || !Number.isFinite(price)) {
    return showMessage("neg", "Type a number in the price field.");
  }
  if (qtyText === "" || !Number.isFinite(quantity)) {
    return showMessage("neg", "Type a number in the quantity field.");
  }
  const priceCents = toGrid(price, PRICE_SCALE);
  if (priceCents === null) {
    return showMessage(
      "neg",
      "The exchange does not accept the price " + priceText + ".",
      "Use whole cents, from 0.01 to " + (MAX_GRID_UNITS / PRICE_SCALE) +
        ". The exchange drops other prices and says nothing. So this page does not sign the order.",
    );
  }
  const qtyTenths = toGrid(quantity, QUANTITY_SCALE);
  if (qtyTenths === null) {
    return showMessage(
      "neg",
      "The exchange does not accept the quantity " + qtyText + ".",
      "Use whole tenths, from 0.1 to " + (MAX_GRID_UNITS / QUANTITY_SCALE) + ".",
    );
  }
  const nonce = newNonce();
  const account = identity.account;
  // The grid units divided back out, never the text that was typed: this is
  // the value the signature covers, and "100.2500" and "100.25" are the same
  // order. Both doors get exactly these numbers.
  const onGridPrice = priceCents / PRICE_SCALE;
  const onGridQty = qtyTenths / QUANTITY_SCALE;
  const terms = kind.terms;
  const statement =
    orderStatement(account, symbol, side, priceCents, qtyTenths, terms, session, nonce);
  const boundWords = kind.market
    ? (side === "Buy" ? " with max price " : " with min price ")
    : (side === "Buy" ? " at no more than " : " at no less than ");
  const what = kind.label + ": " + side + " " + fmtQ(onGridQty) + " " + symbol +
    boundWords + fmtP(onGridPrice) +
    (kind.market ? " and " + slippageText(slippageBps) + "% max slippage" : "");
  // The three terms travel beside the price, always, even when they hold their
  // defaults. The signature covers all three whatever they hold, so a body
  // that dropped a default term is a body the sequencer rebuilds a different
  // statement from, and the order comes back 401.
  const fields = {
    account,
    symbol,
    side,
    price: onGridPrice,
    quantity: onGridQty,
    nonce,
    session,
    order_type: terms.order_type,
    time_in_force: terms.time_in_force,
    post_only: terms.post_only,
  };
  const outcome = outcomeSnapshot(fields, priceCents, qtyTenths);
  showMessage("why", "The page is signing your order.");
  try {
    if (route === "inbox") {
      // No feed id yet: the inbox records, the feed sequences. The fields ride
      // along on the journey record so that `pollInbox` can write the order
      // down the moment it learns which message it became.
      showRecorded(what, await submitViaInbox(statement, { Order: fields }), fields, kind, outcome);
    } else {
      const accepted = await submit("/order", statement, fields);
      rememberSent({
        id: Number(accepted.id),
        at: Date.now(),
        account,
        side,
        symbol,
        price: onGridPrice,
        quantity: onGridQty,
        route: "feed",
      });
      showAccepted(what, accepted);
      // After the receipt, so the outcome line is added under it rather than
      // replacing it.
      watchOutcome(Number(accepted.id), kind, outcome);
    }
  } catch (e) {
    showRefusal(e, route);
  }
}

async function sendCancel(targetId) {
  const nonce = newNonce();
  const account = identity.account;
  const session = feedSession();
  if (!session) {
    return showMessage(
      "neg",
      "This page does not know which log the exchange is on yet.",
      "A cancel is signed for one log, like an order. Wait a moment and send it again.",
    );
  }
  const statement = cancelStatement(account, targetId, session, nonce);
  const what = "the cancel of order #" + targetId;
  showMessage("why", "The page is signing the cancel of order #" + targetId + ".");
  try {
    if (route === "inbox") {
      showRecorded(what, await submitViaInbox(statement,
        { Cancel: { account, target_id: targetId, nonce, session } }));
    } else {
      showAccepted(what, await submit("/cancel", statement,
        { account, target_id: targetId, nonce, session }));
    }
  } catch (e) {
    showRefusal(e, route);
  }
}

// The visitor's own resting orders, straight from the exchange. Not a list this
// page remembers: an order it sent may have filled a second later, and a cancel
// button on a filled order is a button that does nothing.
//
// "From last" is how far the order's price is from the price of the last trade
// in that symbol. That is the number that says whether the order can fill: an
// order far from the last price waits, and the table did not say so before.
// The mark comes from the same /market answer the ticker above is drawn from,
// so the two never disagree.
function renderMyOrders(orders) {
  myOpenOrders = orders;
  const marks = new Map(
    (lastMarket ? lastMarket.symbols : []).map((s) => [s.symbol, s.last_trade_price]));
  document.getElementById("my-orders").innerHTML = orders.map((o) => {
    const mark = marks.get(o.symbol);
    let away = '<span class="num dim">-</span>';
    if (Number.isFinite(mark) && mark > 0) {
      const off = ((o.price - mark) / mark) * 100;
      away = '<span class="num dim" title="The order price is ' + fmtP(o.price) + ". The last trade in " +
        escapeText(o.symbol) + " was " + fmtP(mark) + ". The difference is " + fmtM(o.price - mark) + '.">' +
        (off > 0.005 ? "+" : off < -0.005 ? "−" : "") + Math.abs(off).toFixed(2) + "%</span>";
    }
    return '<div class="row">' +
      '<span class="mono">#' + o.id + "</span>" +
      "<span>" + escapeText(o.symbol) + "</span>" +
      '<span class="' + (o.side === "Buy" ? "pos" : "neg") + '">' + o.side + "</span>" +
      '<span class="num">' + fmtP(o.price) + "</span>" +
      '<span class="num">' + fmtQ(o.quantity) + "</span>" +
      away +
      '<span class="cancel"><button class="cancel-btn" data-cancel="' + o.id +
      '" title="Cancel order #' + o.id + '. This page signs the cancel with your key.">Cancel</button></span></div>';
  }).join("") ||
    '<div class="row"><span class="tk-empty">You have no open orders.' +
    '<span class="explains"> An order waits here for a trade, or for you to cancel it.</span>' +
    "</span></div>";
  for (const el of document.querySelectorAll("[data-cancel]")) {
    el.onclick = () => sendCancel(Number(el.dataset.cancel));
  }
}

function renderSymbols(market) {
  const el = document.getElementById("sym");
  const wanted = market.symbols.map((s) => s.symbol);
  if (wanted.join(",") !== Array.from(el.options, (o) => o.value).join(",")) {
    el.innerHTML = wanted.map((s) => '<option value="' + s + '">' + s + "</option>").join("");
  }
  // Follows the tab bar, which is the other way to choose a symbol here.
  if (symbol && el.value !== symbol) el.value = symbol;
  renderPricePlaceholder(market);
}

// The grey number in the empty price field, on the selected symbol's own step.
//
// It was the fixed string "9.72". With BTC-USDC selected that suggested a
// price off the 1.00 price step and thousands of percent from the book, so it
// named an order the exchange would drop. It now names the last trade in the
// selected symbol, or the best price on the book when nothing has traded yet,
// written on that symbol's step: 9.72 for ETH-USDC, 50000 for BTC-USDC.
//
// The step comes from `/market`, which serves the step each symbol was listed
// with, and not from a constant here. Two symbols on this exchange are listed
// on different steps, and a page that assumed one of them is wrong about the
// other.
function renderPricePlaceholder(market) {
  const el = document.getElementById("price");
  const row = market.symbols.find((s) => s.symbol === symbol);
  const price = row && (row.last_trade_price || row.best_bid || row.best_ask);
  // Empty rather than stale: a symbol with no trade and an empty book has no
  // price to suggest, and inventing one would be the old bug in a new place.
  el.placeholder = price > 0 ? onStepText(price, row.price_step || 0.01) : "";
}

function setSide(next) {
  side = next;
  // A market order's bound is worked out from the side, so the price field has
  // to be rewritten when the side changes.
  if (lastMarket) renderTerms();
  document.getElementById("side-buy").className = next === "Buy" ? "on-buy" : "";
  document.getElementById("side-sell").className = next === "Sell" ? "on-sell" : "";
  const send = document.getElementById("send");
  send.textContent = next;
  send.className = next === "Sell" ? "sell" : "";
}

// ===========================================================================
// The separate service (V3), from this page
//
// The inbox is a submission service the feed does not control. An order sent
// through it is the same order, same statement, same nonce, same signature,
// taking a route the sequencer cannot refuse at the door: the inbox records it
// durably, the feed is required to drain it within the inclusion deadline, and
// an entry still pending past that deadline is reported by the inbox's own
// `GET /status` as overdue. That overdue entry, beside the feed's signed head
// which provably does not contain it, is the evidence this layer produces.
//
// Until this existed the only client for any of that was the Rust CLI, so the
// door was open to whoever could build the binary, which is not the person it
// is for, who is remote and being refused.
// ===========================================================================

function setRoute(next) {
  route = next;
  document.getElementById("route-feed").className = next === "feed" ? "on" : "";
  document.getElementById("route-inbox").className = next === "inbox" ? "on" : "";
  renderRouteNote();
}

// One short line at the end of the ticket row: what the selected path does.
//
// "Feed" and "inbox" are the names in /config and in the Rust code and they
// stay there. Nobody arriving at this page knows what either word means, so
// what a person reads is the path and what happens on it. The deadline is the
// separate service's own number, read from its GET /status, so the sentence never
// states a deadline this deployment does not run.
function renderRouteNote() {
  const el = document.getElementById("route-note");
  if (!el) return;
  const limit = inboxStatus ? fmtSecs(inboxStatus.deadline_ms) : "5.0s";
  if (!inboxUrl) {
    el.innerHTML = "<b>Direct.</b> This page sends your signed order to the sequencer.";
    return;
  }
  el.innerHTML = route === "inbox"
    ? "<b>Separate service.</b> A different service records your order first. " +
      "The sequencer must put your order in the log in " + limit + ". " +
      "If the sequencer is late, the separate service reports the delay in public."
    : "<b>Direct.</b> This page sends your signed order to the sequencer. " +
      "This is the fastest path. The sequencer decides if it takes your order.";
}

function fmtSecs(ms) {
  return (ms / 1000).toFixed(1) + "s";
}

// The most journey blocks kept and shown. A visitor placing many orders should
// not grow this without limit, and the ones worth reading are the recent ones.
const HATCH_SHOWN = 8;

// One block per submission this page put through the separate service, and what
// has become of it. An order that simply appeared would demonstrate nothing: it
// would look exactly like a submission sent straight to the sequencer. The two
// states here are the layer: recorded by
// a service the sequencer does not control, then sequenced by the sequencer,
// with the time it took beside the deadline it had.
function renderHatch() {
  const el = document.getElementById("hatch");
  if (hatch.length > HATCH_SHOWN) hatch.length = HATCH_SHOWN;
  if (!hatch.length) { el.innerHTML = ""; return; }
  // "5.0s " when the inbox has told us its deadline, "" until then, so every
  // sentence below reads the same with and without it.
  const deadline = inboxStatus ? fmtSecs(inboxStatus.deadline_ms) + " " : "";
  el.innerHTML = hatch.map((h) => {
    let state;
    if (h.missing) {
      state = '<span class="neg">The separate service does not have this entry now.</span>';
    } else if (h.feed_id != null) {
      state = '<span class="pos">The sequencer put it in the log as message #' + h.feed_id + ".</span>" +
        (h.sequenced_ms == null ? "" : " The sequencer took " + fmtSecs(h.sequenced_ms) + ".") +
        (deadline ? " The limit is " + deadline.trim() + "." : "");
    } else if (h.overdue) {
      state = '<span class="neg">Late.</span>' +
        (deadline ? " The limit was " + deadline.trim() + "." : "") +
        " The sequencer still did not put it in the log. The separate service reports this on its own " +
        "GET /status. That report is the evidence.";
    } else {
      state = "The separate service has it for " + fmtSecs(performance.now() - h.t0) + "." +
        (deadline ? " The limit is " + deadline.trim() + "." : "") +
        " The sequencer did not put it in the log yet.";
    }
    return '<div class="h-row"><div class="h-what"><span class="mono">separate service #' + h.id +
      "</span> " + escapeText(h.what) + '</div><div class="h-state">' + state + "</div></div>";
  }).join("");
}

// Reads the inbox for the strip and for the blocks above.
//
// Two endpoints, both already there. `GET /status` is the verdict. It owns
// `deadline_ms` and the overdue list, and overdue is the inbox's call to make,
// not this page's: computing it here from a browser clock against timestamps
// from another machine's clock would be this page's opinion dressed up as
// evidence. `GET /entries?ids=` answers "what became of the entry I hold the
// id for", which `?n=` cannot: past a page of other submissions the entry
// falls out of the window, and an entry that cannot be found reads exactly
// like one the feed never sequenced.
async function pollInbox() {
  if (!inboxUrl) return;
  const watching = hatch.filter((h) => h.feed_id == null && !h.missing).map((h) => h.id);
  // An entry in flight is watched every tick, because the transition it is
  // waiting for takes about one feed tick. With nothing in flight the strip is
  // all that needs the inbox, and it can wait.
  if (!watching.length && inboxTick++ % INBOX_EVERY !== 0) return;
  try {
    const [status, mine] = await Promise.all([
      getFrom(inboxUrl, "/status"),
      watching.length
        ? getFrom(inboxUrl, "/entries?ids=" + watching.join(","))
        : Promise.resolve([]),
    ]);
    inboxStatus = status;
    inboxDown = null;
    const found = new Map(mine.map((e) => [e.inbox_id, e]));
    const overdue = new Set(status.overdue.map((e) => e.inbox_id));
    for (const h of hatch) {
      if (h.feed_id != null) continue;
      const entry = found.get(h.id);
      if (!entry) {
        // Only reachable if the row went away, which nothing in the service
        // does. Said out loud rather than left looking pending forever.
        if (watching.includes(h.id)) h.missing = true;
        continue;
      }
      h.missing = false;
      h.overdue = overdue.has(h.id);
      if (entry.feed_id != null) {
        // Coerced rather than interpolated as it arrived: these numbers come
        // off a second service and end up in the panel's markup.
        h.feed_id = Number(entry.feed_id);
        h.overdue = false;
        // The entry is a feed message now, so it is in the history the next
        // anchor commits to, and the anchors view can follow it from here.
        if (h.order) {
          rememberSent({
            id: h.feed_id,
            at: Date.now(),
            account: h.order.account,
            side: h.order.side,
            symbol: h.order.symbol,
            price: h.order.price,
            quantity: h.order.quantity,
            route: "inbox",
          });
          // The entry is a message now, so the exchange will read it and this
          // panel can say what it did with it. The same watch the direct route
          // starts, one hop later.
          if (h.kind) {
            watchOutcome(h.feed_id, h.kind, h.outcome);
          }
          h.order = null;
        }
        // Both stamps come from the inbox's own clock, so the difference is a
        // real interval; the browser's clock is never mixed into it.
        h.sequenced_ms = entry.sequenced_at == null
          ? null
          : entry.sequenced_at - entry.received_at;
      }
    }
  } catch (e) {
    inboxStatus = null;
    inboxDown = e.message;
  }
  renderHatch();
  // The note beside the route buttons states the separate service's own deadline,
  // and this is the read that learns it.
  renderRouteNote();
  // The strip was drawn earlier in this tick, before any of the above was
  // known. Redrawn here so the alarm is never a tick behind the evidence.
  if (lastMarket) renderVerify(lastMarket);
}

// ===========================================================================
// explain
//
// Off, this page is the exchange and nothing else: an order book, a chart, a
// ticket, the tables, and the verification strip. On, it adds what it says
// about itself: what the selected order kind does, what the key in this
// browser is, the three steps an order takes. And the second path an order
// can take to the same sequencer. The stylesheet holds the list; see
// `.explains` there.
//
// Off is the default because the reader who needs the sentences reads them
// once and the operator reads them on every load. Kept in this browser, so
// that choice is made once too.
// ===========================================================================

const EXPLAIN_ITEM = "verifiable-exchange.explain";
let explaining = false;
try {
  explaining = localStorage.getItem(EXPLAIN_ITEM) === "1";
} catch (e) {
  // Storage switched off. The page opens with the sentences off, which is what
  // a first visit does anyway.
}

function setExplain(on) {
  explaining = on;
  document.body.classList.toggle("explaining", on);
  const b = document.getElementById("explain");
  b.className = on ? "iv active" : "iv";
  b.setAttribute("aria-pressed", on ? "true" : "false");
  // The route buttons leave the screen with the sentences, and an order must
  // never take a path its sender can no longer see. Direct is the path with no
  // second service in it, and the one this page uses when the operator runs no
  // separate service at all.
  if (!on && route !== "feed") setRoute("feed");
  try { localStorage.setItem(EXPLAIN_ITEM, on ? "1" : "0"); } catch (e) {}
}

document.getElementById("explain").onclick = () => setExplain(!explaining);
setExplain(explaining);

document.getElementById("route-feed").onclick = () => setRoute("feed");
document.getElementById("route-inbox").onclick = () => setRoute("inbox");
// Never blank, even when /config never answers and the route buttons stay
// hidden: the line then says what the one path this page has does.
renderRouteNote();
// Drawn once before any market answer, so the dropdown is never an empty box.
// With no book read yet the two market kinds are switched off, which is the
// true answer at that moment.
renderTerms();
document.getElementById("side-buy").onclick = () => setSide("Buy");
document.getElementById("side-sell").onclick = () => setSide("Sell");
document.getElementById("send").onclick = async () => {
  if (sending) return;
  sending = true;
  document.getElementById("send").disabled = true;
  try {
    await sendOrder();
  } finally {
    sending = false;
    document.getElementById("send").disabled = false;
  }
};
for (const id of ["price", "qty", "slippage"]) {
  document.getElementById(id).addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("send").click();
  });
}
// The visitor's own price, kept while a market order has the field. A market
// order writes the bound it will sign into the same input, and without this the
// number the visitor typed would be gone when they picked a limit order again.
document.getElementById("price").addEventListener("input", (e) => {
  if (!e.target.disabled) typedPrice = e.target.value;
});
document.getElementById("slippage").addEventListener("input", renderTerms);
document.getElementById("terms").onchange = () => {
  orderKind = document.getElementById("terms").value;
  // The visitor has chosen for themselves, so the page stops explaining the
  // choice it made for them.
  marketWasDropped = false;
  renderTerms();
};
function selectSymbol(next) {
  if (!next || next === symbol) return;
  symbol = next;
  lastTradeId = 0;
  lastMessageId = 0;
  resetCandleView();
  openStream();
  // The chart does not need /market. Start it at the click, then let refresh
  // update every panel; its candle step reuses this request while it is open.
  refreshCandleChart().catch(() => {});
  refresh();
}

document.getElementById("sym").onchange = () => {
  selectSymbol(document.getElementById("sym").value);
};

// Everything the page needs before it can sign: where to send submissions, and
// which key it is. Web Crypto's SHA-512 is used for the key derivation and by
// the signer, and browsers only expose it in a secure context, so a page served
// over plain HTTP from anything but localhost says so instead of failing at the
// first click.
async function startTrading() {
  const send = document.getElementById("send");
  if (!globalThis.crypto || !crypto.subtle) {
    send.disabled = true;
    // Reported where every other failure of this panel is reported. It used to
    // be written into the key note, which is in the "This browser" block, and
    // that block is off unless `explain` is on: the Send button would have
    // been dead with nothing on screen saying why.
    showMessage(
      "neg",
      "This page cannot sign orders here.",
      "The browser gives crypto.subtle only on https, or on localhost. This page came from " +
        location.origin + ".",
    );
    return;
  }
  try {
    const config = await get("/config");
    feedUrl = config.feed_url.replace(/\/+$/, "");
    // Null when the operator runs no inbox. The route choice is then not
    // offered at all rather than offered and broken: a button that leads to a
    // service nobody started reads to a visitor as the separate service being
    // down, which is a much worse thing to say than nothing.
    inboxUrl = config.inbox_url ? config.inbox_url.replace(/\/+$/, "") : null;
    document.getElementById("route").hidden = inboxUrl === null;
    renderRouteNote();
    await loadIdentity(false);
  } catch (e) {
    send.disabled = true;
    showMessage("neg", "The page could not start trading.", e.message);
  }
}

function renderTabs(market) {
  const tabs = document.getElementById("tabs");
  if (!symbol) symbol = market.symbols[0].symbol;
  tabs.innerHTML = "";
  for (const s of market.symbols) {
    const b = document.createElement("button");
    b.className = "tab" + (s.symbol === symbol ? " active" : "");
    b.textContent = s.symbol;
    b.onclick = () => selectSymbol(s.symbol);
    tabs.appendChild(b);
  }
}

// The strip under the header. The book, the chart and the P&L are the same
// pixels whether or not the operator is honest, so none of them can show the
// one property this exchange is actually built around. These numbers can:
// every one of them is something an outside party can recompute for itself.
// One label on the strip, in both lengths. The stylesheet shows one of them,
// see `.verify .sm`. The long form is on the title attribute either way, so a
// reader on a phone can still ask what an item is.
function vk(long, short, title) {
  const t = title || long;
  return `<span class="k" title="${escapeText(t)}">` +
    `<span class="lg">${long}</span><span class="sm">${short}</span></span>`;
}

function renderVerify(market) {
  const el = document.getElementById("verify");
  if (!el) return;
  const head = market.last_feed_id ?? 0;
  const parts = [];

  // How far the engine has checked the feed's signature and hash chain
  // against the messages it actually consumed.
  const chain = market.chain_verified_at;
  parts.push(
    vk("chain checked", "chain",
      "The exchange checked the signature of the sequencer and the hash chain up to this message.") +
      ` <span class="${chain === head ? "v ok" : "v"}">` +
      `${chain == null ? "-" : chain}</span><span class="k">/ ${head}</span>`,
  );

  // How far a two-thirds majority of independent validators vouches for the
  // same ordering. Absent when no validators were configured.
  if ((market.validators_configured ?? 0) > 0) {
    const responding = market.validators_responding ?? 0;
    const configured = market.validators_configured;
    parts.push(
      vk("validators agree", "validators",
        "Two thirds of the validators agree on the log up to this message. Each validator reads the " +
          "sequencer on its own.") +
        ` <span class="v">${market.quorum_verified_at ?? 0}</span>` +
        `<span class="k">· ${responding} of ${configured}<span class="lg"> answer</span></span>`,
    );
  }

  // Committed to disk in the same transaction as the batch that produced it.
  parts.push(vk("written to disk", "disk", "The exchange wrote its work up to this message to disk.") +
    ` <span class="v">${market.durable_feed_id ?? 0}</span>`);

  // The separate service, when the operator runs one. This is the only number on
  // the strip that is not the operator's own word about their own service: it
  // comes from a process the sequencer does not control, and it says whether
  // the sequencer is honouring its inclusion deadline. Overdue above zero is
  // the censorship alarm, so it is red.
  if (inboxUrl) {
    if (inboxDown) {
      parts.push(vk("separate service", "service") + ` <span class="bad">no answer</span>`);
    } else if (inboxStatus) {
      const overdue = Number(inboxStatus.overdue_count ?? 0);
      const pending = Number(inboxStatus.pending ?? 0);
      parts.push(
        vk("separate service", "service") +
          ` <span class="v">${pending}<span class="k"> waiting · </span>` +
          `<span class="${overdue > 0 ? "bad" : "ok"}">${overdue}</span>` +
          `<span class="k"> late</span></span>`,
      );
    }
  }

  // The execution commitment. Two engines with equal roots match identically
  // from here on, which is what --audit and --audit-url check.
  if (market.state_root) {
    parts.push(
      vk("state root", "root") + ` <span class="v mono">${market.state_root.slice(0, 12)}…</span>`,
    );
  }

  // Alarms. Shown only when non-zero: a counter that is always on screen at
  // zero teaches the reader to stop looking at it.
  const alarms = [
    ["bad signatures", market.feed_integrity_failures],
    ["chain mismatches", market.feed_chain_mismatches],
    ["validator disputes", market.validator_disputes],
    ["failed disk writes", market.state_commit_failures],
  ].filter(([, n]) => (n ?? 0) > 0);
  for (const [label, n] of alarms) {
    parts.push(`<span class="bad">${label} ${n}</span>`);
  }
  if (alarms.length === 0) {
    // "self-reported" on purpose. These counters are the matcher's own record
    // of what it saw while consuming the feed, the operator's program
    // reporting on the operator's program. It is a real check, and it is the
    // one thing on this strip that an operator could simply lie about by
    // serving a modified matcher. What is not self-reported is `--audit-url`,
    // which re-executes the history from the feed and checks the signatures
    // independently, and that is the sentence a visitor should trust instead.
    parts.push(
      `<span class="ok" title="These counters come from the exchange itself. The operator runs the ` +
        `exchange. For a check that does not use this page, run --audit-url against this exchange.">` +
        `<span class="lg">the exchange reports no failures</span>` +
        `<span class="sm">no failures</span></span>`,
    );
  }

  // Last, and boxed. Everything above is the matcher's account of the matcher's
  // own work; the sentence right before this one says so. This is the one item
  // the browser fetched from a contract on a chain the operator does not run.
  // Putting it in the same run of grey counters would present the two as the
  // same kind of claim.
  const anchored = anchorPart();
  if (anchored) parts.push(anchored);

  el.innerHTML = parts.map((part) => `<span class="item">${part}</span>`).join("");
}

function renderTicker(market) {
  const s = market.symbols.find((x) => x.symbol === symbol);
  const t = document.getElementById("ticker");
  if (!s) { t.innerHTML = ""; return; }
  t.innerHTML =
    `<span>Last <b>${fmtP(s.last_trade_price)}</b></span>` +
    `<span>Bid <b class="up">${fmtP(s.best_bid)}</b></span>` +
    `<span>Ask <b class="down">${fmtP(s.best_ask)}</b></span>` +
    `<span>Spread <b>${fmtP(s.spread)}</b></span>` +
    `<span>Volume <b>${fmtQ(s.traded_volume)}</b></span>` +
    `<span>Trades <b>${s.trade_count}</b></span>`;
}

function bookRows(levels, cls, reverse) {
  let cumTenths = 0;
  const withCum = levels.map((l) => {
    cumTenths += Math.round(l.quantity * 10);
    return { ...l, cum: cumTenths / 10 };
  });
  const max = Math.max(cumTenths / 10, 1e-9);
  const rows = reverse ? withCum.slice().reverse() : withCum;
  return rows.map((l) => {
    const fill = Math.max(0, Math.min(100, (l.cum / max) * 100));
    return `<div class="row ${cls}">` +
    // A percentage of the columns, not of the panel. SVG numeric attributes
    // keep the value out of an inline style, which the page's CSP forbids.
    `<svg class="bar" viewBox="0 0 100 1" preserveAspectRatio="none" aria-hidden="true">` +
    `<rect x="${100 - fill}" y="0" width="${fill}" height="1"></rect></svg>` +
    `<span class="price">${fmtP(l.price)}</span>` +
    `<span class="num">${fmtQ(l.quantity)}</span>` +
    `<span class="num">${fmtQ(l.cum)}</span></div>`
  }).join("");
}

let firstBook = true;
function renderBook(book, market) {
  document.getElementById("asks").innerHTML = bookRows(book.asks, "ask", true);
  document.getElementById("bids").innerHTML = bookRows(book.bids, "bid", false);
  const s = market.symbols.find((x) => x.symbol === symbol);
  const last = s && s.last_trade_price;
  const dir = s && s._prevLast != null ? (last > s._prevLast ? "up" : last < s._prevLast ? "down" : "") : "";
  s && (s._prevLast = last);
  document.getElementById("spread").innerHTML =
    `<span class="last ${dir}">${fmtP(last)}</span>` +
    `<span class="lbl">Spread ${fmtP(s && s.spread)}</span>`;
  // The first fit ran before any data arrived, when the spread bar was empty
  // and 21px shorter than it is with a price in it, so it asked for one level
  // too many and the worst level on each side was drawn half cut. Fit again
  // now that the bar holds what it will hold. Only once: #book keeps the same
  // height whatever is in it, so the observer never fires for this, and every
  // later book is the same shape as this one.
  if (firstBook) { firstBook = false; fitBook(); }
}

// Sets `depth` to the number of levels a side that the panel can show now.
// The panel's height is not a constant, so the count must not be one either: a
// fixed 12 left about 190px empty above the asks and 180px below the bids in a
// normal window, room for about 19 more levels.
//
// The two lists divide whatever the other children of #book do not use. Those
// children are added up in a loop and not named, so this still measures right
// if a later change moves the panel heading inside #book.
//
// One count for both sides. An uneven split would move the spread.
//
// This writes `depth` and nothing else. It does not trim the lists and does
// not redraw them. A panel that got smaller already holds more rows than fit,
// and `overflow: hidden` with the flex direction of each list clips the top of
// the asks and the bottom of the bids, the worst prices, the right rows to
// lose. A panel that got bigger holds fewer rows than fit and has nothing to
// draw. Either way the next poll, at most 500ms later, sends the new count.
function fitBook() {
  const book = document.getElementById("book");
  const asks = document.getElementById("asks");
  const bids = document.getElementById("bids");
  // The row height is measured off a real row, never read off the stylesheet.
  // `.row` sets 18px of line and 1px of padding above and below, which is 20px
  // today, but a script that writes 20 is wrong the moment either declaration
  // changes. Before the first book arrives there is no row, so one is added
  // here, measured, and removed. Every read below happens while it is in
  // place, so the browser lays the page out once.
  let probe = bids.querySelector(".row");
  const added = probe == null;
  if (added) {
    probe = document.createElement("div");
    probe.className = "row bid";
    probe.innerHTML =
      `<span class="price">0.00</span><span class="num">0.0</span><span class="num">0.0</span>`;
    bids.appendChild(probe);
  }
  const rowH = probe.getBoundingClientRect().height;
  let fixed = 0;
  for (const child of book.children) {
    if (child !== asks && child !== bids) fixed += child.getBoundingClientRect().height;
  }
  const room = book.clientHeight;
  if (added) probe.remove();
  // The floor is 1 and not 0. depth=0 returns two empty sides, and an empty
  // book reads as "no market" rather than as "the panel is too short".
  if (rowH > 0) depth = clamp(Math.floor((room - fixed) / 2 / rowH), 1, MAX_DEPTH);
}

function renderTrades(trades) {
  const el = document.getElementById("trades");
  const fresh = trades.filter((t) => t.trade_id > lastTradeId);
  if (trades.length) lastTradeId = trades[trades.length - 1].trade_id;
  const newestFirst = trades.slice().reverse();
  el.innerHTML = newestFirst.map((t) => {
    const isFresh = fresh.includes(t);
    const cls = t.taker_side === "Buy" ? "trade-buy" : "trade-sell";
    return `<div class="row ${cls}${isFresh ? " flash" : ""}">` +
      // Right-aligned like every other figure on this page. Left-aligned, the
      // decimal points of 99.99 and 100.00 sit one character apart, and a
      // column of prices is read down the decimal point.
      `<span class="num price">${fmtP(t.price)}</span>` +
      `<span class="num">${fmtQ(t.quantity)}</span>` +
      `<span class="num">${fmtT(t.timestamp)}</span></div>`;
  }).join("");
  // The columns are sized from what is in them, and what is in them just
  // changed.
  fitTable("trades");
}

function renderFlow(messages) {
  const el = document.getElementById("flow");
  const fresh = messages.filter((m) => (m.New ? m.New.id : m.Cancel.id) > lastMessageId);
  if (messages.length) {
    const last = messages[messages.length - 1];
    lastMessageId = last.New ? last.New.id : last.Cancel.id;
  }
  const newestFirst = messages.slice().reverse();
  el.innerHTML = newestFirst.map((m) => {
    const id = m.New ? m.New.id : m.Cancel.id;
    const isFresh = fresh.includes(m);
    if (m.New) {
      const o = m.New;
      return `<div class="row flow-new${isFresh ? " flash" : ""}">` +
        `<span class="side-${o.side}">${o.side} #${o.account}${orderTerms(o)}</span>` +
        `<span class="num price">${fmtP(o.price)}</span>` +
        `<span class="num">${fmtQ(o.quantity)}</span></div>`;
    }
    return `<div class="row flow-cancel${isFresh ? " flash" : ""}">` +
      `<span>Cancel</span>` +
      `<span class="num price">#${m.Cancel.target_id}</span>` +
      `<span class="num"></span></div>`;
  }).join("");
  fitTable("flow");
}

// Why the exchange dropped the orders it dropped.
//
// `/market` has served `orders_ignored_by_reason` since the state database
// reached schema 10 and nothing on this page read it, so the status line under
// the flow said "orders dropped 214" and stopped there. A visitor whose
// post-only order was refused because something was resting at their price got
// no answer at all; the exchange had one and was keeping it.
//
// A key appears only once that refusal has happened at least once, so an empty
// object means nothing has been refused and this line says nothing. The counts
// are stored in the state database and survive a restart, so this is the whole
// run and not what happened since the page opened.
//
// A key this page does not know is printed as it arrived. An exchange newer
// than the page it serves is possible; that is what `newest_rule_set` is
// about. A refusal counted under a name this page cannot spell is still a
// refusal a reader should see.
const DROP_REASONS = {
  unlisted_symbol: "no such symbol",
  off_grid: "price or quantity off the grid",
  off_price_step: "price off the price step",
  off_quantity_step: "quantity off the quantity step",
  self_trade: "would have traded with itself",
  position_overflow: "position too large to hold",
  post_only_market: "post-only and a market order",
  post_only_not_resting: "post-only and not allowed to rest",
  post_only_would_take: "post-only, and it would have taken",
  fill_or_kill_unavailable: "fill-or-kill, the book was too thin",
  fill_or_kill_collared: "fill-or-kill, the collar moved its price",
  no_reference_price: "market order, no reference price",
  not_recorded: "refused by an older build, which stored no reason",
};

// The order terms a `New` message carries, as short tags after the account.
//
// A plain limit order gets no tag at all, and that is the wire read back
// rather than a choice made here: domain.rs writes each of the three term
// fields only when it does not hold its default, so a message with no
// `order_type`, no `time_in_force` and no `post_only` *is* a limit order that
// rests and may take. Nothing shown for the default is what the bytes mean.
//
// The tags are the exchange's own names for the terms, shortened, with the
// whole name in the tooltip. The column is three characters wider than it was
// and no wider than that, so the flow keeps its shape.
const ORDER_TERMS = {
  order_type: {
    Market: ["MKT", "Market order. It takes the price the book shows. The exchange bounds " +
      "how far it may fill from the reference price, and refuses it when there is no " +
      "reference price."],
  },
  time_in_force: {
    ImmediateOrCancel: ["IOC", "Immediate or cancel. The part that does not fill straight away " +
      "is dropped and nothing rests."],
    FillOrKill: ["FOK", "Fill or kill. The whole quantity fills or none of it does. The " +
      "exchange decides that before it touches the book."],
  },
};
function orderTerms(o) {
  const tags = [];
  const kind = ORDER_TERMS.order_type[o.order_type];
  if (kind) tags.push(kind);
  const life = ORDER_TERMS.time_in_force[o.time_in_force];
  if (life) tags.push(life);
  if (o.post_only) {
    tags.push(["PO", "Post only. It must rest. The exchange refuses it rather than let it " +
      "take what is resting in the book."]);
  }
  return tags.map(([tag, why]) => ` <span class="term" title="${why}">${tag}</span>`).join("");
}

function renderAccounts(accounts) {
  const sorted = accounts.slice().sort((x, y) => y.total_pnl - x.total_pnl);
  // Ask the matcher to rebuild the selected account's profit history now and
  // then.
  //
  // One account, and it is the one the panel already names. The heading above
  // this chart reads "POSITIONS #13" and the rows under it are #13's positions.
  // This chart drew six other accounts, chosen as the six bots with the most
  // profit over the whole run, so one panel said two different things.
  //
  // Profit over the whole run was also the wrong way to choose. The feed ran
  // 600 accounts for a while and runs 40 now. Accounts 40 to 599 stopped
  // trading and still hold the highest profit, because they traded through the
  // busiest part of the run. The six lines were six accounts that no longer
  // exist, each one flat for the rest of the width. Following the selection
  // removes the question rather than answering it.
  //
  // GET /pnl answers one `PnlSeries` per account, already summed over that
  // account's symbols, so one account is one line and the page sums nothing.
  const wantPnl = selectedAccount != null
    && (pnlTick++ % PNL_EVERY === 0 || selectedAccount !== pnlAccount);
  if (wantPnl) {
    const asked = selectedAccount;
    pnlAccount = asked;
    get(`/pnl?account=${asked}&points=${PNL_POINTS}`)
      .then((s) => {
        // The reader may have clicked another account while this was out.
        if (asked !== pnlAccount) return;
        // A new account is a new x axis, so the window starts again.
        if (asked !== pnlDrawn) { pnlView = newView(); pnlDrawn = asked; }
        pnlSeries = s;
        drawPnl();
      })
      .catch(() => {});
  }
  // Follow a bot by default, since that is what someone opens this to watch.
  //
  // Picked again while the first full walk is still out. `zeroSum` holds the
  // answer to that walk, so a null there means this list is the fast poll's
  // page and nothing else, the lowest account numbers, which at 600 accounts
  // hold no bot at all. A default chosen from that page alone would follow a
  // generated account and stay on it once the bots arrived.
  if (selectedAccount == null || !accounts.some((a) => a.account === selectedAccount)
      || (zeroSum === null && !userPickedAccount && !isBot(selectedAccount))) {
    const bot = sorted.find((a) => isBot(a.account));
    selectedAccount = bot ? bot.account : sorted.length ? sorted[0].account : null;
  }
  // The one exception: the moment the visitor's own first fill lands, follow
  // them instead. Once only, so a later click on another account sticks.
  if (!sawMyAccount && accounts.some((a) => isMe(a.account))) {
    sawMyAccount = true;
    selectedAccount = identity.account;
  }
  const botRule = document.getElementById("bot-rule");
  botRule.textContent =
    botSet
      ? `bot account numbers: ${[...botSet].join(", ")}`
      : `bot numbers ${BOT_ID_FLOOR} to ${RESERVED_ACCOUNTS - 1n}, visitors above`;
  // The Accounts header cuts this with an ellipsis when the box is narrow, so
  // the whole rule has to be readable from somewhere.
  botRule.title = botSet
    ? botRule.textContent
    : `A bot has an account number from ${BOT_ID_FLOOR} to ${RESERVED_ACCOUNTS - 1n}. ` +
      `A higher number is a visitor who came through this page.`;
  document.getElementById("accounts").innerHTML = sorted.map((a) =>
    `<div class="row acct-row${a.account === selectedAccount ? " sel" : ""}" data-acct="${a.account}">` +
    `<span class="acct-id">#${a.account}${
      isMe(a.account) ? ' <span class="badge">you</span>' : isBot(a.account) ? ' <span class="badge">bot</span>' : ""
    }</span>` +
    `<span class="num ${sign(a.realized_pnl)}">${fmtM(a.realized_pnl)}</span>` +
    `<span class="num ${sign(a.unrealized_pnl)}">${fmtM(a.unrealized_pnl)}</span>` +
    `<span class="num ${sign(a.total_pnl)}"><b>${fmtM(a.total_pnl)}</b></span>` +
    `<span class="num dim">${fmtK(openNotional(a))}</span></div>`
  ).join("") || `<div class="row"><span class="dim">Nobody traded yet.</span></div>`;
  for (const el of document.querySelectorAll(".acct-row")) {
    el.onclick = () => {
      selectedAccount = Number(el.dataset.acct);
      userPickedAccount = true;
      refresh();
    };
  }
  // The columns are sized from what is in them, and what is in them just
  // changed: a bot that crosses +100000.00 needs a character more than it did
  // on the tick before.
  fitTable("accounts");
}

// Profit here is exactly zero-sum: every fill moves cash from one account to
// another and nothing is created, so the net must read 0.00. It is shown
// because it is a live check on the engine, and because it says plainly where
// a bot's money comes from. A non-zero net is a bug, not a market move.
//
// This is a check and not a display, which decides two things about it.
//
// It adds up the accounts it was served and never reads a total the exchange
// states. A dishonest exchange that adds to every realized profit it reports
// (services/src/dishonest.rs, `Lie::Positions`) is caught here and nowhere
// else: `services/tests/adversarial.rs` records that --verify, --audit and
// --audit-url all miss it, because no record moves and there is nothing for
// them to re-derive. An exchange asked for the total would state a clean one
// and this line would read 0.00 while the accounts under it did not add up.
//
// It reads every account, not one page. A sum over some of the accounts is
// not a sum, and every account is what makes 0.00 the right answer. That is
// why it runs on its own 30 second timer: reading 600 accounts twice a second
// is 800 KB a second, and reading them every 30 seconds is 13 KB a second.
function renderZeroSum() {
  const el = document.getElementById("zero-sum");
  if (zeroSum === null) {
    el.textContent = "adding up every account…";
    return;
  }
  const ago = Math.max(0, Math.round((Date.now() - zeroSum.at) / 1000));
  const net = zeroSum.bots + zeroSum.crowd;
  // One request is one moment, and over one moment the net is exact. More
  // than one request is more than one moment: a fill landing between two of
  // them moves money from an account already read to an account not read yet,
  // and the net picks that difference up. The line says which of the two it
  // is, so a reader does not take a paging artefact for a broken engine.
  const exact = zeroSum.pages === 1;
  // The net first, and the two halves after it. The heading cuts this line
  // with an ellipsis when the window is narrow, and the net is the part that
  // is a check: a reader who can see one number has to see that one.
  el.innerHTML =
    `Net <b class="${!exact || Math.abs(net) < ZERO ? "" : "neg"}">${fmtM(net)}</b>` +
    `<span class="dim" title="${
      exact
        ? "Every account, read in one request, so this net is exact. It must be 0.00."
        : `Every account, read in ${zeroSum.pages} requests. The market moved between ` +
          "them, so the net is close to 0.00 rather than exactly 0.00."
    }"> ${exact ? "" : `over ${zeroSum.pages} reads, `}${ago}s</span>` +
    ` · Bots <b class="${sign(zeroSum.bots)}">${fmtM(zeroSum.bots)}</b>` +
    ` · Others <b class="${sign(zeroSum.crowd)}">${fmtM(zeroSum.crowd)}</b>`;
}

// Reads every account, one page at a time, and adds up what it was served.
//
// The cursor is the account number: a page comes back ordered by it, and the
// next request asks for the accounts above the last one seen. A page shorter
// than the number asked for is the end, which is how /claims and /trades-since
// are read too.
//
// The accounts it reads also go into the table. They are the only answer the
// page ever gets about an account outside the fast poll's first page.
let walking = false;
async function walkPositions() {
  // One walk at a time. A slow exchange must not stack walks up behind each
  // other until the browser is asking for every account continuously, which is
  // the traffic this timer exists to avoid.
  if (walking) return;
  walking = true;
  try {
    const all = [];
    let since = null;
    let pages = 0;
    let complete = false;
    // A ceiling as well as a cursor. 20 pages is 20,000 accounts; an exchange
    // holding more than that has outgrown a table a person reads, and a walk
    // with no ceiling would hold the browser open against one that answers the
    // same page forever.
    while (pages < 20) {
      const page = await get(
        `/positions?n=${POSITIONS_MAX_PAGE}&totals=true` +
          (since === null ? "" : `&since=${since}`));
      pages++;
      all.push(...page);
      if (page.length < POSITIONS_MAX_PAGE) { complete = true; break; }
      since = page[page.length - 1].account;
    }
    for (const a of all) accountsById.set(a.account, a);
    // A walk that hit the ceiling saw some of the accounts, and some of the
    // accounts do not add up to zero. The last complete answer stays on screen
    // rather than being replaced by a number that means nothing.
    if (!complete) return;
    let bots = 0, crowd = 0;
    for (const a of all) {
      if (isBot(a.account)) bots += a.total_pnl; else crowd += a.total_pnl;
    }
    zeroSum = { bots, crowd, pages, at: Date.now() };
  } catch {
    // Left alone on a failed read. The line keeps its last answer and the age
    // beside it counts up, which says "this was not checked recently" without
    // claiming a fault the page did not see.
  } finally {
    walking = false;
  }
}

function renderPositions(a) {
  document.getElementById("sel-label").textContent = a ? `#${a.account}` : "";
  const el = document.getElementById("positions");
  if (!a) {
    el.innerHTML = `<div class="row"><span class="dim">-</span></div>`;
    fitTable("positions");
    return;
  }
  // `a` is whichever row `accountsById` holds for this account. The two accounts
  // this panel can be pointed at are read whole every tick, so it has rows. The
  // rest of the map is read with `totals=1` and has none, and this draws an
  // empty table rather than throwing if it is ever handed one of those.
  const held = (a.positions || []).filter((p) => p.net_quantity !== 0 || p.realized_pnl !== 0);
  el.innerHTML = held.map((p) =>
    `<div class="row">` +
    `<span>${p.symbol}</span>` +
    // Deliberately NOT coloured by sign. A negative quantity is a short, which
    // is a direction and not a loss, but red sits in the same row as the two
    // P&L columns that do mean loss, and it reads as one. The sign carries the
    // direction; only money gets the money colours.
    `<span class="num" title="${p.net_quantity < 0 ? "short position" : p.net_quantity > 0 ? "long position" : "no position"}">` +
    `${p.net_quantity > 0 ? "+" : p.net_quantity < 0 ? "−" : ""}${Math.abs(p.net_quantity).toFixed(1)}</span>` +
    `<span class="num">${fmtP(p.avg_entry_price)}</span>` +
    `<span class="num">${fmtP(p.last_trade_price)}</span>` +
    // Kept apart deliberately. Unrealized is the quantity on this row valued at
    // the mark; realized is profit from quantity already closed and has nothing
    // to do with what is held now. Added together under one "P&L" heading they
    // read as the position losing money when it is doing nothing of the kind.
    `<span class="num ${sign(p.unrealized_pnl)}">${fmtM(p.unrealized_pnl)}</span>` +
    `<span class="num ${sign(p.realized_pnl)}">${fmtM(p.realized_pnl)}</span></div>`
  ).join("") || `<div class="row"><span class="dim">This account holds no position.</span></div>`;
  fitTable("positions");
  drawPnl();   // the selected line is drawn thicker
}

function renderAccountTrades(trades) {
  const acct = selectedAccount;
  document.getElementById("trades-label").textContent =
    acct == null ? "" : `#${acct}, last ${trades.length}`;
  document.getElementById("acct-trades").innerHTML = trades.slice().reverse().map((t) => {
    // A trade names the taker's side, so the maker's side is the other one.
    // An account can be both: this engine allows an account to match itself.
    const self = t.maker_account === t.taker_account;
    const taker = t.taker_account === acct;
    const side = self ? "self" : taker ? t.taker_side : t.taker_side === "Buy" ? "Sell" : "Buy";
    const role = self ? "self" : taker ? "taker" : "maker";
    const other = self ? "" : ` #${taker ? t.maker_account : t.taker_account}`;
    const cls = side === "Buy" ? "pos" : side === "Sell" ? "neg" : "dim";
    return `<div class="row">` +
      `<span class="dim">${fmtT(t.timestamp)}</span>` +
      `<span>${t.symbol}</span>` +
      `<span class="${cls}">${side}</span>` +
      `<span class="num">${fmtP(t.price)}</span>` +
      `<span class="num">${fmtQ(t.quantity)}</span>` +
      `<span class="num dim">${role}${other}</span></div>`;
  }).join("") || `<div class="row"><span class="dim">This account has no trades yet.</span></div>`;
  fitTable("acct-trades");
}

// Profit over the whole run, not just since this page loaded. The matcher reads
// this account's fills through its account index and values each sampled point
// at that moment's market price. The last point equals /positions now.
//
// One line, for the account the Positions panel above is showing.
const PNL_COLOR = "#f0b90b";

function drawPnl() {
  const canvas = document.getElementById("pnl-chart");
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  ctx.font = "10px monospace";

  const series = pnlSeries.find((s) => s.points.length > 1);
  const legend = document.getElementById("pnl-legend");
  pnlPoints = series ? series.points : [];
  if (!series) {
    legend.innerHTML = "";
    ctx.fillStyle = "#848e9c";
    ctx.fillText("No history yet.", 4, 14);
    return;
  }

  const plotW = Math.max(1, w - AXIS_W), plotH = Math.max(1, h - 12);

  // The same window rule the candle chart uses, over the same helpers. The
  // profit line had the same fault and it was worse: the series starts at
  // trade 1 of the run and an account that began trading late is flat at zero
  // across most of the width. A window over the newest part of the run drops
  // that flat stretch, and scaling to the window alone gives what is left the
  // full height.
  //
  // A pan costs no requests. The window is a slice of the points already
  // loaded, and the request below is unchanged by any pan or zoom. Panning is
  // free; only the 4-second refresh reads the account history again.
  const { start, bars } = windowOf(pnlView, series.points, pnlAt, plotW, pnlLimits);
  const view = series.points.slice(start, start + bars);

  let t0 = Infinity, t1 = -Infinity, lo = Infinity, hi = -Infinity;
  for (const p of view) {
    if (p.timestamp < t0) t0 = p.timestamp;
    if (p.timestamp > t1) t1 = p.timestamp;
    if (p.total < lo) lo = p.total;
    if (p.total > hi) hi = p.total;
  }
  if (t1 === t0) t1 = t0 + 1;
  if (lo === hi) { lo -= 1; hi += 1; }
  const pad = (hi - lo) * 0.08;
  lo -= pad; hi += pad;

  const X = (t) => ((t - t0) / (t1 - t0)) * plotW;
  const Y = (v) => plotH * (1 - (v - lo) / (hi - lo));

  // Break-even, drawn only when the window actually crosses it: a stretch where
  // the account never went negative should not be given a baseline it never
  // touched.
  if (lo < 0 && hi > 0) {
    ctx.strokeStyle = "#2b3139";
    ctx.setLineDash([2, 3]);
    ctx.beginPath(); ctx.moveTo(0, Y(0)); ctx.lineTo(plotW, Y(0)); ctx.stroke();
    ctx.setLineDash([]);
  }
  ctx.fillStyle = "#848e9c";
  ctx.fillText(fmtM(hi), plotW + 4, 9);
  ctx.fillText(fmtM(lo), plotW + 4, plotH - 1);
  ctx.fillText(fmtT(t0), 2, h - 2);
  const end = fmtT(t1);
  ctx.fillText(end, Math.max(0, plotW - ctx.measureText(end).width - 2), h - 2);

  ctx.strokeStyle = PNL_COLOR;
  ctx.lineWidth = 2;
  ctx.beginPath();
  view.forEach((p, j) => {
    const x = X(p.timestamp), y = Y(p.total);
    j ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  ctx.lineWidth = 1;

  // The legend says what the window shows, not what the run shows. The last
  // point of the window is the account's profit at the right edge, so a reader
  // who panned back reads the number that belongs to the picture in front of
  // them, and the whole-run number stays in the Accounts table.
  const last = view[view.length - 1].total;
  const low = Math.min(...view.map((p) => p.total));
  const all = series.points.length;
  legend.innerHTML =
    `<span title="The worst point in this window was ${fmtM(low)}. ` +
    `The window shows ${view.length} of ${all} points of the run.">` +
    `<i class="pnl-key"></i>` +
    `#${series.account} <b class="${sign(last)}">${fmtM(last)}</b></span>`;
}

document.getElementById("traders-toggle").onclick = (e) => {
  const open = document.getElementById("traders").classList.toggle("collapsed");
  e.target.textContent = open ? "show" : "hide";
  // Nothing to drag while the panel is a header bar, and a handle that resized
  // something invisible would come back as a surprise on the next click.
  document.getElementById("gut-traders").hidden = open;
  drawChart(lastCandles);   // both charts' boxes just changed size
  drawPnl();
};

function renderIntervals() {
  const el = document.getElementById("intervals");
  el.innerHTML = "";
  for (const [sec, label] of INTERVALS) {
    const b = document.createElement("button");
    b.className = "iv" + (sec === interval ? " active" : "");
    b.textContent = label;
    // A new interval is a new x axis, so the window starts again and the
    // lookback goes back to the first request. Keeping the old window would
    // put the reader at a moment that no longer has a candle at that index,
    // and keeping a 1000-candle lookback would make every interval click slow.
    b.onclick = () => {
      if (sec === interval) return;
      interval = sec;
      resetCandleView();
      refreshCandleChart().catch(() => {});
      refresh();
    };
    el.appendChild(b);
  }
}

// How narrow and how wide the candle window may be, for one plot width.
//
// The floor comes from `MAX_SLOT_PX`: fewer candles than `plotW / 24` would
// draw candles wider than 24 px. The ceiling comes from `MIN_SLOT_PX`: more
// candles than `plotW / 3` would draw them closer than 3 px, and they would
// merge into one block. Neither bound can ask for more candles than are
// loaded.
//
// `open` is how many candles the window shows before a reader touches it. It is
// a fixed count and not a share of the plot width, for the two reasons written
// at `OPEN_BARS`. `windowOf` still clamps it to `hi`, so a window narrower than
// 132 * 3 px opens on fewer.
const candleLimits = (plotW, n) => ({
  lo: Math.min(Math.max(2, Math.ceil(plotW / MAX_SLOT_PX)), n),
  hi: Math.min(Math.max(3, Math.floor(plotW / MIN_SLOT_PX)), n),
  open: OPEN_BARS,
});

// The profit chart is a line and not a row of candles, so pixels per point do
// not bound it the same way. Its floor is 8 points, which is the fewest that
// still draw as a line a reader can follow rather than one straight segment.
// Its ceiling is everything loaded.
const PNL_MIN_POINTS = 8;
// The profit chart opens at 2 px a point. A line needs about that to show its
// shape rather than a row of steps.
//
// This is what makes the opening window shorter than the run. Measured in this
// page: the profit canvas is 439 px at a 1440 px window and 791 px at 2560, and
// the right axis takes 52 px, so the plot is 387 px and 739 px. At 2 px a point
// the window opens on 194 points and 370 points, out of the 900 that
// `PNL_POINTS` asks for. So the chart opens on the newest fifth to the newest
// 40% of the run, and not on all of it.
const PNL_OPEN_PX = 2;
const pnlLimits = (plotW, n) => ({
  lo: Math.min(PNL_MIN_POINTS, n),
  hi: n,
  open: Math.round(plotW / PNL_OPEN_PX),
});

// Where the window starts, and how wide it is, for one draw.
//
// `points` is in time order, oldest first. `at(p)` answers the timestamp of one
// point. `limits` is `candleLimits` or `pnlLimits`. Returns `{ start, bars }`
// as indexes into `points`.
//
// The window is clamped to what is loaded on every draw. That is what keeps a
// pan honest while the array grows under it: a reader who panned to the oldest
// loaded candle stays on it. The window never starts before index 0, so the
// chart never draws a stretch that holds no candles.
function windowOf(view, points, at, plotW, limits) {
  const n = points.length;
  const { lo, hi, open } = limits(plotW, n);
  const wanted = view.bars || open;
  const bars = Math.max(2, Math.min(Math.max(wanted, lo), hi));
  if (view.left === null) return { start: n - bars, bars };
  // The first point at or after the remembered moment. A plain scan: these
  // arrays hold 900 points at the most, so a binary search would save about
  // 890 comparisons once a frame and buy a reader nothing.
  let start = 0;
  while (start < n && at(points[start]) < view.left) start++;
  return { start: Math.max(0, Math.min(start, n - bars)), bars };
}

// Where one point sits across the plot, and which point sits at one x.
//
// Both charts draw their window against the right edge, because `rightOffset`
// in `lightweight-charts` is 0 by default: TradingView leaves no empty space
// past the newest bar unless it is asked to.
const slotOf = (plotW, bars) => Math.min(plotW / bars, MAX_SLOT_PX);
const originOf = (plotW, bars) => plotW - bars * slotOf(plotW, bars);

// Moves the window by `delta` points. Positive is towards the newest point.
//
// Setting `left` back to null when the window reaches the newest point is what
// makes a pan to the right edge start following the market again. It matches
// `shiftVisibleRangeOnNewBar`, which is `true` by default in
// `lightweight-charts` and, by its own note, "only applies when the last bar is
// visible".
function panWindow(view, points, at, plotW, limits, delta) {
  const n = points.length;
  if (!n) return;
  const { start, bars } = windowOf(view, points, at, plotW, limits);
  const moved = Math.max(0, Math.min(start + delta, n - bars));
  view.bars = bars;
  view.left = moved >= n - bars ? null : at(points[moved]);
}

// Zooms the window around the point under `cursorX`.
//
// The point the cursor is on does not move. That is what TradingView does:
// `zoomTime(scrollPosition, zoomScale)` in its chart widget passes the cursor's
// x, and its `zoom()` holds the bar at that x in place. `scale` above 1 makes
// the window wider, which shows more points and is zooming out.
function zoomWindow(view, points, at, plotW, limits, scale, cursorX) {
  const n = points.length;
  if (!n) return;
  const { start, bars } = windowOf(view, points, at, plotW, limits);
  // Which point, as a fraction, the cursor is over now.
  const slot = slotOf(plotW, bars);
  const held = start + (cursorX - originOf(plotW, bars)) / slot;
  const { lo, hi } = limits(plotW, n);
  const wide = Math.max(2, Math.min(Math.max(Math.round(bars * scale), lo), hi));
  // A 10% step on a narrow window can round back to the same number, which
  // would make the wheel do nothing. Move by one point instead.
  const next = wide === bars
    ? Math.max(2, Math.min(Math.max(bars + (scale > 1 ? 1 : -1), lo), hi))
    : wide;
  // Put the held point back under the cursor.
  const moved = held - (cursorX - originOf(plotW, next)) / slotOf(plotW, next);
  const at0 = Math.max(0, Math.min(Math.round(moved), n - next));
  view.bars = next;
  view.left = at0 >= n - next ? null : at(points[at0]);
}

// The right axis of both charts, in pixels. The plot is the canvas without it.
const AXIS_W = 52;
// Where each chart reads a timestamp from one of its points.
const candleAt = (c) => c.start;
const pnlAt = (p) => p.timestamp;

// Puts the window controls on one canvas: wheel, drag, keys, and double-click.
//
// `chart` names the four things that differ between the two charts: which view
// object to move, which points are drawn, how to read a timestamp out of one
// point, and which limits bound the window. Everything else is the same for
// both, so it is written once.
//
// What each control does was taken from `lightweight-charts`, which is
// TradingView's own chart library, and is marked where it was:
//
// - wheel up or down zooms, one step being 10% (its `zoom()`), around the point
//   under the cursor (its `zoomTime(event.clientX - left, …)`);
// - wheel sideways pans (its `scrollChart(deltaX * -80)`);
// - holding the button and moving pans (its `handleScroll.pressedMouseMove`,
//   `true` by default);
// - no modifier key changes anything, because its wheel handler reads none.
//   Shift and wheel still pans, but only because some browsers turn a shift and
//   a vertical wheel into a sideways one before the page sees it.
//
// Keys are this page's own addition. `lightweight-charts` binds no keys, and
// every other control on this page can be reached from the keyboard, so the
// chart should not be the one that cannot.
function attachChartInput(canvasId, chart) {
  const canvas = document.getElementById(canvasId);
  const plotW = () => Math.max(1, canvas.clientWidth - AXIS_W);
  const bars = () => windowOf(chart.view(), chart.points(), chart.at, plotW(), chart.limits).bars;

  // One redraw a frame, however many events arrive. A drag fires a pointermove
  // for every pixel on a fast mouse, and drawing 158 candles 300 times a second
  // would waste the work the browser needs to show one of them.
  let frame = 0;
  const redraw = () => {
    if (frame) return;
    frame = requestAnimationFrame(() => { frame = 0; chart.redraw(); });
  };
  const pan = (delta) => {
    panWindow(chart.view(), chart.points(), chart.at, plotW(), chart.limits, delta);
    redraw();
  };
  const zoom = (scale, x) => {
    zoomWindow(chart.view(), chart.points(), chart.at, plotW(), chart.limits, scale, x);
    redraw();
  };
  // The centre of the plot, for the controls that have no cursor: the buttons
  // and the keys.
  const middle = () => plotW() / 2;

  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
      // Sideways wheel pans. The pixels are turned into points by the width one
      // point is drawn at, so a trackpad swipe moves the same distance on the
      // screen whatever the zoom.
      pan(Math.round(e.deltaX / slotOf(plotW(), bars())) || Math.sign(e.deltaX));
      return;
    }
    if (!e.deltaY) return;
    // Down the page shows more points, which is zooming out.
    zoom(e.deltaY > 0 ? 1 + ZOOM_STEP : 1 - ZOOM_STEP,
      e.clientX - canvas.getBoundingClientRect().left);
  }, { passive: false });

  // Holding the button and moving pans. The remainder is kept between events,
  // so a slow drag over a wide zoom still moves: without it every move of less
  // than one point would round to zero and the chart would stay still.
  let dragFrom = null, carry = 0;
  canvas.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    dragFrom = e.clientX;
    carry = 0;
    canvas.setPointerCapture(e.pointerId);
    canvas.style.cursor = "grabbing";
  });
  canvas.addEventListener("pointermove", (e) => {
    if (dragFrom === null) return;
    const points = (dragFrom - e.clientX) / slotOf(plotW(), bars()) + carry;
    const whole = Math.trunc(points);
    carry = points - whole;
    dragFrom = e.clientX;
    if (whole) pan(whole);
  });
  const drop = (e) => {
    if (dragFrom === null) return;
    dragFrom = null;
    canvas.style.cursor = "";
    if (canvas.hasPointerCapture(e.pointerId)) canvas.releasePointerCapture(e.pointerId);
  };
  canvas.addEventListener("pointerup", drop);
  canvas.addEventListener("pointercancel", drop);

  // Double-click puts the view back, the way double-clicking an axis in
  // `lightweight-charts` resets that axis.
  canvas.addEventListener("dblclick", (e) => { e.preventDefault(); chart.reset(); redraw(); });

  canvas.addEventListener("keydown", (e) => {
    // A page of the window, for the keys that move a page. 10 points otherwise,
    // which is a readable step at any zoom.
    const page = Math.max(1, Math.round(bars() * 0.8));
    const step = e.shiftKey ? page : 10;
    const keys = {
      ArrowLeft: () => pan(-step),
      ArrowRight: () => pan(step),
      PageUp: () => pan(-page),
      PageDown: () => pan(page),
      Home: () => { chart.view().left = 0; redraw(); },   // clamped to the oldest loaded
      End: () => { chart.view().left = null; redraw(); },
      "+": () => zoom(1 - ZOOM_STEP, middle()),
      "=": () => zoom(1 - ZOOM_STEP, middle()),
      "-": () => zoom(1 + ZOOM_STEP, middle()),
      _: () => zoom(1 + ZOOM_STEP, middle()),
      "0": () => { chart.reset(); redraw(); },
    };
    const run = keys[e.key];
    if (!run) return;
    e.preventDefault();
    run();
  });

  // The buttons in the panel heading, for a reader on a trackpad that reports
  // no wheel and for a reader who would rather press a button.
  const button = (id, run) => {
    const el = document.getElementById(id);
    if (el) el.onclick = () => { run(); redraw(); };
  };
  button(canvasId + "-in", () => zoomWindow(
    chart.view(), chart.points(), chart.at, plotW(), chart.limits, 1 - ZOOM_STEP, middle()));
  button(canvasId + "-out", () => zoomWindow(
    chart.view(), chart.points(), chart.at, plotW(), chart.limits, 1 + ZOOM_STEP, middle()));
  button(canvasId + "-now", () => { chart.view().left = null; });
  button(canvasId + "-reset", () => chart.reset());
}

// Puts the candle chart back to its first state: the opening width, the newest
// candle, and the first lookback. Used when the reader changes symbol or
// interval, and by the chart's own reset.
function resetCandleView() {
  abortCandleRequests();
  candleView = newView();
  candleLookback = FIRST_LOOKBACK;
  // A response already in flight belongs to the axis that was just replaced.
  // Invalidate it immediately, before the new refresh has reached /candles,
  // and do not label the old rows as if they used the newly selected interval.
  candleRequestSerial += 1;
  const cached = cachedCandleWindow(currentCandleKey());
  candleError = null;
  candleLoading = cached === null;
  drawChart(cached === null ? [] : cached.rows);
}

// The two charts, named for `attachChartInput`. Called at the end of the
// script, once both draw functions and both canvases exist.
function attachCharts() {
  attachChartInput("chart", {
    view: () => candleView,
    points: () => chartPoints,
    at: candleAt,
    limits: candleLimits,
    redraw: () => drawChart(lastCandles),
    // The candle reset puts the window back to the opening one and leaves the
    // loaded candles alone. Dropping the lookback as well would throw away
    // candles the reader has already waited for.
    reset: () => { candleView = newView(); },
  });
  attachChartInput("pnl-chart", {
    view: () => pnlView,
    points: () => pnlPoints,
    at: pnlAt,
    limits: pnlLimits,
    redraw: drawPnl,
    reset: () => { pnlView = newView(); },
  });
}

function drawChart(candles) {
  lastCandles = candles;
  const canvas = document.getElementById("chart");
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  ctx.font = "10px monospace";

  // One step in this array is always one interval, so a pan of 10 candles at
  // 15m is always 150 minutes. The matcher sends the buckets that hold no trade
  // as well, so the array arrives with no hole in it. The page used to insert
  // those buckets itself, in a function named `fillGaps`. It asked the matcher
  // for 400 candles and drew 3716 of them, and every window number below counts
  // candles, so every one of them was wrong by that ratio.
  chartPoints = candles;
  if (!candles.length) {
    ctx.fillStyle = "#848e9c";
    ctx.fillText(candleLoading ? "Loading candles..." : (candleError || "No trades yet."), 12, 20);
    return;
  }

  const timeH = 14, volH = Math.floor(h * 0.15);
  // Never below 1. The panel is 0 px wide while the Anchors view is open and
  // at window widths the grid cannot fit, and a negative plot width would make
  // the window arithmetic below ask for a negative number of candles.
  const plotW = Math.max(1, w - AXIS_W), plotH = h - timeH - volH;

  const { start, bars } = windowOf(candleView, candles, candleAt, plotW, candleLimits);
  const view = candles.slice(start, start + bars);

  // The price scale covers the window and nothing else. This is the whole fix
  // for the flat 15m picture: the 1520 candle only sets the scale while it is
  // on screen, and the candles either side of it get the full height as soon as
  // the reader scrolls past it.
  //
  // TradingView does the same. Its `lightweight-charts` price scale has
  // `autoScale: true` by default and it fits the visible range, not the series.
  let min = Infinity, max = -Infinity, maxVol = 0;
  for (const c of view) {
    min = Math.min(min, c.low);
    max = Math.max(max, c.high);
    maxVol = Math.max(maxVol, c.volume);
  }
  if (min === max) { min -= 0.01; max += 0.01; }
  const pad = (max - min) * 0.05;
  min -= pad; max += pad;
  const y = (p) => plotH * (1 - (p - min) / (max - min));

  // Price gridlines and labels on the right axis.
  ctx.strokeStyle = "#2b3139";
  ctx.fillStyle = "#848e9c";
  for (let i = 0; i <= 4; i++) {
    const p = min + ((max - min) * i) / 4;
    const yy = y(p);
    ctx.beginPath(); ctx.moveTo(0, yy); ctx.lineTo(plotW, yy); ctx.stroke();
    ctx.fillText(fmtP(p), plotW + 4, yy + 3);
  }

  const n = view.length;
  // The window fills the width now. It cannot be wider than `MAX_SLOT_PX`,
  // because `minBars` stops the reader zooming in past that.
  const slot = Math.min(plotW / n, MAX_SLOT_PX);
  const x0 = plotW - n * slot;
  const bodyW = Math.max(1, slot * 0.7);
  for (let i = 0; i < n; i++) {
    const c = view[i];
    const x = x0 + i * slot + slot / 2;
    const up = c.close >= c.open;
    const color = up ? "#0ecb81" : "#f6465d";
    // Wick.
    ctx.strokeStyle = color;
    ctx.beginPath(); ctx.moveTo(x, y(c.high)); ctx.lineTo(x, y(c.low)); ctx.stroke();
    // Body (flat candles get a 1px line).
    const top = y(Math.max(c.open, c.close)), bot = y(Math.min(c.open, c.close));
    ctx.fillStyle = color;
    ctx.fillRect(x - bodyW / 2, top, bodyW, Math.max(1, bot - top));
    // Volume bar. Scaled over the window too, and drawn at the same x as the
    // candle above it, so the two keep telling one story.
    if (maxVol > 0 && c.volume > 0) {
      const vh = (c.volume / maxVol) * volH;
      ctx.globalAlpha = 0.5;
      ctx.fillRect(x - bodyW / 2, h - timeH - vh, bodyW, vh);
      ctx.globalAlpha = 1;
    }
  }

  // Mark this browser's newest fill only when the server candle for the same
  // bucket contains its full execution-price range. Until then there is no
  // outline; the marker never expands the axis or invents a candle.
  if (lastOwnFill && lastOwnFill.symbol === symbol) {
    const bucketMs = interval * 1000;
    const starts = new Set(lastOwnFill.timestamps.map((at) => at - at % bucketMs));
    const low = lastOwnFill.minCents / PRICE_SCALE;
    const high = lastOwnFill.maxCents / PRICE_SCALE;
    for (let i = 0; i < n; i++) {
      const c = view[i];
      if (!starts.has(c.start) || c.low > low || c.high < high) continue;
      const x = x0 + i * slot + slot / 2;
      const top = Math.max(1, y(high) - 4);
      const bottom = Math.min(plotH - 1, y(low) + 4);
      const markerW = Math.max(4, slot * 0.9);
      ctx.save();
      ctx.strokeStyle = "#f0b90b";
      ctx.fillStyle = "#f0b90b";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 2]);
      ctx.strokeRect(x - markerW / 2, top, markerW, Math.max(8, bottom - top));
      ctx.setLineDash([]);
      ctx.fillText("your fill", Math.max(2, Math.min(plotW - 54, x - 24)), Math.max(10, top - 3));
      ctx.restore();
    }
  }

  // Time labels along the bottom.
  ctx.fillStyle = "#848e9c";
  const every = Math.max(1, Math.ceil(n / 6));
  for (let i = 0; i < n; i += every) {
    ctx.fillText(fmtT(view[i].start), x0 + i * slot + 2, h - 2);
  }

  // The left edge of the loaded data.
  //
  // The load starts while 10 candles of slack are still left, not once the
  // reader has already hit the front. That is what `lightweight-charts` does in
  // its own infinite-history example: it asks for more when
  // `logicalRange.from < 10`. Asking early means the answer usually lands
  // before the reader arrives, so most pans never see the label at all.
  if (start <= LOAD_SLACK_BARS && !loadingOlder && candleLookback < MAX_LOOKBACK) {
    loadOlderCandles();
  }
  // The label only appears once the window really is against the front, so it
  // says something true: nothing older is drawn here.
  if (start === 0) {
    ctx.fillStyle = "#848e9c";
    ctx.fillText(
      loadingOlder ? "loading older candles…"
        : candleLookback >= MAX_LOOKBACK ? "oldest candle loaded"
        : "start of loaded candles", 4, 10);
  }
}

// The oldest loaded candle is on screen, so ask for more.
//
// The matcher's GET /candles answers the newest `n` buckets and takes no "older
// than" cursor, so there is no way to ask for a page below what is loaded. The
// page asks for a bigger `n` instead and keeps the answer. 200 becomes 600
// becomes 1000, and 1000 is `MAX_LOOKBACK`.
//
// While the request is out the chart keeps drawing what it already has, and the
// left edge reads "loading older candles…". Nothing moves and nothing blanks,
// because the window is anchored to a timestamp: when the bigger answer lands
// with 300 more candles in front, the same moment is still on screen and the
// reader gets more room to the left of it.
async function loadOlderCandles() {
  if (loadingOlder || candleLookback >= MAX_LOOKBACK || !symbol) return;
  // The last answer held fewer buckets than it was asked for, so the matcher
  // walked back to the first trade of the run and there is nothing older to
  // get. Asking again would send two more requests and answer the same.
  //
  // This test is exact now that `n` counts buckets. The matcher answers `n`
  // buckets whenever a trade sits below the range, and fewer only when the run
  // starts inside the range. It used to count the buckets that hold a trade, so
  // a short answer meant the same thing but the page then drew a different
  // number again.
  if (lastCandles.length < candleLookback) return;
  loadingOlder = true;
  const want = Math.min(candleLookback + LOOKBACK_STEP, MAX_LOOKBACK);
  const asked = symbol, askedInterval = interval;
  try {
    const older = await getCandles(
      `/candles?symbol=${encodeURIComponent(asked)}&interval=${askedInterval}&n=${want}`);
    // The reader may have changed symbol or interval while this was out. That
    // answer describes a chart nobody is looking at, so it is dropped.
    if (asked === symbol && askedInterval === interval) {
      candleLookback = want;
      rememberCandleWindow({ key: currentCandleKey(), rows: older });
      drawChart(older);
    }
  } catch (e) {
    if (e && e.name !== "AbortError") {
      candleError = "Candles unavailable; retrying...";
      drawChart(lastCandles);
    }
  } finally {
    loadingOlder = false;
  }
}

// ===========================================================================
// The live view
//
// The page reads the snapshot endpoints first and then follows `GET /stream`.
// That order is the point. A stream tells you what changed, and a reader that
// joined late, or missed a batch, cannot tell what changed from what it never
// had. So the snapshots are what the page is built from, and the stream is what
// keeps three of its panels current between them.
//
// While a stream is open the tick stops asking for the book, the trades and the
// messages: 15 KB of every tick that the stream sends as a few hundred bytes of
// what is new. Everything else is still asked for, because everything else is
// either small or slow-moving.
//
// The stream is never the only path. If it never opens, if it drops, if a proxy
// closes it, the tick asks for all three again and the page is exactly what it
// was before any of this existed.
// ===========================================================================

/// The open stream, or null.
let live = null;
/// The last cursor the stream delivered. The strip's own numbers come from
/// `/market`, so this is not drawn; it is what says whether a batch was missed.
let liveCursor = 0;
/// What the stream adds to, seeded by the tick's own answers so that a stream
/// opening mid-session starts from what the page already shows.
let liveTrades = [];
let liveFlow = [];
let liveBook = null;

/// How many rows the two lists keep. The tick asks `/trades` and `/messages`
/// for 40, and the panels show fewer than that.
const LIVE_ROWS = 40;

const streaming = () => live !== null && live.readyState === EventSource.OPEN;

function openStream() {
  if (live) {
    live.close();
    live = null;
  }
  if (!symbol || typeof EventSource === "undefined") return;
  // The lists start again with the symbol. A stream for MERKLE-USDC must not
  // add to a list of ETH-USDC trades.
  liveTrades = [];
  liveFlow = [];
  liveBook = null;
  const opened = new EventSource(`/stream?symbol=${encodeURIComponent(symbol)}`);
  opened.addEventListener("tick", (event) => {
    // A message this page cannot read is a page older than the exchange, which
    // the strip says in its own words. It must not stop the stream.
    try {
      applyTick(JSON.parse(event.data));
    } catch (e) {
      // The next batch redraws from the same three panels.
    }
  });
  // The reader fell behind by more batches than the exchange holds. The next
  // tick reads the three snapshots again, because a gap cannot be drawn.
  opened.addEventListener("behind", () => {
    liveBook = null;
    liveTrades = [];
    liveFlow = [];
  });
  // `EventSource` reconnects by itself, and while it is not OPEN the tick asks
  // for all three again. So there is nothing to do here but let it.
  opened.onerror = () => {};
  live = opened;
}

/// The streamed book, cut to what this panel has room for.
///
/// A stream is written once for every reader, so it carries `STREAM_DEPTH`
/// levels a side and not the number this panel fits. `fitBook` measures that
/// number into `depth` twice a second; drawing all 50 would put 100 rows in a
/// panel with room for 30 and let the browser clip the rest.
const bookToFit = (book) => ({
  symbol: book.symbol,
  bids: book.bids.slice(0, depth),
  asks: book.asks.slice(0, depth),
});

function applyTick(tick) {
  liveCursor = tick.cursor;
  if (tick.book) {
    liveBook = tick.book;
    // `lastMarket` and not the tick: the last trade and the spread on that line
    // come from `/market`, which the tick still reads.
    if (lastMarket) renderBook(bookToFit(liveBook), lastMarket);
  }
  if (tick.trades && tick.trades.length) {
    liveTrades = liveTrades.concat(tick.trades).slice(-LIVE_ROWS);
    renderTrades(liveTrades);
  }
  if (tick.messages && tick.messages.length) {
    liveFlow = liveFlow.concat(tick.messages).slice(-LIVE_ROWS);
    renderFlow(liveFlow);
  }
}

/// How many of the newest buckets a tick reads once the window is in hand.
///
/// Two, and not one. One bucket changes while a bucket is open. Two change on
/// the tick a bucket closes: the one that just closed takes its last trade, and
/// the one that just opened appears.
const CANDLE_TAIL = 2;

/// The chart's rows, without asking for the whole window twice a second.
///
/// `/candles?n=400` is 39.5 KB and the page asked for it on every 500ms tick,
/// when at most two of those 400 buckets had changed. Measured on the live
/// exchange: that request answered in 657ms on its own and in 4,374ms from
/// inside the page, because six of them were out at once. It is about 200
/// bytes now.
///
/// An exact recent symbol, interval and lookback window starts with the tail.
/// A window is read whole when that exact key is not in the bounded cache,
/// when it has no rows, or when the newest bucket moved further ahead than the
/// tail can join up. The last case is what a tab that sat in the background
/// comes back to: nothing polled while it was there, and two buckets do not
/// close the gap.
// One exact symbol, interval and lookback window per entry. Keeping recent
// windows makes a return to MERKLE, ETH or BTC immediate, while the two-bucket
// request below catches it up. The bound prevents an operator with many listed
// symbols from turning tab clicks into unbounded browser memory.
const MAX_CANDLE_WINDOWS = 12;
const candleWindows = new Map();
let candlePending = null;
let candleRequestSerial = 0;

function cachedCandleWindow(key) {
  const cached = candleWindows.get(key);
  if (!cached) return null;
  // Touch the entry so the first key remains the least recently used one.
  candleWindows.delete(key);
  candleWindows.set(key, cached);
  return cached;
}

function rememberCandleWindow(window) {
  candleWindows.delete(window.key);
  candleWindows.set(window.key, window);
  while (candleWindows.size > MAX_CANDLE_WINDOWS) {
    candleWindows.delete(candleWindows.keys().next().value);
  }
  return window;
}

function currentCandleKey() {
  return `${symbol}|${interval}|${candleLookback}`;
}

function candleUrl(atSymbol, atInterval, n) {
  return `/candles?symbol=${encodeURIComponent(atSymbol)}&interval=${atInterval}&n=${n}`;
}

function candleRows() {
  const asked = { symbol, interval, lookback: candleLookback };
  const key = currentCandleKey();
  // A tab click starts the chart before /market answers. The ordinary refresh
  // reaches this function later and must join that same read, not invalidate
  // it and ask the matcher for the same window again.
  if (candlePending && candlePending.key === key) return candlePending.promise;

  const serial = ++candleRequestSerial;
  const request = (async () => {
    const current = () => serial === candleRequestSerial && key === currentCandleKey();
    const whole = async () => {
      const rows = await getCandles(candleUrl(asked.symbol, asked.interval, asked.lookback));
      if (!current()) return null;
      rememberCandleWindow({ key, rows });
      return { key, serial, rows };
    };
    const window = cachedCandleWindow(key);
    if (window === null || window.rows.length === 0) return whole();

    const tail = await getCandles(candleUrl(asked.symbol, asked.interval, CANDLE_TAIL));
    // A symbol, interval or lookback change makes this answer stale. A newer
    // request for the same chart also wins: do not merge an older tail into the
    // window it has already replaced.
    if (!current() || candleWindows.get(key) !== window) return null;
    const rows = window.rows;
    const newest = rows[rows.length - 1];
    // `start` is the bucket's own start in milliseconds, so this compares two
    // bucket starts and not two arrival times.
    if (tail.length && newest && tail[0].start > newest.start + asked.interval * 1000) {
      return whole();
    }
    for (const bucket of tail) {
      const at = rows.findIndex((row) => row.start === bucket.start);
      if (at >= 0) rows[at] = bucket;
      else rows.push(bucket);
    }
    // The window holds what was asked for, oldest first, however many buckets
    // the tail added to the end of it.
    if (rows.length > asked.lookback) rows.splice(0, rows.length - asked.lookback);
    return { key, serial, rows };
  })();
  const promise = request.finally(() => {
    if (candlePending && candlePending.promise === promise) candlePending = null;
  });
  candlePending = { key, promise };
  return promise;
}

function drawCandleAnswer(answer) {
  if (!answer || answer.serial !== candleRequestSerial || answer.key !== currentCandleKey()) {
    return answer;
  }
  candleError = null;
  candleLoading = false;
  drawChart(answer.rows);
  return answer;
}

function refreshCandleChart() {
  return candleRows().then(drawCandleAnswer).catch((error) => {
    if (error && error.name === "AbortError") return null;
    candleLoading = false;
    candleError = "Candles unavailable; retrying...";
    drawChart(lastCandles);
    return null;
  });
}

async function refresh() {
  const status = document.getElementById("status");
  try {
    const market = await get("/market");
    lastMarket = market;
    // A log that has not listed a symbol trades nothing, and the engine builds
    // its symbol list from the log's ListSymbol messages alone. So an empty
    // list here is a true answer about this exchange and not a failure to
    // reach it. Said in words, because everything below reads symbols[0] and
    // would otherwise show the operator a TypeError.
    if (market.symbols.length === 0) {
      renderVerify(market);
      document.getElementById("tabs").innerHTML =
        `<span class="dim">No market is open: the log has not listed a symbol.</span>`;
      document.getElementById("ticker").innerHTML = "";
      status.textContent = `message ${market.last_feed_id} · read ${market.messages_processed} · ` +
        `no listed symbol, so every order is refused · orders dropped ${market.orders_ignored}`;
      return;
    }
    renderTabs(market);
    // The first answer is what names the symbol, so the stream cannot be opened
    // before it. Opened once: `streaming()` is what every tick after this reads,
    // and `EventSource` reconnects on its own.
    if (live === null) openStream();
    renderSymbols(market);
    renderTicker(market);
    renderVerify(market);
    renderIntervals();
    // Each answer is drawn when it arrives.
    //
    // They used to be drawn together, after `Promise.all` had every one of
    // them, and that made every panel as slow as the slowest request in the
    // tick. Measured on the live exchange: the order book answered in 83ms and
    // was drawn 4,374ms later, because the chart's answer was in the same
    // batch. The Order Book, Recent Trades, Order Flow, Accounts, Positions and
    // the open orders all answer in 76 to 84ms, and all six waited for the one
    // request that did not.
    //
    // `Promise.all` is still awaited at the end of the group. It is not what
    // decides when a panel is drawn any more; it decides when the tick is over,
    // and it is what turns a failed request into the one message this page has
    // for an exchange it cannot reach.
    // The three the stream owns while it is open. Asked for again the moment it
    // is not: `streaming()` is false before the first connection, after an
    // error, and while `EventSource` is reconnecting.
    const streamed = streaming() && liveBook !== null;
    const bookP = streamed
      // The book itself has not changed since the last batch, but the line
      // under it reads the last trade and the spread out of `/market`, which
      // this tick just read.
      ? Promise.resolve(renderBook(bookToFit(liveBook), market))
      : get(`/book?symbol=${encodeURIComponent(symbol)}&depth=${depth}`)
        .then((rows) => { liveBook = rows; renderBook(rows, market); return rows; });
    const tradesP = streamed
      ? Promise.resolve(null)
      : get(`/trades?symbol=${encodeURIComponent(symbol)}&n=40`)
        .then((rows) => { liveTrades = rows; renderTrades(rows); return rows; });
    const messagesP = streamed
      ? Promise.resolve(null)
      : get(`/messages?symbol=${encodeURIComponent(symbol)}&n=40`)
        .then((rows) => { liveFlow = rows; renderFlow(rows); return rows; });
    const candlesP = refreshCandleChart();
    const acctTradesP = (selectedAccount == null
      ? Promise.resolve([])
      : get(`/trades?account=${selectedAccount}&n=60`))
      .then((rows) => { renderAccountTrades(rows); return rows; });
    const openOrdersP = (identity == null
      ? Promise.resolve([])
      : get(`/open-orders?account=${identity.account}`))
      .then((rows) => { renderMyOrders(rows); return rows; });
    // The three account reads are one panel between them, so they are drawn
    // together and not one at a time: an Accounts table drawn from the page
    // alone, and then again with the two named accounts in it, would move its
    // rows twice a tick.
    const accountsP = Promise.all([
      // `totals=true`: the four numbers an account and the value of what it
      // holds, without the per-symbol rows under them. The rows are about 500
      // of the 570 bytes of an account here, and this table draws none of
      // them. The two accounts named below are read whole, because the
      // Positions panel does draw their rows.
      get(`/positions?n=${ACCOUNTS_PAGE}&totals=true`),
      // The two accounts a visitor is looking at, by name. Neither is
      // necessarily in the page above. The page holds the lowest account
      // numbers and a visitor's own number is above 1,000,000. Both have
      // to be right now rather than within 30 seconds: the Positions panel is
      // the selected account, and the "you" badge has to appear on the tick
      // the visitor's first fill lands. One account is 663 bytes.
      selectedAccount == null
        ? Promise.resolve([])
        : get(`/positions?account=${selectedAccount}`),
      identity == null
        ? Promise.resolve([])
        : get(`/positions?account=${identity.account}`),
    ]).then(([accountsPage, selectedRows, myRows]) => {
      for (const a of [...accountsPage, ...selectedRows, ...myRows]) {
        accountsById.set(a.account, a);
      }
      const accounts = [...accountsById.values()];
      renderAccounts(accounts);
      renderZeroSum();
      renderPositions(accountsById.get(selectedAccount));
      return accounts;
    });
    // The order kinds, and what the selected one does. Redrawn every tick
    // because the two market kinds depend on the book having both sides, and
    // the price a market order would sign moves with the book. It reads the
    // book out of `/market`, which is already in hand, so it does not wait for
    // the six requests above.
    renderTerms();
    const openOrders = await openOrdersP;
    // What the exchange did with the last order this browser sent. It asks the
    // exchange one extra question, and only while an order is unsettled.
    await resolveOutcome(market, openOrders);
    // The tick is over when every panel has its answer. Nothing below is drawn
    // from these, and a rejection here is what the catch turns into the "cannot
    // reach the exchange" line.
    await Promise.all([bookP, tradesP, messagesP, candlesP, acctTradesP, accountsP]);
    // The inbox is a different service on a different port, so it is asked for
    // separately and its being down does not take the market view with it.
    pollInbox();
    // The chain is a third party again, and on its own much slower timer: an
    // anchor lands every few minutes, not twice a second.
    pollAnchor();
    // The session on the strip's anchor comes from this answer, and the "not
    // anchored yet" lines below name the feed's position, so a market tick that
    // moves either has to reach the view while it is open.
    if (anchorsOpen) renderAnchorHeader();
    // Nothing is written here while the exchange answers. This line used to
    // carry five counters, and under it a second line split the refusals by
    // reason: "message 5640501 · read 5640501 · cancels 1455029 · cancels too
    // late 151395 · orders dropped 165". They are the same numbers `/market`
    // serves, they wrapped onto three lines under Order Flow, and the head
    // they open with is on the verification strip at the top of the page. The
    // element stays for the one thing that has nowhere else to go: the
    // exchange being unreachable.
    status.textContent = "";
  } catch (e) {
    status.textContent = "The browser cannot reach the exchange. " + e.message;
  }
}

// ===========================================================================
// The anchor: the one thing on this page the operator cannot answer for
//
// Everything else here is checkable but local. The feed signs its history, the
// matcher re-executes it, the validators vouch for the ordering, and the
// separate service is one the sequencer does not control, but all of it runs
// on machines this operator runs. An operator who stops, deletes the databases,
// replays a different history and re-signs every statement leaves an exchange
// that passes every one of those checks.
//
// What that operator cannot do is change a transaction that is already on a
// public chain. So the sender writes one tuple every few minutes into
// ExchangeAnchor on Base: the feed's session, the message it had reached, the
// SHA-256 chain over messages 1..lastId, and the matcher's state root. This
// section reads those back out of the chain, in this browser, over an RPC
// this operator does not run. Nothing below asks the exchange whether the
// exchange is honest.
//
// The verification itself is a fold and nothing more: chain_0 is 32 zero bytes
// and chain_i is SHA-256(chain_{i-1} || the exact bytes of message i). That is
// why one anchor costs only the messages since the anchor before it.
// ===========================================================================

// GET /anchor-config, or null when this exchange is anchored to nothing. The
// 404 is a supported deployment, not a failure, and on it every anchor element
// on the page is removed rather than left showing an empty state.
let anchorConfig = null;
// `latest()` as of the last read, or null before the first one.
let anchorLatest = null;
// Why the chain could not be read, if it could not. An RPC that is down is
// itself worth saying: this is the layer that does not depend on the operator,
// and a reader should know when it is the layer that is missing.
let anchorDown = null;
// When the chain last answered. A failed read does not throw away the reading
// before it: the anchor that was on the contract 40 seconds ago is still the
// anchor that is on the contract, and this page says how old it is rather than
// pretending it never saw one.
let anchorReadAt = 0;
let anchorTick = 0;
let anchorsOpen = false;
// Every anchor found in the logs, newest first. Empty until the view is opened:
// a visitor who never opens it should cost the public RPC one `eth_call`,
// not a scan of the chain.
let anchors = [];
let anchorScan = null;     // { done, from, complete, note } while or after scanning
let verifying = false;

// `latest()`, from anchor/deployment.json and anchor/root-deployment.json.
//
// Two contracts answer this selector and they answer it with different values.
// `ExchangeAnchor` returns six words: lastId, session, chainHash, stateRoot,
// anchoredAt, count. `ExchangeRootAnchor` returns seven: treeSize,
// lastId, session, rootHash, stateRoot, anchoredAt, count. Both are fixed-width
// tuples, so Solidity encodes them with no offset and no length header and the
// answer is exactly 32 bytes a value: 192 bytes against 224.
//
// `/anchor-config` does not say which one it names. It serves the address, the
// chain and the deployment block, and nothing in it distinguishes the two
// contracts, so **the width of the answer is the only thing this page has to go
// on.** That is thinner than it should be and the decoder below does not lean
// on it alone: every uint64 word must have 24 leading zero bytes, every bytes8
// word must have 24 trailing zero bytes, and a root anchor's lastId must not be
// past its treeSize, the same rule the contract enforces on the way in. A
// 192-byte answer read as the wrong shape fails all three. The right fix is for
// `/anchor-config` to name the contract, and it is a matcher change, not a
// change this file can make.
const LATEST_SELECTOR = "0x52bfe789";
// `Anchored(uint64,bytes8,bytes32,bytes32,uint64,uint64)` and
// `AnchoredRoot(uint64,bytes8,bytes32,uint64,bytes32,uint64,uint64)`, from the
// two deployment files. In the logs there is no guessing: the two events hash
// to different topics, so topic 0 says which kind an entry is and neither
// filter can return the other kind. ExchangeRootAnchor.sol says exactly this is
// why the new contract is a new contract rather than the old one with its
// chainHash slot reused.
const CHAIN_TOPIC = "0x846b388d9a84109263340756e41099d4945f475c34c4f401faf0850b7c6d8385";
const ROOT_TOPIC = "0xf17e064140470b4f4b89eb3a9324a477206c096df6cbc3dfed400e9b4a2c191f";
// sepolia.base.org answers a wider window with
// {"code":-32614,"message":"eth_getLogs is limited to a 10,000 range"}, and
// `toBlock - fromBlock` of exactly 10000 is accepted. Other providers cap this
// lower, so it is a starting point that halves on refusal rather than a
// constant that has to be right.
const LOG_SPAN = 10000;
// How far back one opening of this view scans before it stops and offers to go
// on. At Base's two second blocks this is about nine days of chain. Without a
// stop, a page opened against a contract that has been anchoring for a year
// would fire two thousand requests at a public RPC before it drew anything.
const SCAN_WINDOWS = 40;
// The feed's own page size (services/src/feed.rs, PAGE_LIMIT). Asking for more
// is not refused, it is silently clamped, so the number is repeated here to
// keep the paging arithmetic honest.
const FEED_PAGE = 1000;
const ZERO_HASH = "0".repeat(64);

const fmtN = (n) => Number(n).toLocaleString("en-GB");
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
// Chain time is UTC seconds and is printed as UTC. A block timestamp shown in
// the reader's own zone invites them to compare it with a local clock, and the
// thing being established here is what a public record says, not what time it
// is where they are.
function fmtUTC(sec, zone) {
  const d = new Date(sec * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${zone ? " UTC" : ""}`;
}
function fmtAgo(sec) {
  const s = Math.max(0, Math.round(Date.now() / 1000 - sec));
  if (s < 45) return "just now";
  if (s < 5400) return Math.round(s / 60) + " min ago";
  if (s < 172800) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " d ago";
}
// A length of time, with no preposition and no "about": the sentence that uses
// it says whether it is a wait, a gap between anchors, or an estimate.
function fmtSpan(sec) {
  const s = Math.max(0, Math.round(sec));
  return s < 90 ? s + " seconds" : Math.round(s / 60) + " minutes";
}

// One JSON-RPC call to the chain named by the configuration. No key, no
// credentials, no library: a POST with a JSON body, which is all `eth_call` and
// `eth_getLogs` are.
// What the last answer weighed. The chain read is one of the five requests a
// check against the anchored root makes, and a page that prints "1,088 bytes"
// has to have counted all five.
let lastRpcBytes = 0;

// Which endpoint answered last. Every call starts there, so a browser that has
// found a working one does not walk the dead ones again on every poll.
let rpcInUse = 0;
// What this page reads the chain through. `anchor-config` answers a list now;
// a single string is what an older exchange answers, and this reads both.
const rpcList = () => {
  const c = anchorConfig || {};
  return Array.isArray(c.rpcs) && c.rpcs.length ? c.rpcs : c.rpc ? [c.rpc] : [];
};

// One JSON-RPC call, against the first endpoint in the list that answers.
//
// Public endpoints time out, rate-limit, and are on the block lists some
// browser extensions ship. Any one of those makes the anchor box red, and the
// anchor is the one number on this page that does not come from the operator.
// So there is more than one, and a failure walks to the next.
//
// Every endpoint here is a third party, and that is the property this box
// exists for. An RPC served by this exchange would make this a number the
// operator asserts, which is what every other number on the strip already is.
async function rpcOnce(url, method, params) {
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
  } catch (e) {
    throw new Error("The browser cannot reach the " + anchorConfig.chain_name +
      " RPC at " + url + ".");
  }
  if (!res.ok) throw new Error(url + " answered " + res.status + " to " + method + ".");
  const text = await res.text();
  lastRpcBytes = encode(text).length;
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    throw new Error(url + " did not answer " + method + " with JSON.");
  }
  if (body && body.error) {
    throw new Error(method + ": " + (body.error.message || JSON.stringify(body.error)));
  }
  return body.result;
}

async function rpc(method, params) {
  const urls = rpcList();
  if (!urls.length) throw new Error("This exchange named no RPC to read its chain through.");
  let firstFailure = null;
  for (let tried = 0; tried < urls.length; tried++) {
    const at = (rpcInUse + tried) % urls.length;
    try {
      const answer = await rpcOnce(urls[at], method, params);
      rpcInUse = at;
      return answer;
    } catch (e) {
      firstFailure = firstFailure || e;
    }
  }
  // Every endpoint failed. The first failure is the one reported, because the
  // first one tried is the one the operator named, and the count says the page
  // did not give up after one: "no answer" from three endpoints is a different
  // fact from "no answer" from one.
  throw new Error(urls.length > 1
    ? firstFailure.message + " " + urls.length + " endpoints were tried and none answered."
    : firstFailure.message);
}

// The endpoint the last answer came from, for the lines that tell a reader
// where a number they are looking at was read. Naming the first in the list
// would be wrong the moment it is not the one that answered.
const rpcAnswering = () => rpcList()[rpcInUse] || "no RPC";

// The i-th 32-byte word of a hex return, without its 0x.
const word = (hex, i) => hex.slice(2 + i * 64, 2 + (i + 1) * 64).toLowerCase();
// A uint64 out of a 32-byte word. Through BigInt rather than parseInt, which
// silently rounds above 2^53; anything that would not survive the conversion is
// refused rather than displayed wrong.
//
// The 24 leading bytes must be zero. A uint64 is right-aligned in its word, so
// on a real answer they always are, and when they are not, this word is not
// the word this page thinks it is. That is the check that stops one contract's
// answer being read as the other's shape.
function u64(hexWord) {
  if (hexWord.slice(0, 48) !== "0".repeat(48)) {
    throw new Error("The word 0x" + hexWord + " is not a uint64. This is not the answer this page " +
      "expected here.");
  }
  const v = BigInt("0x" + hexWord);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("The value 0x" + hexWord + " is too large for this page.");
  return Number(v);
}

// A bytes8 out of a 32-byte word. Left-aligned, so the session is the FIRST
// eight bytes and not the last. Right-aligned, this would read as zero for
// every anchor ever written. The 24 bytes after it must be zero for the
// same reason `u64` insists on its own padding.
function b8(hexWord) {
  if (hexWord.slice(16) !== "0".repeat(48)) {
    throw new Error("The word 0x" + hexWord + " is not a bytes8. This is not the answer this page " +
      "expected here.");
  }
  return hexWord.slice(0, 16);
}

// `latest()`, from whichever of the two contracts is at this address.
//
// 224 bytes is ExchangeRootAnchor and 192 is ExchangeAnchor. See the note on
// LATEST_SELECTOR for why the width is the discriminator and what the decoders
// check so that it is not the only thing standing between the two.
function decodeLatest(data) {
  const bytes = typeof data === "string" && data.startsWith("0x") ? (data.length - 2) / 2 : -1;
  if (bytes === 224) {
    const out = {
      kind: "root",
      treeSize: u64(word(data, 0)),
      lastId: u64(word(data, 1)),
      session: b8(word(data, 2)),
      rootHash: word(data, 3),
      stateRoot: word(data, 4),
      anchoredAt: u64(word(data, 5)),
      count: u64(word(data, 6)),
    };
    // The contract reverts a write with `lastId > treeSize`, so no anchor it
    // holds can break this. An answer that does break it is not this contract's
    // answer and nothing below should be built on it.
    if (out.lastId > out.treeSize) {
      throw new Error("latest() says the cursor is at message " + out.lastId + " and the anchored " +
        "tree holds " + out.treeSize + ". The contract at " + anchorConfig.address + " refuses that " +
        "combination, so this is not an answer from it.");
    }
    return out;
  }
  if (bytes === 192) {
    return {
      kind: "chain",
      lastId: u64(word(data, 0)),
      session: b8(word(data, 1)),
      chainHash: word(data, 2),
      stateRoot: word(data, 3),
      anchoredAt: u64(word(data, 4)),
      count: u64(word(data, 5)),
    };
  }
  throw new Error(data === "0x"
    ? "latest() returned nothing. There is no contract at " + anchorConfig.address + " on this chain."
    : "latest() returned " + (bytes < 0 ? "an answer this page cannot read" : bytes + " bytes") +
      ". This page reads 224 bytes (a root anchor) and 192 bytes (a chain anchor).");
}

// One anchor out of the logs, of either kind. Topic 0 decides, and a log that
// carries neither topic is not an anchor. `scanFrom` drops it.
function decodeAnchorLog(log) {
  const topic = String(log.topics[0] || "").toLowerCase();
  const common = { block: Number(BigInt(log.blockNumber)), tx: String(log.transactionHash) };
  if (topic === ROOT_TOPIC) {
    // AnchoredRoot(treeSize indexed, session indexed, rootHash, lastId,
    // stateRoot, anchoredAt, count).
    return {
      ...common,
      kind: "root",
      treeSize: u64(log.topics[1].slice(2)),
      session: b8(log.topics[2].slice(2)),
      rootHash: word(log.data, 0),
      lastId: u64(word(log.data, 1)),
      stateRoot: word(log.data, 2),
      anchoredAt: u64(word(log.data, 3)),
      count: u64(word(log.data, 4)),
    };
  }
  if (topic === CHAIN_TOPIC) {
    // Anchored(lastId indexed, session indexed, chainHash, stateRoot,
    // anchoredAt, count).
    return {
      ...common,
      kind: "chain",
      lastId: u64(log.topics[1].slice(2)),
      session: b8(log.topics[2].slice(2)),
      chainHash: word(log.data, 0),
      stateRoot: word(log.data, 1),
      anchoredAt: u64(word(log.data, 2)),
      count: u64(word(log.data, 3)),
    };
  }
  throw new Error("not an anchor event");
}

// Which contract is at this address, once `latest()` has been read once.
const anchorKind = () => (anchorLatest ? anchorLatest.kind : null);
// True on a deployment whose anchors commit a Merkle root, which is the only
// deployment where a trade can be checked against the chain in a kilobyte.
const isRootAnchored = () => anchorKind() === "root";

async function readAnchorConfig() {
  let res;
  try {
    res = await fetch("/anchor-config");
  } catch (e) {
    return null;
  }
  // 404 is the answer for an exchange anchored to nothing, and it is a normal
  // deployment. Anything else that is not 200 is a matcher that cannot answer,
  // which leaves this page in the same position: nothing to read the chain for.
  if (!res.ok) return null;
  try {
    return await res.json();
  } catch (e) {
    return null;
  }
}

// The strip's read, on its own slow timer. Anchors are written minutes apart,
// so asking a public RPC twice a second, which is what the market tick runs at,
// would be thirty thousand requests an hour per open tab to learn a number
// that changes twelve times.
const ANCHOR_EVERY = 60;
async function pollAnchor() {
  if (!anchorConfig) return;
  if (anchorTick++ % ANCHOR_EVERY !== 0) return;
  try {
    anchorLatest = decodeLatest(await rpc("eth_call",
      [{ to: anchorConfig.address, data: LATEST_SELECTOR }, "latest"]));
    anchorDown = null;
    anchorReadAt = Date.now();
  } catch (e) {
    anchorDown = e.message;
  }
  if (lastMarket) renderVerify(lastMarket);
  if (anchorsOpen) renderAnchorHeader();
}

// The strip's anchor item, or null when there is nothing to say.
//
// This is deliberately the only item on the strip that is boxed and coloured.
// Everything to its left is the matcher's own account of its own work; this the
// browser read from a contract on another party's chain. The two are different
// kinds of claim and the strip should not present them as one row of counters.
function anchorPart() {
  if (!anchorConfig) return null;
  const chain = escapeText(anchorConfig.chain_name);
  const why = "This browser read this from the anchor contract on " + chain +
    ". The exchange did not report it. Click to see every anchor and to check one.";
  // Never read it. There is nothing to show but the failure.
  if (anchorDown && !anchorLatest) {
    return `<button class="base down" data-open-anchors title="${escapeText(anchorDown)}">` +
      `${chain}<span class="n">no answer</span></button>`;
  }
  if (!anchorLatest) {
    return `<button class="base" data-open-anchors title="${escapeText(why)}">` +
      `reading ${chain}…</button>`;
  }
  const out = anchorConfig.explorer
    ? `<a class="out" href="${escapeText(anchorConfig.explorer)}/address/${escapeText(anchorConfig.address)}"` +
      ` target="_blank" rel="noopener noreferrer" title="The anchor contract on the ${chain} explorer.">↗</a>`
    : "";
  if (!anchorLatest.count) {
    return `<span class="anchor"><button class="base" data-open-anchors title="${escapeText(why)}">` +
      `${chain}<span class="n">no anchor yet</span></button>${out}</span>`;
  }
  // A root anchor's headline number is the tree it committed to, not the
  // matcher's cursor: the tree is what a proof is checked against.
  const at = anchorLatest.kind === "root"
    ? `·<span class="lg"> tree</span> <span class="n">${fmtN(anchorLatest.treeSize)}</span>`
    : `·<span class="lg"> message</span> <span class="n">${fmtN(anchorLatest.lastId)}</span>`;
  // The last read failed, and there is a reading from before it. The anchor is
  // still the anchor: what is not current is this browser's view of the chain.
  // So the box says what it knows and marks itself stale, rather than dropping
  // to "no answer" and losing a number that was right 40 seconds ago.
  const stale = anchorDown
    ? ` <span class="lg">· not reading</span><span class="sm">· stale</span>`
    : "";
  const said = anchorDown
    ? anchorDown + "\n\nThis is the last reading that arrived, " +
      fmtAgo(Math.floor(anchorReadAt / 1000)) + ". The anchor on the contract has not " +
      "changed because this browser cannot reach the chain."
    : why;
  return `<span class="anchor"><button class="base${anchorDown ? " stale" : ""}" ` +
    `data-open-anchors title="${escapeText(said)}">anchored` +
    `<span class="n">#${anchorLatest.count}</span>${at}` +
    `· ${fmtAgo(anchorLatest.anchoredAt)}${stale}</button>${out}</span>`;
}

// ---------------------------------------------------------------------------
// Reading every anchor out of the logs
// ---------------------------------------------------------------------------

// Newest first, so the anchors a reader cares about are on screen before the
// scan has finished walking back to the deployment block.
//
// `count` from `latest()` is read at the same block the scan ends at, and it is
// the contract's own tally of successful writes, so it says exactly when the
// scan is complete and there is no need to reach the deployment block to find
// out. A scan that ends short of it says so rather than presenting a partial
// list as the whole record.
async function loadAnchors() {
  anchors = [];
  anchorScan = { running: true, from: null, found: 0, counted: 0, reachedFloor: false, note: null };
  renderAnchorTable();
  const tipHex = await rpc("eth_blockNumber", []);
  const tip = Number(BigInt(tipHex));
  // Pinned to the same block as the scan below: `count` and the logs are then
  // two views of one moment, and an anchor landing between the two calls cannot
  // make a complete scan look like it is missing one.
  anchorLatest = decodeLatest(await rpc("eth_call",
    [{ to: anchorConfig.address, data: LATEST_SELECTOR }, tipHex]));
  anchorDown = null;
  renderAnchorHeader();
  await scanFrom(tip);
  renderAnchors();
}

// Continues where the last pass stopped, at the window budget or at an error.
async function loadOlderAnchors() {
  if (!anchorScan || anchorScan.running || anchorScan.from == null) return;
  const resume = anchorScan.from;
  anchorScan = { ...anchorScan, running: true, note: null };
  renderAnchorScan();
  await scanFrom(resume);
  renderAnchors();
}

// One backward pass over the logs. The first opening and "load older" differ
// only in the block they start at, so they are the same walk.
async function scanFrom(top) {
  const floor = Number(anchorConfig.deployed_block);
  let span = LOG_SPAN;
  let to = top;
  let windows = 0;
  let stopped = null;
  while (to >= floor && anchors.length < anchorLatest.count && windows < SCAN_WINDOWS) {
    const from = Math.max(floor, to - span);
    let logs;
    try {
      logs = await rpc("eth_getLogs", [{
        address: anchorConfig.address,
        fromBlock: "0x" + from.toString(16),
        toBlock: "0x" + to.toString(16),
      }]);
    } catch (e) {
      // Providers cap this range and each one caps it differently, so the
      // window is halved and tried again rather than the scan being abandoned
      // over a limit that is not an error in anything here.
      if (span > 200) { span = Math.floor(span / 2); continue; }
      stopped = e.message;
      break;
    }
    windows++;
    for (const log of logs) {
      try { anchors.push(decodeAnchorLog(log)); } catch (e) { /* not an Anchored event */ }
    }
    anchors.sort((a, b) => b.count - a.count);
    renderAnchorTable();
    renderSentOrders();
    if (from === floor) { to = floor - 1; break; }
    to = from - 1;
  }
  const more = to >= floor && anchors.length < anchorLatest.count;
  anchorScan = {
    running: false,
    // Where a further pass would resume, or null when there is nowhere left to
    // go: every anchor the contract counts has been found, or the walk reached
    // the block the contract was deployed in.
    from: more ? to : null,
    found: anchors.length,
    counted: anchorLatest.count,
    reachedFloor: to < floor,
    note: stopped,
  };
}

// ---------------------------------------------------------------------------
// Folding the feed, here, over the bytes the feed served
// ---------------------------------------------------------------------------

// The lines of one `/messages.ndjson` body, as bytes.
//
// Split on 0x0A and never decoded before hashing. The chain is folded over
// `serde_json::to_vec` of each message, and serde writes a price of 100.0 as
// `100.0` where JSON.stringify writes `100`, same number, different bytes,
// different SHA-256. A page that parsed these and re-serialized them would
// compute a chain that disagrees with the one the feed signed and would report
// an honest exchange as a dishonest one. The newline is a separator the feed
// adds after each message and is not part of what was hashed, so it is dropped
// with the split.
function ndjsonLines(bytes) {
  const lines = [];
  let start = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0x0a) {
      lines.push(bytes.subarray(start, i));
      start = i + 1;
    }
  }
  // The feed writes one 0x0A after every message, so a body ending anywhere
  // else was cut short in transit. Folding what arrived would produce a wrong
  // hash for a reason that has nothing to do with the operator, which is the
  // one mistake this whole section must not make.
  if (start !== bytes.length) {
    throw new Error("The answer of the sequencer stopped in the middle of a message. The answer is " +
      "not complete.");
  }
  return lines;
}

// The id of one line, from a COPY of it, for checking the page starts and
// continues where it should. Never used to rebuild the bytes: the bytes are
// what arrived.
function lineId(text) {
  const msg = JSON.parse(text);
  const body = msg.New || msg.Cancel;
  return body ? Number(body.id) : null;
}

// Folds the feed's own bytes from `fromId` (exclusive) to `toId` (inclusive),
// starting from `startHex`.
//
// `since` is EXCLUSIVE. Checked against the running feed rather than assumed:
// `?since=0&limit=3` answers with messages 1, 2, 3 and `?since=1&limit=3`
// answers with 2, 3, 4. services/src/feed.rs agrees: `page()` starts at
// `since.saturating_add(1)` and its query is `WHERE id > ?1`. An off-by-one
// here would put every verification one message out and report every honest
// anchor as broken, so the page asks for `since = the last id already folded`
// and starts at the previous anchor's own lastId.
async function foldFeed(fromId, toId, startHex, onProgress, run) {
  if (!feedUrl) throw new Error("Nobody told this page where the sequencer is. It cannot read the messages.");
  const start = fromHex(startHex);
  if (!start || start.length !== 32) throw new Error("The start hash of the anchor is not 32 bytes.");
  const decoder = new TextDecoder();
  const total = toId - fromId;
  const began = performance.now();
  let chain = start;
  let id = fromId;
  let n = 0;
  let session = null;
  while (id < toId) {
    if (run && run.cancelled) throw new VerifyStopped();
    // Never past the target: the window this anchor commits to ends at toId,
    // and one message folded beyond it produces a hash for a different history.
    const want = Math.min(FEED_PAGE, toId - id);
    // One closed range is one URL, and deliberately: the same window verified
    // twice is then a request the browser can answer out of its own cache. A
    // cache-busting parameter, or `cache: "no-store"`, would throw that away
    // and make every repeat pay the full download again.
    const url = feedUrl + "/messages.ndjson?since=" + id + "&limit=" + want;
    let res;
    try {
      res = await fetch(url, run ? { signal: run.ctrl.signal } : undefined);
    } catch (e) {
      // A stopped verification arrives here too, as the abort the signal
      // raised. It is not the feed being unreachable and must not be reported
      // as if it were.
      if (run && run.cancelled) throw new VerifyStopped();
      throw new Error("The browser cannot reach the sequencer at " + feedUrl + ".");
    }
    if (!res.ok) {
      const detail = (await res.text()).trim();
      throw new Error("The sequencer answered " + res.status + " for the messages after #" + id +
        (detail ? ". " + detail : "."));
    }
    // Only readable when the feed exposes it cross-origin; null otherwise, and
    // the session check falls back to what the matcher reports. See
    // `feedSession`.
    session = res.headers.get("x-feed-session") || session;
    if (session) feedSessionHeader = session;
    const body = new Uint8Array(await res.arrayBuffer());
    const lines = ndjsonLines(body);
    // What a message weighs on this deployment, kept for the costs printed on
    // the verify buttons. Measured from the pages this browser actually fetched
    // rather than assumed: message sizes differ between feeds, and a number
    // written down here would be a guess about somebody else's.
    noteFeedBytes(body.length, lines.length);
    if (!lines.length) {
      throw new Error("The sequencer served no message after #" + id + ". This anchor covers a log " +
        "that reaches #" + toId + ". The sequencer is behind the record on the chain.");
    }
    for (const line of lines) {
      if (id >= toId) break;
      const at = lineId(decoder.decode(line));
      if (at !== id + 1) {
        throw new Error("The sequencer served message #" + at + ". Message #" + (id + 1) +
          " was expected. Its log has a gap here.");
      }
      const joined = new Uint8Array(32 + line.length);
      joined.set(chain, 0);
      joined.set(line, 32);
      chain = new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
      id = at;
      n++;
      // A tight await loop over a promise queue never lets the browser paint,
      // so the count on screen would jump from 0 to 600 at the end. Yielding to
      // a timer hands the frame back.
      if (n % 250 === 0) {
        onProgress(n, total);
        await new Promise((r) => setTimeout(r, 0));
        if (run && run.cancelled) throw new VerifyStopped();
      }
    }
    onProgress(n, total);
  }
  // What this machine and this network just managed, for the next estimate.
  noteFold(n, performance.now() - began);
  return { hash: toHex(chain), messages: n, session };
}

// The window one anchor commits to, and whether this page can check it.
//
// The start is the anchor before it: its chainHash and its lastId. The first
// anchor ever written, the one the contract counted as 1, starts from 32 zero
// bytes at message 0, because that is where the feed's chain starts. Any other
// anchor whose predecessor has not been loaded cannot be checked from zero: the
// fold would cover the whole history instead of this anchor's window, take the
// wrong start hash, and report a mismatch that means nothing.
// A root anchor has no window and no chain hash. It commits a Merkle root, and
// the check that reaches it is a consistency proof, seventeen hashes, not six
// hundred messages, so `verifyRootAnchor` handles those rows instead.
function anchorWindow(a) {
  if (a.kind !== "chain") return null;
  if (a.count === 1) return { fromId: 0, startHash: ZERO_HASH, prev: null };
  const prev = anchors.find((x) => x.count === a.count - 1);
  if (!prev) return null;
  return { fromId: prev.lastId, startHash: prev.chainHash, prev };
}

// The bytes a chain head signature covers, exactly as `head_statement` builds
// them in services/src/logchain.rs. Same shape and same reasoning as
// `treeHeadStatement` further down, and a different version prefix so the two
// cannot be swapped for each other.
const chainHeadStatement = (head) =>
  encode(["exchange-feed-head-v1", head.session, head.last_id, head.chain].join("\n"));

// `GET /head`, with its Ed25519 signature checked here. The chain-hash twin of
// `readSignedTreeHead`, and there is no path through it that returns an
// unverified head either.
async function readSignedChainHead() {
  let res;
  try {
    res = await fetch(feedUrl + "/head", { cache: "no-store" });
  } catch (e) {
    throw new ProofFailure("reading the signed chain head",
      "The browser cannot reach the sequencer at " + feedUrl + ".");
  }
  if (!res.ok) {
    throw new ProofFailure("reading the signed chain head",
      "The sequencer answered " + res.status + " to GET /head.");
  }
  const text = await res.text();
  const bytes = encode(text).length;
  let head;
  try {
    head = JSON.parse(text);
  } catch (e) {
    throw new ProofFailure("reading the signed chain head", "GET /head did not answer with JSON.");
  }
  const key = fromHex(String(head.public_key ?? ""));
  const signature = fromHex(String(head.signature ?? ""));
  const chain = fromHex(String(head.chain ?? ""));
  if (!key || key.length !== 32 || !signature || signature.length !== 64 || !chain || chain.length !== 32) {
    throw new ProofFailure("the shape of the signed chain head",
      "A chain head carries a 32 byte public key, a 64 byte signature and a 32 byte chain hash, as " +
      "lower case hex. This one does not.");
  }
  if (!Number.isSafeInteger(head.last_id)) {
    throw new ProofFailure("the shape of the signed chain head",
      "The message number of this head is too large for this page to check.");
  }
  const signed = await ed.verifyAsync(signature, chainHeadStatement(head), key, { zip215: false });
  if (!signed) {
    throw new ProofFailure("the signature on the signed chain head",
      "The signature on GET /head is not this key's signature over this session, this message number " +
      "and this chain hash. So the chain hash is a number, not a commitment, and nothing was folded " +
      "against it.");
  }
  return { head, bytes };
}

// The whole log, folded here, against the head the sequencer signed.
//
// This is the check that needs no chain at all, and it is the only one an
// exchange anchored to nothing can offer. It is also by far the most expensive:
// every message of the history, over the wire, hashed in this tab.
//
// It ends at the operator's own signature, so it does not say what the anchored
// root says. What it does say is that this whole log, every message, not a
// window, folds to the one value the operator put their name to, with no tree,
// no proof and no contract involved.
async function verifyWholeLog(messageId, report) {
  if (!feedUrl) {
    report(`<span class="neg">Nobody told this page where the sequencer is.</span>`);
    return;
  }
  const run = startRun();
  let done = 0;
  let signed;
  try {
    report(`checking the signature on the chain head…`);
    signed = await readSignedChainHead();
  } catch (e) {
    if (verifyRun === run) verifyRun = null;
    report(e instanceof ProofFailure
      ? `<span class="neg">This check failed at: ${escapeText(e.step)}.</span> ${escapeText(e.message)}`
      : `<span class="neg">This browser could not read the head.</span> ${escapeText(e.message)}`);
    return;
  }
  const head = signed.head;
  if (messageId > head.last_id) {
    if (verifyRun === run) verifyRun = null;
    report(`<span class="neg">This head does not reach your order.</span> The sequencer signed a head ` +
      `at message ${fmtN(head.last_id)} and your order is #${fmtN(messageId)}.`);
    return;
  }
  report(`hashing <b class="ax-n">0</b> of ${fmtN(head.last_id)} messages in this browser. ` +
    `<button class="go" data-verify-stop="1">stop</button>`);
  const counter = document.querySelector(`#ax-log-${messageId} .ax-n`);
  const began = performance.now();
  let out;
  try {
    out = await foldFeed(0, head.last_id, ZERO_HASH, (n) => {
      done = n;
      if (counter) counter.textContent = fmtN(n);
    }, run);
  } catch (e) {
    report(stopped(e)
      ? `<span class="dim">Stopped.</span> This browser hashed ${fmtN(done)} of ` +
        `${fmtN(head.last_id)} messages. A check that stops early says nothing about this order.`
      : `<span class="neg">This browser could not fold the log.</span> ${escapeText(e.message)}`);
    return;
  } finally {
    if (verifyRun === run) verifyRun = null;
  }
  const ms = Math.round(performance.now() - began);
  const weight = feedBytes ? out.messages * bytesPerMessage() : null;
  if (out.hash !== head.chain) {
    report(`<span class="neg">The fold does not match the head the sequencer signed.</span> This ` +
      `browser hashed ${fmtN(out.messages)} messages from 32 zero bytes and got ` +
      `<span class="mono">${out.hash}</span>. The signed head says ` +
      `<span class="mono">${escapeText(head.chain)}</span>.`);
    return;
  }
  report(`<span class="pos">The whole log folds to the head the sequencer signed.</span> Order ` +
    `#${fmtN(messageId)} is one of the ${fmtN(out.messages)} messages this browser hashed, from 32 ` +
    `zero bytes to <span class="mono">${out.hash}</span>${weight ? `, about ${fmtSize(weight)}` : ""} ` +
    `in ${fmtN(ms)} ms. <span class="dim">This check touched no chain and no Merkle tree. It ends at ` +
    `an Ed25519 signature by key <span class="mono">${escapeText(head.public_key)}</span>, which is ` +
    `the operator's own, over message ${fmtN(head.last_id)} of session ` +
    `<span class="mono">${escapeText(head.session)}</span>.</span>`);
}

// ---------------------------------------------------------------------------
// Checking one message with an inclusion proof, RFC 9162
// ---------------------------------------------------------------------------
//
// The fold above answers "is the whole history this sequencer serves still the
// history it wrote into the contract". This answers a smaller and different
// question: "is this one message inside the tree the sequencer signed". The
// sequencer keeps a Merkle tree beside the hash chain (docs/ENGINE.md section 1)
// and serves the path from one leaf up to the root, so the check costs about
// log2(n) hashes instead of n messages. Both numbers are printed after every
// run, measured, so the difference is on screen rather than asserted here.
//
// The two do not replace each other and the page never presents them as if they
// did. A proof is checked against a root the operator signed, so it says the
// operator is not contradicting themselves; the fold is checked against a value
// on a chain the operator does not run, so it says the operator cannot have
// changed their mind since.
//
// The first step carries the whole thing. The root has to come out of a signed
// tree head and the signature has to be checked here, in this browser. A root
// taken from an answer whose signature nobody looked at is a number the operator
// chose, and a proof against such a root always verifies and establishes
// nothing. So `GET /sth` is verified with the same Ed25519 library this page
// signs orders with, before the message or the proof is even fetched.

// A check that did not pass, and which of the checks it was.
//
// The step is carried separately from the sentence because "it failed" is not
// something a visitor can act on. "The sequencer served a different message" and
// "the browser could not reach the sequencer" are the operator's problem and the
// network's problem respectively, and they must not read the same.
class ProofFailure extends Error {
  constructor(step, detail) {
    super(detail);
    this.step = step;
  }
}

// The two RFC 9162 domain prefixes. Section 2.1.1: a leaf is hashed as
// HASH(0x00 || entry) and an internal node as HASH(0x01 || left || right).
// They are what stops an internal node being presented as a leaf. Without them
// a proof can be produced for bytes nobody ever submitted, so nothing here
// drops them or reorders them.
const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

// SHA-256 over the concatenation, without building an intermediate string.
async function sha256(...parts) {
  let width = 0;
  for (const part of parts) width += part.length;
  const joined = new Uint8Array(width);
  let at = 0;
  for (const part of parts) { joined.set(part, at); at += part.length; }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", joined));
}

// The bytes a tree head signature covers, exactly as `tree_head_statement`
// builds them in services/src/logchain.rs: a versioned prefix and four fields,
// newline separated, no trailing newline.
//
// The prefix is not decoration either. This feed signs a chain head and a tree
// head with one key, and both statements start with a session and a count, so
// without `exchange-feed-sth-v1` and `exchange-feed-head-v1` a chain head at
// message 500 and a tree head over 500 leaves would be two signatures a verifier
// could swap for each other.
//
// Rebuilt from the parsed fields rather than hashed off the wire on purpose: the
// signature covers these five values, not the JSON that carried them. That is
// the opposite of the rule for a message, where the bytes that arrived are the
// only thing that may be hashed: a message is a leaf, and its serialization is
// what was committed to.
const treeHeadStatement = (sth) =>
  encode(["exchange-feed-sth-v1", sth.session, sth.timestamp, sth.tree_size, sth.root_hash].join("\n"));

// `GET /sth`, with its Ed25519 signature checked here.
//
// Returns the head and how many bytes it cost, or throws naming the step. There
// is no path through this function that returns an unverified head: a caller
// that holds an `sth` from here holds one whose signature this browser checked
// against the key in it.
async function readSignedTreeHead() {
  let res;
  try {
    res = await fetch(feedUrl + "/sth", { cache: "no-store" });
  } catch (e) {
    throw new ProofFailure("reading the signed tree head",
      "The browser cannot reach the sequencer at " + feedUrl + ".");
  }
  if (!res.ok) {
    throw new ProofFailure("reading the signed tree head",
      "The sequencer answered " + res.status + " to GET /sth.");
  }
  const text = await res.text();
  const bytes = encode(text).length;
  let sth;
  try {
    sth = JSON.parse(text);
  } catch (e) {
    throw new ProofFailure("reading the signed tree head", "GET /sth did not answer with JSON.");
  }
  const key = fromHex(String(sth.public_key ?? ""));
  const signature = fromHex(String(sth.signature ?? ""));
  const root = fromHex(String(sth.root_hash ?? ""));
  if (!key || key.length !== 32 || !signature || signature.length !== 64 || !root || root.length !== 32) {
    throw new ProofFailure("the shape of the signed tree head",
      "A tree head carries a 32 byte public key, a 64 byte signature and a 32 byte root, as lower " +
      "case hex. This one does not.");
  }
  // Both numbers go into the signed statement as decimal digits, and a JavaScript
  // number above 2^53 neither survives JSON intact nor prints as digits. It
  // prints as 1e+21. Refused rather than checked wrongly: a statement rebuilt
  // from a rounded number never verifies, and reporting that as a bad signature
  // would blame the operator for this page's arithmetic.
  if (!Number.isSafeInteger(sth.tree_size) || !Number.isSafeInteger(sth.timestamp)) {
    throw new ProofFailure("the shape of the signed tree head",
      "The tree size or the timestamp of this head is too large for this page to check.");
  }
  // The one line the rest of this depends on. `zip215: false` is RFC 8032
  // verification, which is what the sequencer's own `verify_strict` does
  // (services/src/logchain.rs); the library's default is the looser ZIP215 rule,
  // and a page checking a feed under a rule the feed does not use would accept
  // signatures the feed itself would reject.
  const signed = await ed.verifyAsync(signature, treeHeadStatement(sth), key, { zip215: false });
  if (!signed) {
    throw new ProofFailure("the signature on the signed tree head",
      "The signature on GET /sth is not this key's signature over this session, this timestamp, this " +
      "tree size and this root. So the root is a number, not a commitment, and no proof was checked " +
      "against it.");
  }
  return { sth, bytes };
}

// One message of the log, as the bytes the sequencer hashed into it.
//
// `arrayBuffer`, never `text()` and never re-serialized: the leaf is
// SHA-256(0x00 || those exact bytes), and Rust writes a price of 100.0 as
// `100.0` where JSON.stringify writes `100`. Same number, different bytes,
// different leaf, and a page that re-encoded would report an honest sequencer as
// a dishonest one. `since` is exclusive, so message N is `since=N-1&limit=1`.
async function readMessageBytes(messageId) {
  const url = feedUrl + "/messages.ndjson?since=" + (messageId - 1) + "&limit=1";
  let res;
  try {
    res = await fetch(url);
  } catch (e) {
    throw new ProofFailure("reading the message",
      "The browser cannot reach the sequencer at " + feedUrl + ".");
  }
  if (!res.ok) {
    throw new ProofFailure("reading the message",
      "The sequencer answered " + res.status + " for message #" + messageId + ".");
  }
  const body = new Uint8Array(await res.arrayBuffer());
  const lines = ndjsonLines(body);
  if (!lines.length) {
    throw new ProofFailure("reading the message",
      "The sequencer served no message #" + messageId + ".");
  }
  const line = lines[0];
  const at = lineId(new TextDecoder().decode(line));
  if (at !== messageId) {
    throw new ProofFailure("the message the sequencer served",
      "This page asked for message #" + messageId + " and the sequencer served message #" + at + ".");
  }
  return { line, bytes: body.length };
}

// `GET /proof/inclusion`, with every number in the answer checked against what
// was asked for.
//
// The proof carries no root and no signature, deliberately: the root comes from
// the head above. What it does carry is `leaf_index` and `message_id`, which
// differ by one. RFC 9162 counts leaves from 0 and this sequencer numbers
// messages from 1. The page uses the numbers in the answer rather than
// converting again, which is the one place this is easy to get wrong.
async function readInclusionProof(messageId, sth) {
  const leaf = messageId - 1;
  const url = feedUrl + "/proof/inclusion?leaf=" + leaf + "&tree_size=" + sth.tree_size;
  let res;
  try {
    res = await fetch(url);
  } catch (e) {
    throw new ProofFailure("reading the proof",
      "The browser cannot reach the sequencer at " + feedUrl + ".");
  }
  if (!res.ok) {
    const detail = (await res.text()).trim();
    throw new ProofFailure("reading the proof",
      "The sequencer answered " + res.status + " for the proof of leaf " + leaf + " in a tree of " +
      sth.tree_size + (detail ? ". " + detail : "."));
  }
  const text = await res.text();
  const bytes = encode(text).length;
  let proof;
  try {
    proof = JSON.parse(text);
  } catch (e) {
    throw new ProofFailure("reading the proof", "GET /proof/inclusion did not answer with JSON.");
  }
  // A proof for another leaf, another tree or another history verifies against
  // nothing, but it is worth saying which of the three arrived rather than
  // letting the climb below fail with "the root does not match".
  if (proof.session !== sth.session) {
    throw new ProofFailure("the proof answers the question that was asked",
      "The proof names history " + String(proof.session) + " and the tree head names " +
      String(sth.session) + ".");
  }
  if (proof.leaf_index !== leaf || proof.message_id !== messageId || proof.tree_size !== sth.tree_size) {
    throw new ProofFailure("the proof answers the question that was asked",
      "This page asked for leaf " + leaf + " (message #" + messageId + ") in a tree of " +
      sth.tree_size + ". The answer is about leaf " + proof.leaf_index + " (message #" +
      proof.message_id + ") in a tree of " + proof.tree_size + ".");
  }
  const path = [];
  for (const node of proof.inclusion_path || []) {
    const bytes32 = fromHex(String(node));
    if (!bytes32 || bytes32.length !== 32) {
      throw new ProofFailure("the shape of the proof",
        "A proof is a list of 32 byte hashes as lower case hex. This one holds " +
        String(node) + ".");
    }
    path.push(bytes32);
  }
  return { path, leafIndex: proof.leaf_index, bytes };
}

// RFC 9162 section 2.1.3.2, the `fn`/`sn` climb, ported from the Python in
// docs/API.md.
//
// Two deliberate differences from that script, both from the RFC's own text:
//
//   - step 1, `leaf_index >= tree_size` fails before anything is hashed;
//   - step 4, running out of `sn` before running out of path *fails*. The
//     script breaks out of the loop instead, and then its final `sn == 0` test
//     passes, so a valid proof with junk appended to it is accepted. Nothing is
//     forged by that, but a verifier that accepts a proof it did not consume is
//     not the verifier the RFC describes.
//
// `fn` and `sn` are divided and tested with arithmetic rather than `>>` and `&`.
// JavaScript's bitwise operators truncate to 32 bits, and a log of more than
// 2,147,483,647 messages is a size this sequencer's u64 ids allow; `/ 2` and
// `% 2` stay exact to 2^53.
async function verifyInclusion(leafBytes, leafIndex, treeSize, path, rootHex) {
  if (leafIndex >= treeSize) {
    throw new ProofFailure("the tree covers this message",
      "Leaf " + leafIndex + " is not inside a tree of " + treeSize + " leaves.");
  }
  let r = await sha256(LEAF_PREFIX, leafBytes);
  let fn = leafIndex;
  let sn = treeSize - 1;
  for (const p of path) {
    if (sn === 0) {
      throw new ProofFailure("the length of the proof",
        "The proof carries " + path.length + " hashes and the climb to the root of a tree of " +
        treeSize + " used fewer. A proof this page did not consume is a proof it cannot vouch for.");
    }
    if (fn % 2 === 1 || fn === sn) {
      r = await sha256(NODE_PREFIX, p, r);
      while (fn !== 0 && fn % 2 === 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      r = await sha256(NODE_PREFIX, r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  const root = toHex(r);
  if (sn !== 0) {
    throw new ProofFailure("the length of the proof",
      "The proof ran out " + sn + (sn === 1 ? " level" : " levels") + " below the root of a tree of " +
      treeSize + " leaves.");
  }
  if (root !== rootHex) {
    throw new ProofFailure("the recomputed root",
      "Hashing this message with this proof gives " + root + ". The sequencer signed " + rootHex +
      " for this tree. So the sequencer's own signature says this message is not the message at " +
      "leaf " + leafIndex + ".");
  }
  return { root };
}

// ---------------------------------------------------------------------------
// The log only grew: RFC 9162 section 2.1.4.2
// ---------------------------------------------------------------------------
//
// This is the step that makes an inclusion proof worth more than the operator's
// signature. A consistency proof says: the tree of size `first` with root
// `firstHash` is a PREFIX of the tree of size `second` with root `secondHash`.
// Entries were appended and never changed, removed or reordered.
//
// Give it a `firstHash` that came off a public chain and the operator is boxed
// in. They can serve whatever `secondHash` they like; it is their own number,
// signed by their own key. But the only `secondHash` they can produce a
// consistency proof for is one whose first `first` leaves are the leaves the
// chain already committed to. Producing another needs a SHA-256 collision.
//
// So the root the inclusion proof below is checked against is not the
// operator's word any more. It is the chain's value, carried forward.
//
// Ported from anchor/merkle.go, which is the sender's own transcription of the
// same section, step by step. services/src/merkle.rs is a third. All three fail
// on a path that is longer than the climb (step 6(a)) and on one that is
// shorter (step 7), the shape docs/API.md's published inclusion script got
// wrong, where a `break` where the RFC says FAIL let a padded proof through.

// MTH({}) = HASH(), the hash of nothing at all. Only the `first === 0` case
// needs it, and that case is outside the RFC's own range.
let emptyRootHex = null;
async function emptyTreeRoot() {
  if (!emptyRootHex) emptyRootHex = toHex(await sha256(new Uint8Array(0)));
  return emptyRootHex;
}

// `n` is a power of two, without `&`. `n & (n - 1)` is the usual test and it is
// wrong above 2,147,483,647, because JavaScript's bitwise operators truncate to
// 32 bits, the same reason the climb below divides instead of shifting.
function isPowerOfTwo(n) {
  if (!Number.isSafeInteger(n) || n < 1) return false;
  while (n > 1) {
    if (n % 2 !== 0) return false;
    n /= 2;
  }
  return true;
}

// Throws naming the step, or returns the number of hashes it computed.
//
// Three failures are told apart on purpose. A proof of the wrong length is a
// broken or padded answer. A first root that does not rebuild is the operator
// serving a history that does not contain the one on the chain, the loudest
// thing this page can find. A second root that does not rebuild is a proof that
// does not reach the head they signed.
async function verifyConsistency(first, second, firstHex, secondHex, path) {
  // Outside the RFC. A consistency proof only runs forwards.
  if (first > second) {
    throw new ProofFailure("the direction of the proof",
      "This page asked whether a tree of " + fmtN(first) + " leaves grew into one of " +
      fmtN(second) + ". A log cannot shrink, so there is nothing here to check.");
  }
  // Outside the RFC. The empty tree is a prefix of every tree, so there is
  // nothing to prove; but firstHex must really be the empty tree's root.
  if (first === 0) {
    if (path.length !== 0 || firstHex !== (await emptyTreeRoot())) {
      throw new ProofFailure("the empty tree",
        "A proof from an empty tree carries no hashes and starts at the hash of nothing.");
    }
    return 0;
  }
  // Outside the RFC. The same tree twice: nothing to prove, but the two heads
  // must be the same head.
  if (first === second) {
    if (path.length !== 0 || firstHex !== secondHex) {
      throw new ProofFailure("the two heads at one size",
        "The chain holds " + firstHex + " for " + fmtN(first) + " messages and the sequencer serves " +
        secondHex + " for the same " + fmtN(second) + ". At one size there is one root, so these " +
        "are two different histories.");
    }
    return 0;
  }
  // Step 1.
  if (path.length === 0) {
    throw new ProofFailure("the length of the proof",
      "A tree of " + fmtN(first) + " leaves growing into one of " + fmtN(second) + " needs a proof, " +
      "and the sequencer sent none.");
  }
  // Step 2. A `first` that is a power of two means the old tree is itself a
  // perfect subtree of the new one, so the log does not send that node: the
  // verifier already holds it as the root off the chain.
  const full = isPowerOfTwo(first) ? [fromHex(firstHex), ...path] : path.slice();
  // Step 3.
  let fn = first - 1;
  let sn = second - 1;
  // Step 4. Climb out of the old tree's own right edge before the two trees are
  // compared.
  while (fn % 2 === 1) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
  // Step 5. Both rebuilds start from the same node. That shared start is what
  // makes one proof say something about two trees.
  let fr = full[0];
  let sr = full[0];
  let hashes = 0;
  // Step 6.
  for (const c of full.slice(1)) {
    // Step 6(a). A proof longer than the climb is refused HERE, not folded in
    // and then let through by a final test that happens to pass.
    if (sn === 0) {
      throw new ProofFailure("the length of the proof",
        "The proof carries " + path.length + " hashes and the climb from " + fmtN(first) + " to " +
        fmtN(second) + " leaves used fewer. A proof this page did not consume is a proof it cannot " +
        "vouch for.");
    }
    if (fn % 2 === 1 || fn === sn) {
      // Steps 6(b)(i) and 6(b)(ii). This node is in both trees, so it feeds
      // both rebuilds.
      fr = await sha256(NODE_PREFIX, c, fr);
      sr = await sha256(NODE_PREFIX, c, sr);
      hashes += 2;
      // Step 6(b)(iii).
      while (fn !== 0 && fn % 2 === 0) { fn = Math.floor(fn / 2); sn = Math.floor(sn / 2); }
    } else {
      // Step 6(b), "Otherwise", (i). This node covers entries the old tree did
      // not have, so it feeds the new root only.
      sr = await sha256(NODE_PREFIX, sr, c);
      hashes += 1;
    }
    // Step 6(c).
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  // Step 7. A proof that ran out before the root is refused as well as one that
  // ran past it.
  if (sn !== 0) {
    throw new ProofFailure("the length of the proof",
      "The proof ran out " + sn + (sn === 1 ? " level" : " levels") + " below the root of a tree of " +
      fmtN(second) + " leaves.");
  }
  const rebuiltFirst = toHex(fr);
  const rebuiltSecond = toHex(sr);
  if (rebuiltFirst !== firstHex) {
    throw new ProofFailure("the anchored root",
      "This proof rebuilds " + rebuiltFirst + " for the first " + fmtN(first) + " messages. The " +
      "anchored root is " + firstHex + ". So the log this sequencer serves does not contain the log " +
      "that was committed to the chain.");
  }
  if (rebuiltSecond !== secondHex) {
    throw new ProofFailure("the current root",
      "This proof rebuilds " + rebuiltSecond + " for " + fmtN(second) + " messages and the sequencer " +
      "serves " + secondHex + ". The proof does not reach the head it was asked about.");
  }
  return hashes;
}

// `GET /proof/consistency`, with every number in the answer checked against
// what was asked for. Like the inclusion proof it carries no root and no
// signature, deliberately: both roots are already held, one off the chain, one
// out of the signed tree head.
async function readConsistencyProof(first, second, session) {
  const url = feedUrl + "/proof/consistency?first=" + first + "&second=" + second;
  let res;
  try {
    res = await fetch(url);
  } catch (e) {
    throw new ProofFailure("reading the consistency proof",
      "The browser cannot reach the sequencer at " + feedUrl + ".");
  }
  if (!res.ok) {
    const detail = (await res.text()).trim();
    throw new ProofFailure("reading the consistency proof",
      "The sequencer answered " + res.status + " for the proof that " + fmtN(first) + " messages " +
      "grew into " + fmtN(second) + (detail ? ". " + detail : "."));
  }
  const text = await res.text();
  const bytes = encode(text).length;
  let proof;
  try {
    proof = JSON.parse(text);
  } catch (e) {
    throw new ProofFailure("reading the consistency proof",
      "GET /proof/consistency did not answer with JSON.");
  }
  if (proof.session !== session) {
    throw new ProofFailure("the proof answers the question that was asked",
      "The proof names history " + String(proof.session) + " and this check is about history " +
      String(session) + ".");
  }
  if (proof.first !== first || proof.second !== second) {
    throw new ProofFailure("the proof answers the question that was asked",
      "This page asked how " + fmtN(first) + " messages grew into " + fmtN(second) + ". The answer " +
      "is about " + String(proof.first) + " and " + String(proof.second) + ".");
  }
  const path = [];
  for (const node of proof.consistency_path || []) {
    const bytes32 = fromHex(String(node));
    if (!bytes32 || bytes32.length !== 32) {
      throw new ProofFailure("the shape of the consistency proof",
        "A proof is a list of 32 byte hashes as lower case hex. This one holds " + String(node) + ".");
    }
    path.push(bytes32);
  }
  return { path, bytes };
}

// ---------------------------------------------------------------------------
// The whole chain of trust, in about a kilobyte
// ---------------------------------------------------------------------------
//
//   1. the anchored root at tree size N, read out of the contract on the chain.
//      The operator cannot change it and did not answer for it.
//   2. a consistency proof N -> M. The log only grew.
//   3. an inclusion proof for the message at size M, against the root step 2
//      carried forward.
//
// That is section 8 of the Bitcoin whitepaper: a client that holds one header
// off a chain it does not run, and a path. It is what RFC 9162
// consistency proofs are for.
//
// What each step costs is measured and printed, because the point of this over
// the whole-window fold is the size of it and a number nobody counted is not
// evidence of that.

// The anchored root to check a message against, and where it came from.
//
// `latest()` is read fresh on every check rather than taken from the strip's
// minute timer. This is the value the whole claim rests on and it should be one
// this browser asked the chain for while the visitor was watching.
//
// Which anchor is then used is a separate question, and the answer is the
// OLDEST one on this contract that already covers the message, not the newest.
// Both are roots the operator cannot change; the older one has been on the
// chain longer, and "committed an hour ago" is a stronger sentence than
// "committed a minute ago". It also has to be the one the line above the button
// names, or the page would claim a block in one sentence and another in the
// next. When the log scan has found no covering entry, including for an order
// no anchor has reached yet, this falls back to the newest, which is what
// `latest()` just returned.
async function readAnchoredRoot(messageId) {
  if (!anchorConfig) {
    throw new ProofFailure("reading the anchor contract",
      "This exchange is anchored to nothing, so there is no root on a chain to check against.");
  }
  let latest;
  try {
    latest = decodeLatest(await rpc("eth_call",
      [{ to: anchorConfig.address, data: LATEST_SELECTOR }, "latest"]));
  } catch (e) {
    throw new ProofFailure("reading the anchored root from " + anchorConfig.chain_name, e.message);
  }
  const bytes = lastRpcBytes;
  if (latest.kind !== "root") {
    throw new ProofFailure("the kind of anchor this contract holds",
      "The contract at " + anchorConfig.address + " commits a chain hash over every message, not a " +
      "Merkle root. A proof cannot be checked against it. Checking one trade against that value " +
      "needs every message of the window.");
  }
  if (!latest.count) {
    throw new ProofFailure("the anchored root",
      "Nobody has written an anchor to " + anchorConfig.address + " yet, so there is no root on " +
      anchorConfig.chain_name + " to check against.");
  }
  anchorLatest = latest;
  anchorDown = null;
  // The block comes from the log entry, when the scan has reached it. It is the
  // number worth printing; a block is a thing a reader can look up on an
  // explorer this operator does not run. And it is not worth an extra
  // eth_getLogs when the view already scans the logs as it opens.
  let use = anchors.find((a) => a.kind === "root" && a.treeSize === latest.treeSize &&
    a.rootHash === latest.rootHash) || { ...latest, block: null, tx: null };
  for (const a of anchors) {
    if (a.kind !== "root" || a.treeSize < messageId) continue;
    if (use.count == null || a.count < use.count) use = a;
  }
  return {
    treeSize: use.treeSize, rootHash: use.rootHash, session: use.session,
    anchoredAt: use.anchoredAt, count: use.count,
    block: use.block ?? null, tx: use.tx ?? null,
    // The contract's own tally, always from the fresh read, so "anchor 3 of 8"
    // is the chain's count and not the count of what this browser loaded.
    total: latest.count, newestTreeSize: latest.treeSize, bytes,
  };
}

// One message, checked against the root on the chain. Every step is named, so a
// failure says which one, and nothing after a failed step runs.
async function checkAgainstChain(messageId, onStep) {
  if (!feedUrl) {
    throw new ProofFailure("reading the sequencer",
      "Nobody told this page where the sequencer is. It cannot read the messages.");
  }
  const began = performance.now();
  onStep("reading the anchored root from " + anchorConfig.chain_name);
  const anchored = await readAnchoredRoot(messageId);

  onStep("checking the signature on the tree head");
  const head = await readSignedTreeHead();
  const sth = head.sth;
  // The session check, before any hashing. Sizes and roots restart when a log
  // is replaced, so a proof from another history is not a failed check, it is a
  // check about something else.
  if (sth.session !== anchored.session) {
    throw new ProofFailure("the history the sequencer serves",
      anchorConfig.chain_name + " holds an anchor for history " + anchored.session +
      " and this sequencer serves history " + sth.session + ". A session changes when somebody " +
      "replaces the log. So nothing this sequencer serves can be checked against that anchor.");
  }
  if (sth.tree_size < anchored.treeSize) {
    throw new ProofFailure("the sequencer is behind its own anchor",
      anchorConfig.chain_name + " holds a commitment to " + fmtN(anchored.treeSize) + " messages " +
      "and this sequencer only offers " + fmtN(sth.tree_size) + ". A log cannot shrink.");
  }
  if (messageId > sth.tree_size) {
    throw new ProofFailure("the tree covers this message",
      "The signed tree head covers " + fmtN(sth.tree_size) + " messages and this one is #" +
      fmtN(messageId) + ". The sequencer has not put it in the tree yet. Try again in a moment.");
  }

  onStep("checking that the log only grew");
  const consistency = await readConsistencyProof(anchored.treeSize, sth.tree_size, sth.session);
  await verifyConsistency(
    anchored.treeSize, sth.tree_size, anchored.rootHash, sth.root_hash, consistency.path);

  onStep("reading the message");
  const message = await readMessageBytes(messageId);
  onStep("reading the inclusion proof");
  const proof = await readInclusionProof(messageId, sth);
  onStep("hashing the proof");
  await verifyInclusion(message.line, proof.leafIndex, sth.tree_size, proof.path, sth.root_hash);

  const hashes = consistency.path.length + proof.path.length;
  return {
    anchored,
    // Inside the tree the chain committed to, rather than only inside a tree
    // that provably extends it. The two are different claims and the page must
    // not print the first when it has the second.
    covered: proof.leafIndex < anchored.treeSize,
    session: sth.session,
    treeSize: sth.tree_size,
    timestamp: sth.timestamp,
    publicKey: sth.public_key,
    root: sth.root_hash,
    leafIndex: proof.leafIndex,
    consistencyHashes: consistency.path.length,
    inclusionHashes: proof.path.length,
    hashes,
    proofBytes: hashes * 32,
    downloaded: anchored.bytes + head.bytes + consistency.bytes + message.bytes + proof.bytes,
    requests: 5,
    ms: performance.now() - began,
  };
}

// The whole check for one message: head, message, proof, climb. Every step is
// named, so a failure says which one, and nothing after a failed step runs.
//
// `hashes` is the number of node hashes in the proof, which is the figure RFC
// 9162 calls the proof length and the one worth comparing against the fold.
// `downloaded` is what the three requests actually weighed, measured from the
// bodies that arrived rather than assumed here.
async function checkInclusion(messageId, onStep) {
  if (!feedUrl) {
    throw new ProofFailure("reading the sequencer",
      "Nobody told this page where the sequencer is. It cannot read the messages.");
  }
  const began = performance.now();
  onStep("checking the signature on the tree head");
  const head = await readSignedTreeHead();
  const sth = head.sth;
  if (messageId > sth.tree_size) {
    throw new ProofFailure("the tree covers this message",
      "The signed tree head covers " + fmtN(sth.tree_size) + " messages and this one is #" +
      fmtN(messageId) + ". The sequencer has not put it in the tree yet. Try again in a moment.");
  }
  onStep("reading the message");
  const message = await readMessageBytes(messageId);
  onStep("reading the proof");
  const proof = await readInclusionProof(messageId, sth);
  onStep("hashing the proof");
  const checked = await verifyInclusion(
    message.line, proof.leafIndex, sth.tree_size, proof.path, sth.root_hash);
  return {
    session: sth.session,
    treeSize: sth.tree_size,
    timestamp: sth.timestamp,
    publicKey: sth.public_key,
    root: checked.root,
    leafIndex: proof.leafIndex,
    hashes: proof.path.length,
    proofBytes: proof.path.length * 32,
    downloaded: head.bytes + message.bytes + proof.bytes,
    requests: 3,
    ms: performance.now() - began,
  };
}

// ---------------------------------------------------------------------------
// What a verification costs, said before it is started
// ---------------------------------------------------------------------------
//
// One anchor is one window of the feed, the messages between the anchor before
// it and this one, and on this contract those windows are not the same size.
// The sender started when the feed had already reached message 13,774, so the
// first anchor covers all of them and every anchor after it covers about six
// hundred. That is 1.7 MB and 14 requests against 75 KB and one, and it is a
// permanent property of this contract rather than a phase it will grow out of.
// A visitor who clicks the first expecting the second gets seven seconds of a
// page that looks like it has hung, and the matcher serves fourteen paged reads
// out of SQLite for a click nobody knew they were making.
//
// So: every row says what it will cost before it is clicked, a window over
// CONFIRM_OVER messages asks first, and "verify all" states the total and asks
// once. Nothing here caps or samples the fold. A partial check that reported
// success would be worth less than no check at all, which is the whole reason
// this page exists.

// Bytes per message on the wire, until this browser has fetched a page and can
// use the real figure. Measured on the running demo: 1.70 MB over
// /messages.ndjson for the 13,774 messages of anchor #1, which is 123 bytes a
// message. It is a starting estimate for this feed, not a constant about feeds.
const FEED_BYTES_PER_MESSAGE = 123;
// Messages a second, until this browser has folded some and knows its own rate.
// Same run: the 13,774 messages of anchor #1 took about seven seconds end to
// end, requests and SHA-256 together, which is 2,000 a second. It is only ever
// used to keep a long wait from reading as a hung tab, and it is replaced by
// what this machine and this network actually do as soon as there is a figure.
// The same fold against a feed on localhost runs ten times faster, and telling
// someone "about seven seconds" for something that takes one is its own kind of
// wrong.
const FOLD_RATE = 2000;
// Above this many messages, a verification asks before it starts. At the
// numbers above that is roughly a quarter of a megabyte and a second, the
// point where a click stops being instant. It leaves the ordinary anchor on
// this contract, about 620 messages, a single click, which is the common case
// and has to stay one.
const CONFIRM_OVER = 2000;

// The bytes and messages this browser has actually pulled from the feed.
let feedBytes = null;
function noteFeedBytes(bytes, messages) {
  if (!messages) return;
  feedBytes = feedBytes
    ? { bytes: feedBytes.bytes + bytes, messages: feedBytes.messages + messages }
    : { bytes, messages };
}
// The measured figure once there is one. This counts the bytes the fetch handed
// over, so on a feed that compresses its answers the estimate is above what the
// network carries, never below.
const bytesPerMessage = () =>
  feedBytes ? feedBytes.bytes / feedBytes.messages : FEED_BYTES_PER_MESSAGE;

// The same for the clock: what the folds this tab has run actually managed,
// once there is enough of one to divide by. Fetching and hashing together,
// because that is what the wait is.
let feedFold = null;
function noteFold(messages, ms) {
  if (messages < 200 || ms <= 0) return;
  feedFold = feedFold
    ? { messages: feedFold.messages + messages, ms: feedFold.ms + ms }
    : { messages, ms };
}
const foldRate = () => (feedFold ? feedFold.messages / (feedFold.ms / 1000) : FOLD_RATE);

const fmtSize = (bytes) =>
  bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(bytes / 1024)) + " KB";
// The same, for the figures a proof produces. `fmtSize` rounds everything below
// half a kilobyte up to "1 KB", and 544 bytes rounded to "1 KB" beside 1.7 MB
// throws away the part of the comparison that is worth reading.
// The cut-off is 4 KB rather than 1 KB because the figures this prints are
// proofs and the five small reads around them, and every one of them lands
// between half a kilobyte and three. "1 KB" for 1,056 bytes throws away the
// digits that make the comparison with a 13 MB fold worth printing at all.
const fmtBytes = (bytes) => bytes < 4096 ? fmtN(Math.round(bytes)) + " bytes" : fmtSize(bytes);
// Seconds, in words. `fmtSecs` above is the separate service's own, and takes
// milliseconds.
const fmtHowLong = (s) =>
  s < 1.5 ? "under a second" : s < 90 ? "about " + Math.round(s) + " seconds" : "about " + Math.round(s / 60) + " minutes";

// What checking this one anchor would cost, or null when it cannot be checked
// at all because the anchor before it has not been loaded.
function anchorCost(a) {
  const win = anchorWindow(a);
  if (!win) return null;
  const messages = a.lastId - win.fromId;
  return { messages, bytes: messages * bytesPerMessage(), seconds: messages / foldRate() };
}

// The same for every loaded anchor that can be checked.
function verifyAllCost() {
  let messages = 0;
  let rows = 0;
  for (const a of anchors) {
    const c = anchorCost(a);
    if (c) { messages += c.messages; rows++; }
  }
  return { rows, messages, bytes: messages * bytesPerMessage(), seconds: messages / foldRate() };
}

const costLine = (c) => `${fmtN(c.messages)} messages · about ${fmtSize(c.bytes)} · ${fmtHowLong(c.seconds)}`;

// Thrown when a verification was stopped from the page. Not a failure: nothing
// disagreed, the work was called off, and the two must not read the same.
class VerifyStopped extends Error {}

// The verification in flight, or null. One at a time. The button that started
// it is disabled while it runs, so one holder is enough.
let verifyRun = null;
function startRun() {
  verifyRun = { ctrl: new AbortController(), cancelled: false };
  return verifyRun;
}
// Stops the fold between pages AND aborts the request already in the air, so
// cancelling stops the bytes rather than only the report at the end.
function cancelRun() {
  if (!verifyRun) return;
  verifyRun.cancelled = true;
  verifyRun.ctrl.abort();
}
const stopped = (e) => e instanceof VerifyStopped || e.name === "AbortError";

async function verifyAnchor(a, report, onCount, sharedHead) {
  // A root anchor is checked with a proof, not with a fold. One entry point, so
  // the row click, "check every anchor" and the order's own button all reach
  // whichever check this anchor's kind can actually answer.
  if (a.kind === "root") return verifyRootAnchor(a, report, sharedHead);
  const win = anchorWindow(a);
  if (!win) {
    report(`<span class="neg">This browser cannot check this anchor yet.</span> The window starts ` +
      `where anchor #${a.count - 1} ended. This browser did not load anchor #${a.count - 1}. Use ` +
      `"load older anchors" below first.`);
    return false;
  }
  const span = a.lastId - win.fromId;
  // "Verify all" owns the run while it is the caller, so that one stop stops
  // the whole sequence; a single row starts its own and clears it at the end.
  const owned = !verifyRun;
  const run = verifyRun || startRun();
  let done = 0;
  report(`hashing <b class="ax-n">0</b> of ${fmtN(span)} messages ` +
    `(#${fmtN(win.fromId + 1)} to #${fmtN(a.lastId)}). ` +
    `<button class="go" data-verify-stop="1">stop</button>`);
  // Written once; after this only the number is replaced. Rewriting the line
  // would rebuild the stop button several times a second, and a button replaced
  // under the pointer between the press and the release is a click the page
  // never sees, on the one control whose whole job is to be clicked in a hurry.
  const counter = document.querySelector(`#ax-result-${a.count} .ax-n`);
  let out;
  try {
    out = await foldFeed(win.fromId, a.lastId, win.startHash, (n) => {
      done = n;
      if (counter) counter.textContent = fmtN(n);
      if (onCount) onCount(n);
    }, run);
  } catch (e) {
    if (stopped(e)) {
      report(`<span class="dim">Stopped.</span> This browser hashed ${fmtN(done)} of ${fmtN(span)} ` +
        `messages. A check that stops early proves nothing. So this page claims nothing.`);
    } else {
      report(`<span class="neg">This browser could not check this anchor.</span> ${escapeText(e.message)}`);
    }
    return null;
  } finally {
    if (owned && verifyRun === run) verifyRun = null;
  }
  const match = out.hash === a.chainHash;
  const where = win.prev
    ? `messages #${fmtN(win.fromId + 1)} to #${fmtN(a.lastId)}, from the chain hash of anchor #${win.prev.count}`
    : `messages #1 to #${fmtN(a.lastId)}, from 32 zero bytes`;
  if (match) {
    report(`<span class="pos">The hashes match.</span> This browser hashed ${fmtN(out.messages)} ` +
      `messages again (${where}). The result is <span class="mono">${out.hash}</span>. ` +
      `${escapeText(anchorConfig.chain_name)} holds that same chain hash for this anchor since ` +
      `${fmtUTC(a.anchoredAt, true)}.`);
  } else {
    report(`<span class="neg">The hashes do not match.</span> This browser hashed ` +
      `${fmtN(out.messages)} messages again (${where}).<br>` +
      `<span class="mono">this browser ${out.hash}</span><br>` +
      `<span class="mono">on the chain ${a.chainHash}</span><br>` +
      `The sequencer serves a different log for messages #${fmtN(win.fromId + 1)} to ` +
      `#${fmtN(a.lastId)}. ${escapeText(anchorConfig.chain_name)} holds the other log since block ` +
      `${fmtN(a.block)}. The difference is inside that window.`);
  }
  return match;
}

// The click on "verify all anchors". While one is running it is the stop; the
// rest of the time it puts the total on screen and waits to be told to go, so
// nobody starts a multi-megabyte sequence without having seen the number.
function verifyAllClicked() {
  if (verifying) { cancelRun(); return; }
  // One fold at a time. A single row already folding has its own progress line
  // and its own stop, and starting the sequence on top of it would leave two
  // things writing into the same rows.
  if (verifyRun || !anchors.length) return;
  // Root anchors are proofs. Every row is about seventeen hashes and half a
  // kilobyte, so there is nothing to warn anybody about and the confirmation
  // that exists for the megabyte folds would only be in the way.
  if (isRootAnchored()) { verifyAllAnchors(); return; }
  const c = verifyAllCost();
  const el = document.getElementById("ax-confirm");
  if (!c.messages) { el.innerHTML = ""; return; }
  el.innerHTML =
    `<p><b>${c.rows} anchors. ${costLine(c)}.</b> This tab reads every message from the window of the ` +
    `first loaded anchor to the newest anchor. It hashes them again here. The count covers every ` +
    `window. This page never samples and never skips a message. A check of some messages that ` +
    `reports a match is worth less than no check. ` +
    `<button class="go" id="ax-all-go">check all ${c.rows} anchors</button> ` +
    `<button class="linkish" id="ax-all-off">not now</button></p>`;
  document.getElementById("ax-all-go").onclick = () => verifyAllAnchors();
  document.getElementById("ax-all-off").onclick = () => { el.innerHTML = ""; };
}

// Every anchor, oldest first, each against its own on-chain start hash rather
// than against the hash the previous row computed. Chained, one broken anchor
// would make every anchor after it fail too and the screen would say nothing
// about where the history actually changed; independent, the earliest failing
// row is the answer.
async function verifyAllAnchors() {
  if (verifying || verifyRun || !anchors.length) return;
  verifying = true;
  const run = startRun();
  const button = document.getElementById("ax-verify-all");
  const note = document.getElementById("ax-confirm");
  const total = verifyAllCost();
  button.textContent = "stop";
  const order = anchors.slice().sort((a, b) => a.count - b.count);
  // One tree head for the whole sequence on a root-anchored deployment. Each
  // row is still checked against its own root off the chain; that is the half
  // that must not be shared. Only the head the rows are carried forward to is
  // read once.
  let sharedHead = null;
  if (isRootAnchored()) {
    note.innerHTML = `<p>reading the tree head the sequencer serves now…</p>`;
    try {
      sharedHead = await readSignedTreeHead();
    } catch (e) {
      verifying = false;
      verifyRun = null;
      button.textContent = "check every anchor";
      note.innerHTML = `<p><span class="neg">This browser could not read the tree head.</span> ` +
        `${escapeText(e.message)} No anchor was checked.</p>`;
      return;
    }
  }
  let firstBad = null;
  let checked = 0;
  let folded = 0;      // messages folded in the anchors already finished
  // The line is built once and only its text is replaced, so the stop button
  // survives every update. See the same point in `verifyAnchor`.
  note.innerHTML = `<p><span id="ax-all-at"></span> · ` +
    `<button class="go" id="ax-all-stop">stop</button></p>`;
  document.getElementById("ax-all-stop").onclick = () => cancelRun();
  const at = document.getElementById("ax-all-at");
  // The count has to move inside an anchor, not only between them: the first
  // anchor on this contract is 13,774 of the 17,374 messages, and a line that
  // only stepped on completion would read "0 of 17,374" for the whole of it.
  const line = (a, i, doneNow) => {
    at.innerHTML = `checking anchor #${a.count}, ${i + 1} of ${order.length}` +
      (total.messages ? ` · <b>${fmtN(doneNow)} of ${fmtN(total.messages)} messages hashed</b>` : "");
  };
  for (const [i, a] of order.entries()) {
    if (run.cancelled) break;
    const c = anchorCost(a);
    line(a, i, folded);
    const ok = await verifyAnchor(
      a, (html) => reportOn(a, html), (n) => line(a, i, folded + n), sharedHead);
    if (c) folded += c.messages;
    if (ok === true) checked++;
    if (ok === false && firstBad === null) firstBad = a;
  }
  const wasCancelled = run.cancelled;
  verifyRun = null;
  button.textContent = "check every anchor";
  verifying = false;
  if (wasCancelled) {
    note.innerHTML =
      `<p><b>Stopped.</b> This browser checked ${checked} of ${order.length} anchors. It fetched ` +
      `nothing more. The rows that finished keep their result. The other rows say nothing.</p>`;
    return;
  }
  note.innerHTML = "";
  const scan = document.getElementById("ax-scan");
  const newest = order[order.length - 1];
  const summary = firstBad
    ? `<p><b class="neg">Anchor #${firstBad.count} is the first anchor that does not match.</b> ` +
      `The log the sequencer serves below ` +
      `${firstBad.kind === "root" ? `tree size ${fmtN(firstBad.treeSize)}` : `message #${fmtN(firstBad.lastId)}`}` +
      ` differs from the log ${escapeText(anchorConfig.chain_name)} recorded at ` +
      `${fmtUTC(firstBad.anchoredAt, true)}.</p>`
    : isRootAnchored()
    ? `<p><b class="pos">All ${checked} loaded anchors are prefixes of the log served now.</b> Every ` +
      `root this contract holds, up to the tree of ${fmtN(newest.treeSize)} messages, was rebuilt in ` +
      `this browser from a proof. The contract has held them since the writer wrote them.</p>`
    : `<p><b class="pos">All ${checked} loaded anchors match.</b> Every message this sequencer serves ` +
      `up to #${fmtN(newest.lastId)} hashes to the values this contract holds. The ` +
      `contract has held them since the writer wrote them.</p>`;
  scan.insertAdjacentHTML("afterbegin", summary);
}

// One root anchor, checked with a consistency proof.
//
// The question is the same one the fold asks of a chain anchor: is the log
// this sequencer serves still the log it committed to. The answer costs
// about seventeen hashes instead of a window of messages, because the value on
// the chain is a Merkle root and not a fold.
//
// It reads the tree head fresh rather than reusing one, so a row checked twice
// is checked against where the sequencer stands twice.
async function verifyRootAnchor(a, report, sharedHead) {
  report(`reading the tree head the sequencer serves now…`);
  let head;
  let consistency;
  let hashes;
  try {
    // "Check every anchor" reads one head and checks every row against it, so a
    // hundred rows are a hundred proofs and not a hundred head requests. Every
    // row is still checked against its own root off the chain, which is the
    // part that has to stay independent.
    head = sharedHead || await readSignedTreeHead();
    const sth = head.sth;
    if (sth.session !== a.session) {
      report(`<span class="neg">This anchor is about another history.</span> The anchor names ` +
        `session <span class="mono">${escapeText(a.session)}</span> and this sequencer serves ` +
        `<span class="mono">${escapeText(sth.session)}</span>.`);
      return false;
    }
    report(`checking that ${fmtN(a.treeSize)} messages grew into ${fmtN(sth.tree_size)}…`);
    consistency = await readConsistencyProof(a.treeSize, sth.tree_size, sth.session);
    hashes = await verifyConsistency(
      a.treeSize, sth.tree_size, a.rootHash, sth.root_hash, consistency.path);
    report(`<span class="pos">The log only grew.</span> The tree of ${fmtN(a.treeSize)} messages ` +
      `this anchor holds on ${escapeText(anchorConfig.chain_name)} is a prefix of the tree of ` +
      `${fmtN(sth.tree_size)} the sequencer serves now. Checked here with ` +
      `<b>${fmtN(consistency.path.length)} hashes, ${fmtBytes(consistency.path.length * 32)}</b> ` +
      `(${fmtN(hashes)} SHA-256 calls, ${fmtBytes(head.bytes + consistency.bytes)} downloaded). ` +
      `<span class="dim">Anchored root <span class="mono">${escapeText(a.rootHash)}</span> since ` +
      `${fmtUTC(a.anchoredAt, true)}.</span>`);
    return true;
  } catch (e) {
    report(e instanceof ProofFailure
      ? `<span class="neg">This check failed at: ${escapeText(e.step)}.</span> ` +
        `${escapeText(e.message)} Nothing after that step was checked, so this page claims nothing.`
      : `<span class="neg">This browser could not check this anchor.</span> ${escapeText(e.message)}`);
    return false;
  }
}

function reportOn(a, html) {
  const el = document.getElementById("ax-result-" + a.count);
  if (el) el.innerHTML = html;
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

// The feed's own `x-feed-session`, once a verification has read one. Null until
// then, and null for good on a deployment where the header is not visible.
let feedSessionHeader = null;

// The session the feed is serving.
//
// Two sources, in order. The feed's own `x-feed-session` header is the better
// one. It arrives beside the signed head, from the service that owns the
// value. But the feed is a different origin from this page and its CORS layer
// (services/src/cors.rs) sends no `Access-Control-Expose-Headers`, so a browser
// hides that header from this script even though it is on the wire. Checked in
// Chromium against the running feed: the body reads fine, and
// `headers.get("x-feed-session")` is null.
//
// So the fallback is the matcher's `/market`, which carries `feed_session` and
// is on this page's origin. It is the same value one hop later. It is not a
// weaker check than it looks: an operator who lied about their session here
// would still fail the fold below, because the messages they serve would not
// hash to what the chain holds.
function feedSession() {
  if (feedSessionHeader) return feedSessionHeader;
  return lastMarket && lastMarket.feed_session ? String(lastMarket.feed_session) : null;
}

// The interval between anchors, from the anchors themselves.
//
// The median of the recent gaps, not the mean. A sender that is restarted
// writes one short interval and one long one; this contract has a 78 second
// gap between two 300 second ones. The mean of those is a wait that never
// happens.
function anchorInterval() {
  const times = anchors.map((a) => a.anchoredAt).sort((x, y) => x - y);
  if (times.length < 2) return null;
  const gaps = [];
  for (let i = Math.max(1, times.length - 6); i < times.length; i++) gaps.push(times[i] - times[i - 1]);
  gaps.sort((x, y) => x - y);
  return gaps[Math.floor(gaps.length / 2)];
}

// This view has an address of its own: /#anchors.
//
// It is a separate page as far as a reader is concerned. It fills the window
// and the market is gone, so the browser's back button has to come back to the
// market rather than leave the site, which is what it did while the view was a
// hidden section with no address. It also makes the view linkable, and for this
// page that is the point of it: someone can be sent a URL that opens where the
// exchange is checked, instead of being told to click the strip after they
// arrive.
//
// The hash is the state and `syncAnchors` is the only thing that reads it. Open
// and close move the hash; what is on screen follows from it.
const ANCHOR_HASH = "#anchors";

function showAnchors(on) {
  if (on === anchorsOpen) return;
  anchorsOpen = on;
  document.querySelector("main").hidden = on;
  document.getElementById("anchors").hidden = !on;
  if (!on) {
    // Both canvases were drawn into a box of zero width while this was open.
    drawChart(lastCandles);
    drawPnl();
    return;
  }
  renderAnchors();
  // Scanned on the first opening only. Reopening shows what was found; the
  // strip's own read keeps the newest number honest in the meantime.
  if (!anchorScan) loadAnchors().catch((e) => {
    anchorScan = { running: false, from: null, complete: false, note: e.message };
    renderAnchors();
  });
}

// On load, on back and forward, and on a hash typed into the address bar. Any
// other hash is not this view's business and leaves the market where it is.
function syncAnchors() {
  if (!anchorConfig) return;
  showAnchors(location.hash === ANCHOR_HASH);
}

function openAnchors() {
  if (!anchorConfig || anchorsOpen) return;
  // `ax` marks the entry as one this page pushed. Closing reads it to tell
  // "there is a market view behind this" from "this tab opened straight here".
  if (location.hash !== ANCHOR_HASH) history.pushState({ ax: 1 }, "", ANCHOR_HASH);
  showAnchors(true);
}

function closeAnchors() {
  if (!anchorsOpen) return;
  if (history.state && history.state.ax) {
    // Step back onto the entry this view was opened from, and let popstate put
    // the market up. Closing and the back button are then the same movement
    // rather than two paths that can leave the hash and the screen disagreeing.
    history.back();
    return;
  }
  // Arrived straight at /#anchors, so there is nothing of ours behind it and
  // history.back() would leave the site. The hash is dropped in place instead:
  // the address is the market's again, and back still goes wherever they came
  // from.
  history.replaceState(null, "", location.pathname + location.search);
  showAnchors(false);
}

function renderAnchors() {
  renderAnchorHeader();
  renderAnchorTable();
  renderSentOrders();
  renderAnchorScan();
  renderSelfCheck();
}

// The contract, the session check, and what an anchor is and is not evidence of.
function renderAnchorHeader() {
  if (!anchorsOpen) return;
  const chain = escapeText(anchorConfig.chain_name);
  document.getElementById("ax-title").textContent = "Anchors on " + anchorConfig.chain_name;

  const address = anchorConfig.explorer
    ? `<a href="${escapeText(anchorConfig.explorer)}/address/${escapeText(anchorConfig.address)}" ` +
      `target="_blank" rel="noopener noreferrer"><code>${escapeText(anchorConfig.address)}</code></a>`
    : `<code>${escapeText(anchorConfig.address)}</code>`;
  const parts = [
    isRootAnchored()
      ? `<p>Every few minutes this exchange writes one record into ${address} on ${chain}. The record ` +
        `holds five values: the session of the sequencer, how many messages were in its Merkle tree, ` +
        `the RFC 9162 root over those messages, the message its state database had reached, and the ` +
        `state root at that message. Only <code>${escapeText(anchorConfig.writer)}</code> can write to ` +
        `the contract. The contract refuses a tree smaller than the tree it holds. This browser read ` +
        `everything below from ${chain} over ${escapeText(rpcAnswering())}. The exchange did not ` +
        `answer any of it.</p>` +
        `<p><b>Why a root and not a chain hash.</b> Showing that one trade sits inside a chain hash ` +
        `needs every message it was folded over. Showing that one trade sits inside a Merkle root ` +
        `needs about seventeen node hashes. So on this contract a trade is checked against the chain ` +
        `in a kilobyte, in this browser, and the megabyte fold is no longer the only way in.</p>`
      : `<p>Every few minutes this exchange writes one record into ${address} on ${chain}. The record ` +
        `holds four values: the session of the sequencer, the last message number, the SHA-256 chain ` +
        `hash over messages 1 to that message, and the state root of the exchange. Only ` +
        `<code>${escapeText(anchorConfig.writer)}</code> can write to the contract. The contract refuses ` +
        `a message number lower than the number it holds. This browser read everything below from ` +
        `${chain} over ${escapeText(rpcAnswering())}. The exchange did not answer any of it.</p>` +
        `<p>This contract commits a <b>chain hash</b>: SHA-256 folded over every message. There is no ` +
        `short proof against a fold, so every check below reads a whole window of messages. A ` +
        `deployment anchored to an <code>ExchangeRootAnchor</code> instead commits a Merkle root, and ` +
        `one trade is then checked against the chain with about seventeen hashes.</p>`,
  ];
  if (anchorLatest && !anchorLatest.count) {
    parts.push(`<p><b>No anchor exists yet.</b> The contract is at block ` +
      `${fmtN(anchorConfig.deployed_block)} and its counter is zero. There is nothing on ${chain} to ` +
      `check this log against. The list below grows when the sender writes an anchor.</p>`);
  }
  parts.push(`<p><b>What an anchor proves.</b> The operator committed to this exact log at the time ` +
    `of that block. The operator cannot change the log now. A change contradicts a record the ` +
    `operator does not control. <b>What an anchor does not prove.</b> It does not prove that the ` +
    `matching was correct. An operator who is dishonest from message 1 can anchor a dishonest log. ` +
    `To check the matching, run <code>--audit-url</code>. See below.</p>`);
  document.getElementById("ax-where").innerHTML = parts.join("");

  // The session check. The contract fixes its session on the first anchor and
  // reverts any write carrying another, so every anchor here belongs to one
  // feed history by construction. A feed serving a different session is
  // therefore not a disagreement between anchors. It is this exchange serving
  // a history that is not the one it committed to.
  const alarm = document.getElementById("ax-alarm");
  const feed = feedSession();
  const onChain = anchors.length ? anchors[0].session : anchorLatest && anchorLatest.count ? anchorLatest.session : null;
  if (feed && onChain && feed !== onChain) {
    alarm.innerHTML =
      `<div class="what">This exchange serves a different log from the log it anchored.</div>` +
      `<div class="why">${chain} holds ${anchors.length || anchorLatest.count} anchors for session ` +
      `<span class="mono">${escapeText(onChain)}</span>. The sequencer in front of you serves session ` +
      `<span class="mono">${escapeText(feed)}</span>. A session changes when somebody replaces the log ` +
      `of the sequencer. The message numbers then restart at 1, and so does ` +
      `${isRootAnchored() ? "the tree the roots below were taken from" : "the chain hash"}. So the ` +
      `anchors on this page describe a log that this exchange does not serve now. You cannot check ` +
      `anything below against this sequencer.</div>`;
  } else {
    alarm.innerHTML = "";
  }
}

function hashCell(hex) {
  return `<button class="copy" data-full="${escapeText(hex)}" title="${escapeText(hex)}. Click to copy it.">` +
    `${escapeText(hex.slice(0, 12))}…</button>`;
}

function renderAnchorTable() {
  if (!anchorsOpen) return;
  const count = anchorLatest ? anchorLatest.count : 0;
  document.getElementById("ax-count").textContent =
    count ? `${anchors.length} of ${count} loaded` : "";
  document.getElementById("ax-verify-all").hidden = anchors.length === 0;

  // The two contracts hold different values, so the columns are not the same
  // columns. A header that said "chain hash" over a Merkle root would be the
  // page telling a reader something the chain does not say.
  document.getElementById("ax-head").innerHTML = isRootAnchored()
    ? `<span>#</span><span>written at (UTC)</span><span class="num">messages in the tree</span>` +
      `<span>Merkle root</span><span>state root</span><span class="num">block</span><span></span>`
    : `<span>#</span><span>written at (UTC)</span><span class="num">up to message</span>` +
      `<span>chain hash</span><span>state root</span><span class="num">block</span><span></span>`;

  const rows = document.getElementById("ax-rows");
  if (!anchors.length) {
    rows.innerHTML = `<div class="row"><span class="dim">${
      anchorScan && anchorScan.running ? "This browser is reading the chain."
        : count ? "No anchor is loaded yet."
        : "Nobody wrote an anchor to this contract yet."
    }</span></div>`;
    return;
  }
  // A verification already on screen survives the table being redrawn. The scan
  // redraws after every window it reads, and without this a result a visitor
  // waited on would be wiped by an older anchor arriving behind it.
  const shown = new Map();
  for (const el of rows.querySelectorAll(".ax-result")) {
    if (el.innerHTML) shown.set(el.id, el.innerHTML);
  }
  rows.innerHTML = anchors.map((a) => {
    const tx = anchorConfig.explorer
      ? `<a href="${escapeText(anchorConfig.explorer)}/tx/${escapeText(a.tx)}" target="_blank" ` +
        `rel="noopener noreferrer" title="${escapeText(a.tx)}">${fmtN(a.block)}</a>`
      : `<span title="${escapeText(a.tx)}">${fmtN(a.block)}</span>`;
    // What this row's verify will cost, on the button itself. A row whose
    // window is only a few hundred messages runs on the click; one over
    // CONFIRM_OVER asks first. See the `[data-verify]` branch in the click
    // handler at the bottom of this section.
    const cost = anchorCost(a);
    const verify = a.kind === "root"
      ? `<button class="linkish" data-verify="${a.count}" title="Asks the sequencer for a proof that ` +
        `its tree of ${fmtN(a.treeSize)} messages grew into the tree it serves now, and rebuilds ` +
        `both roots here. About ${Math.ceil(Math.log2(Math.max(2, a.treeSize)))} hashes and half a ` +
        `kilobyte. It reads no message.">check · a proof · under 1 KB</button>`
      : cost
      ? `<button class="linkish" data-verify="${a.count}" title="Messages #${fmtN(a.lastId - cost.messages + 1)}` +
        ` to #${fmtN(a.lastId)}. This page reads them from the sequencer and hashes them again here. ` +
        `${costLine(cost)}.">check · ${fmtN(cost.messages)} messages · ${fmtSize(cost.bytes)}</button>`
      : `<button class="linkish" data-verify="${a.count}">check</button>`;
    return `<div class="row">` +
      `<span class="mono">#${a.count}</span>` +
      `<span class="dim" title="${fmtUTC(a.anchoredAt, true)}">${fmtUTC(a.anchoredAt, false)}</span>` +
      (a.kind === "root"
        ? `<span class="num mono" title="The matcher's own cursor stood at message ${fmtN(a.lastId)} ` +
          `when this was written.">${fmtN(a.treeSize)}</span><span>${hashCell(a.rootHash)}</span>`
        : `<span class="num mono">${fmtN(a.lastId)}</span><span>${hashCell(a.chainHash)}</span>`) +
      `<span>${hashCell(a.stateRoot)}</span>` +
      `<span class="num">${tx}</span>` +
      `<span>${verify}</span>` +
      `</div>` +
      `<div class="ax-result" id="ax-result-${a.count}"></div>`;
  }).join("");
  for (const [id, html] of shown) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  const gap = anchorInterval();
  const perAnchor = anchors.length > 1
    ? Math.round((anchors[0].lastId - anchors[anchors.length - 1].lastId) / (anchors.length - 1))
    : anchors[0].lastId;
  document.getElementById("ax-why").innerHTML = isRootAnchored()
    ? `<p>Each row holds the RFC 9162 Merkle root over messages 1 to that tree size` +
      `${gap ? `, one anchor every ${fmtSpan(gap)}` : ""}. Checking one reads no message at all. ` +
      `This page asks the sequencer for a consistency proof from that tree size to the size it serves ` +
      `now, about ${fmtN(Math.ceil(Math.log2(Math.max(2, anchors[0].treeSize))))} node hashes, and ` +
      `rebuilds both roots here. The old root has to come out as the value the contract holds, and the ` +
      `new one as the root the sequencer signed. That says the log only ever grew: entries were added ` +
      `and none was changed, removed or reordered.</p>`
    : `<p>A check of one anchor reads only the messages after the anchor before it. That is about ` +
      `${fmtN(perAnchor)} messages here${gap ? `, one anchor every ${fmtSpan(gap)}` : ""}. ` +
      `The chain hash is a simple fold. The hash of each message covers the hash of the message before ` +
      `it. So this page starts at the hash of the anchor before, and reads no earlier message. The ` +
      `check reads those messages as the exact bytes the sequencer hashed. It hashes them again in this ` +
      `browser. Then it compares the result with the value the contract holds.</p>`;
}

function renderAnchorScan() {
  if (!anchorsOpen) return;
  const el = document.getElementById("ax-scan");
  if (!anchorScan) { el.innerHTML = ""; return; }
  if (anchorScan.running) {
    el.innerHTML = `<p>This browser is reading the ${escapeText(anchorConfig.chain_name)} logs. It ` +
      `reads the newest anchor first.</p>`;
    return;
  }
  const parts = [];
  if (anchorScan.note) {
    parts.push(`<p><span class="neg">The log read stopped.</span> ${escapeText(anchorScan.note)}. ` +
      `The list above holds the anchors this browser read before it stopped.</p>`);
  }
  if (anchorScan.from != null) {
    parts.push(`<p>This browser loaded ${anchorScan.found} of ${anchorScan.counted} anchors, back to ` +
      `block ${fmtN(anchorScan.from)}. The other anchors are older. ` +
      `<button class="linkish" id="ax-more">load older anchors</button></p>`);
  } else if (anchorScan.found >= anchorScan.counted && anchorScan.found) {
    parts.push(`<p>The list above holds all ${anchorScan.found} anchors this contract wrote. The ` +
      `count comes from the contract itself. This browser read it from <code>latest()</code> at the ` +
      `same block as the logs. It is not a number this page decided.</p>`);
  } else if (anchorScan.reachedFloor && anchorScan.found < anchorScan.counted) {
    // The one case where the two disagree. Saying "all of them" here would be
    // false, and it is the kind of false that matters: an anchor that cannot be
    // read is an anchor that cannot be checked, and it is exactly the older
    // ones that catch a rewind.
    parts.push(`<p><span class="neg">${anchorScan.counted - anchorScan.found} anchors are missing.</span> ` +
      `The contract counts ${anchorScan.counted} writes. This browser read the logs back to block ` +
      `${fmtN(anchorConfig.deployed_block)}, where the contract was deployed. Only ` +
      `${anchorScan.found} anchors came back. This RPC does not serve the full log history. You ` +
      `cannot check the missing anchors here. Try another ${escapeText(anchorConfig.chain_name)} ` +
      `RPC, or the explorer above.</p>`);
  }
  el.innerHTML = parts.join("");
  const more = document.getElementById("ax-more");
  if (more) more.onclick = () => loadOlderAnchors();
}

// ---------------------------------------------------------------------------
// The orders this browser placed, and where they ended up
// ---------------------------------------------------------------------------

// The first anchor that reaches a message id.
//
// A chain anchor reaches it when its `lastId` does. A root anchor reaches it
// when its `treeSize` does: message n is leaf n-1, so a tree of `treeSize`
// leaves holds every message up to `treeSize`. Comparing a root anchor's
// `lastId` here, the matcher's cursor, which trails the tree, would name a
// later anchor than the one that first committed to the message.
function anchorFor(feedId) {
  let found = null;
  for (const a of anchors) {
    const reaches = a.kind === "root" ? a.treeSize >= feedId : a.lastId >= feedId;
    if (reaches && (!found || a.count < found.count)) found = a;
  }
  return found;
}

// What every check on this page rests on, said once, above the orders.
//
// The order of the rows is the order of the buttons below, and it is the order
// of how much each one needs you to believe. The first needs a public chain and
// nothing the operator says. The second needs the operator's signature right
// now. The third needs that same signature and twenty-one megabytes.
function checksTable() {
  const chain = escapeText(anchorConfig.chain_name);
  const fold = [`folding the whole log`,
    `the operator's signature right now, and every message of the log`,
    `megabytes`];
  const rows = isRootAnchored()
    ? [
        [`the anchored root, then two proofs`,
         `${chain}, and nothing the operator says`,
         `about a kilobyte`],
        [`an inclusion proof against a fresh <code>/sth</code>`,
         `the operator's signature right now`,
         `under a kilobyte`],
        fold,
      ]
    : [
        [`an inclusion proof against a fresh <code>/sth</code>`,
         `the operator's signature right now`,
         `under a kilobyte`],
        [`folding one anchor's window`,
         `${chain}, and every message of that window`,
         `hundreds of kilobytes`],
        fold,
      ];
  return `<table class="ax-rests"><thead><tr><th>check</th><th>depends on</th><th>costs</th></tr>` +
    `</thead><tbody>` +
    rows.map((r) => `<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td></tr>`).join("") +
    `</tbody></table>` +
    (isRootAnchored()
      ? `<p>The first one is the whole chain of trust and it is what the buttons below start with. ` +
        `This browser reads the Merkle root the operator wrote into ${chain}, which they cannot ` +
        `change now. Then a consistency proof from that tree size to the size the sequencer serves ` +
        `today, which says the log only grew, RFC 9162 section 2.1.4.2. Then an inclusion proof for ` +
        `your one message against the root that proof carried forward. Two paths of about seventeen ` +
        `hashes each.</p>` +
        `<p>The other two are still here and still worth what they are worth. An inclusion proof on ` +
        `its own catches an operator contradicting themselves now, and says nothing about what they ` +
        `signed an hour ago. The fold needs no chain at all, which is the only check an exchange ` +
        `anchored to nothing can offer.</p>`
      : `<p>This exchange anchors a chain hash, not a Merkle root, so there is no short proof that ` +
        `reaches ${chain}: the only check that ends at a value the operator does not control is the ` +
        `fold over a whole window.</p>`);
}

function renderSentOrders() {
  if (!anchorsOpen) return;
  const el = document.getElementById("ax-orders");
  if (!sent.length) {
    el.innerHTML = `<p>This browser sent no orders yet. Send one in the Trade panel on the market ` +
      `view. This page then records it here with its message number. The next anchor after that ` +
      `number covers a log that holds your order.</p>`;
    return;
  }
  // A check already on screen survives this list being redrawn. It is redrawn
  // after every window of the chain scan and on every order this browser sends,
  // and a result a visitor waited a whole fold for must not be wiped by an older
  // anchor arriving behind it. Same rule as `renderAnchorTable`.
  const shown = new Map();
  for (const node of el.querySelectorAll(
    "[id^='ax-order-'], [id^='ax-proof-'], [id^='ax-base-'], [id^='ax-log-']")) {
    if (node.innerHTML) shown.set(node.id, { html: node.innerHTML, cls: node.className });
  }
  // A `<details>` a visitor opened must not close itself when the chain scan
  // redraws this list behind them.
  const opened = new Set();
  for (const [i, node] of [...el.querySelectorAll("details.ax-other")].entries()) {
    if (node.open) opened.add(i);
  }
  const oldest = anchors.length ? anchors[anchors.length - 1] : null;
  const gap = anchorInterval();
  const newest = anchors.length ? anchors[0] : null;
  const reaches = (a, id) => (a.kind === "root" ? a.treeSize >= id : a.lastId >= id);
  const chain = escapeText(anchorConfig.chain_name);
  el.innerHTML = checksTable() + sent.map((o) => {
    const what = `${o.side} ${fmtQ(o.quantity)} ${escapeText(o.symbol)} at ${fmtP(o.price)}`;
    const head = `<div class="ax-order"><div><span class="mono">#${o.id}</span> ${what}` +
      `<span class="dim"> · ${fmtT(o.at)}${o.route === "inbox" ? " · sent through the separate service" : ""}</span></div>`;
    const a = anchorFor(o.id);

    // The check against the chain. It needs no anchor to have reached this
    // message: the consistency proof carries the anchored root forward to the
    // tree the sequencer serves now, and an order placed a second ago is in
    // that tree. Whether the chain itself already covers it is a different
    // claim, and `checkAgainstChain` reports which of the two it got.
    const base = isRootAnchored()
      ? `<button class="go" data-verify-base="${o.id}" title="Reads latest() from the anchor ` +
        `contract on ${chain}, then a consistency proof from that tree size to the size the ` +
        `sequencer serves now, then an inclusion proof for this one message. ` +
        `${proofHashes() ? `About ${proofHashes() * 2} hashes and about a kilobyte. ` : ""}` +
        `The root it ends at came off the chain.">check against ${chain}</button>`
      : "";
    // The inclusion proof on its own. Offered on every order, including the
    // ones no anchor has reached, which is exactly the order a visitor has
    // just placed and most wants to see accounted for.
    const proof = `<button class="linkish" data-verify-proof="${o.id}" title="Reads GET /sth, this ` +
      `one message, and GET /proof/inclusion.${proofHashes() ? ` About ${proofHashes()} hashes and ` +
      `under two kilobytes.` : ""} This page checks the signature on the tree head before it checks ` +
      `the proof. The root it ends at is the operator's own.">check against the operator's ` +
      `signature</button>`;
    // The fold over one anchor's window. Only a chain anchor gives it a value on
    // a chain to end at; a root anchor holds a Merkle root and there is no fold
    // that reaches one.
    const fold = a && a.kind === "chain"
      ? `<button class="linkish" data-verify-order="${o.id}" data-anchor="${a.count}">fold the ` +
        `anchor's window${anchorCost(a) ? ` · ${fmtN(anchorCost(a).messages)} messages · ${fmtSize(anchorCost(a).bytes)}` : ""}` +
        `</button>`
      : "";
    // The fold over the whole log, against the head the operator signed. No
    // chain, no tree, no proof, and every message of the history. It is here
    // on every deployment, including one anchored to nothing, because it is the
    // only check that needs nothing but the sequencer itself.
    const logSize = lastMarket && lastMarket.last_feed_id ? Number(lastMarket.last_feed_id) : 0;
    const wholeCost = logSize
      ? ` · ${fmtN(logSize)} messages · ${fmtSize(logSize * bytesPerMessage())}`
      : "";
    const whole = `<button class="linkish" data-verify-log="${o.id}">fold the whole log${wholeCost}` +
      `</button>`;

    // Where the order stands, before any button is pressed.
    let said;
    if (!a) {
      let wait;
      if (!newest) {
        wait = anchorLatest && !anchorLatest.count
          ? "Nobody wrote an anchor to this contract yet."
          : "This browser loaded no anchor yet.";
      } else if (gap) {
        const left = newest.anchoredAt + gap - Date.now() / 1000;
        wait = (left <= 0 ? "The next anchor is due now." : `The next anchor is due in about ${fmtSpan(left)}.`) +
          ` The recent anchors are ${fmtSpan(gap)} apart.`;
      } else {
        wait = "The next anchor comes in a few minutes.";
      }
      const reached = newest
        ? (newest.kind === "root"
          ? `Anchor #${newest.count} committed to a tree of ${fmtN(newest.treeSize)} messages.`
          : `Anchor #${newest.count} reached message ${fmtN(newest.lastId)}.`)
        : "";
      said = `No anchor covers this order yet. The sequencer holds it as message #${o.id}. ` +
        `${reached} ${wait} ` +
        (isRootAnchored()
          ? `The check below still runs, and it says the smaller thing honestly: your order is in a ` +
            `log that grew out of the log ${chain} already holds.`
          : `The proof below needs no anchor: it checks your message against the tree the sequencer ` +
            `signed a moment ago.`);
    } else if (oldest && reaches(oldest, o.id) && oldest.count > 1) {
      // A partial list can hold an anchor that covers this order while an
      // older, earlier one covers it too. Naming the wrong one would be a false
      // claim about which block first committed to it.
      said = `Anchor #${a.count} covers this order. An older anchor may cover it too. Load older ` +
        `anchors below to find the first one.`;
    } else {
      const tx = anchorConfig.explorer
        ? `<a href="${escapeText(anchorConfig.explorer)}/tx/${escapeText(a.tx)}" target="_blank" ` +
          `rel="noopener noreferrer">block ${fmtN(a.block)}</a>`
        : `block ${fmtN(a.block)}`;
      said = `Anchor #${a.count} covers this order. It is in ${tx} on ${chain}, ` +
        `${fmtUTC(a.anchoredAt, true)}, ${fmtAgo(a.anchoredAt)}.`;
    }

    // The order of these is the order of the table above. The folds are no
    // longer beside the cheap check as if they were equal options: they are
    // behind one more click, under a summary that says what they still buy.
    //
    // Every check's answer is written directly under the button that started
    // it. A result that lands somewhere else, inside a section still folded
    // shut, say, is a click that looks like it did nothing.
    const root = isRootAnchored();
    const front = root
      ? { button: base, slot: `ax-base-${o.id}` }
      : { button: proof, slot: `ax-proof-${o.id}` };
    const behind = (root
      ? [[proof, `ax-proof-${o.id}`], [fold, `ax-order-${o.id}`], [whole, `ax-log-${o.id}`]]
      : [[fold, `ax-order-${o.id}`], [whole, `ax-log-${o.id}`]]).filter(([b]) => b);
    return head +
      `<div class="said">${said}</div>` +
      `<div class="checks">${front.button}</div>` +
      `<div class="said" id="${front.slot}"></div>` +
      `<details class="ax-other"><summary>` +
      `${behind.length === 1 ? "the other check, and what it rests on"
        : `the other ${behind.length} checks, and what they rest on`}</summary>` +
      behind.map(([button, slot]) =>
        `<div class="ax-alt"><div class="checks">${button}</div>` +
        `<div class="said" id="${slot}"></div></div>`).join("") +
      `</details></div>`;
  }).join("");
  for (const [id, was] of shown) {
    const node = document.getElementById(id);
    if (node) { node.className = was.cls; node.innerHTML = was.html; }
  }
  for (const [i, node] of [...el.querySelectorAll("details.ax-other")].entries()) {
    if (opened.has(i)) node.open = true;
  }
}

// How long a proof is likely to be, for the label on the button before anything
// is fetched, or 0 when this page has not been told how long the log is yet.
// `ceil(log2(n))` is the depth of a Merkle tree over n leaves and a proof is at
// most that many hashes. The size comes from the matcher's own `last_feed_id`,
// so it is an estimate off the operator's number; what the page reports after
// the run is counted from the proof that actually arrived.
function proofHashes() {
  const size = lastMarket && lastMarket.last_feed_id ? Number(lastMarket.last_feed_id) : 0;
  return size > 1 ? Math.ceil(Math.log2(size)) : 0;
}

// What the whole-window check on this order would cost, in one phrase, or null
// when there is no anchor to compare against yet. Real numbers: `anchorCost`
// divides the bytes this browser has already pulled from the sequencer by the
// messages it got for them.
function windowCostFor(messageId) {
  const a = anchorFor(messageId);
  if (!a) return null;
  const cost = anchorCost(a);
  return cost ? { anchor: a, ...cost } : null;
}

// One order, checked against the root on the chain: the three steps, and then
// the sentence that says exactly what they established.
//
// Two different sentences, because there are two different claims. An order
// inside the anchored tree is inside the history the chain holds. An order
// after it is in a log that provably grew out of that history, and the chain
// has not committed to it yet, which is true of every order for the few
// minutes before the next anchor, and saying otherwise would be the one lie
// this page cannot afford.
async function verifyOrderChain(orderId) {
  const o = sent.find((r) => r.id === orderId);
  if (!o) return;
  const out = document.getElementById("ax-base-" + orderId);
  if (!out) return;
  out.className = "said";
  let r;
  try {
    r = await checkAgainstChain(o.id, (step) => { out.textContent = step + "…"; });
  } catch (e) {
    out.className = "said";
    out.innerHTML = e instanceof ProofFailure
      ? `<span class="neg">This check failed at: ${escapeText(e.step)}.</span> ` +
        `${escapeText(e.message)} Nothing after that step was checked, so this page claims nothing.`
      : `<span class="neg">This browser could not run the check.</span> ${escapeText(e.message)}`;
    return;
  }
  const chain = escapeText(anchorConfig.chain_name);
  const where = r.anchored.block
    ? (anchorConfig.explorer
      ? `<a href="${escapeText(anchorConfig.explorer)}/tx/${escapeText(r.anchored.tx)}" ` +
        `target="_blank" rel="noopener noreferrer">block ${fmtN(r.anchored.block)}</a>`
      : `block ${fmtN(r.anchored.block)}`)
    : `${fmtUTC(r.anchored.anchoredAt, true)}`;
  const claim = r.covered
    ? `Order #${fmtN(o.id)} is inside the history committed to ${chain} at ${where}.`
    : `Order #${fmtN(o.id)} is not on ${chain} yet. It is message #${fmtN(o.id)} of a log that ` +
      `provably grew out of the ${fmtN(r.anchored.treeSize)} messages ${chain} holds at ${where}. ` +
      `The next anchor covers it.`;
  out.className = "proven";
  out.innerHTML =
    `${claim} <b>Checked in this browser with ${fmtN(r.hashes)} hashes and ` +
    `${fmtBytes(r.proofBytes)} of proof.</b> This browser downloaded ${fmtBytes(r.downloaded)} in ` +
    `${r.requests} requests and finished in ${Math.max(1, Math.round(r.ms))} ms.<br>` +
    `<span class="dim">Three steps. <b>One:</b> anchor #${r.anchored.count} of the ` +
    `${fmtN(r.anchored.total)} on <span class="mono">${escapeText(anchorConfig.address)}</span> ` +
    `holds root <span class="mono">${escapeText(r.anchored.rootHash)}</span> over ` +
    `${fmtN(r.anchored.treeSize)} messages, written ${fmtUTC(r.anchored.anchoredAt, true)}. This ` +
    `browser read <span class="mono">latest()</span> from ${chain} over ` +
    `${escapeText(rpcAnswering())} just now; the exchange did not answer for it and cannot change ` +
    `it. ` +
    `<b>Two:</b> a consistency proof of ${fmtN(r.consistencyHashes)} hashes carried that root ` +
    `forward to ${fmtN(r.treeSize)} messages, so the log only grew, RFC 9162 section 2.1.4.2. ` +
    `<b>Three:</b> an inclusion proof of ${fmtN(r.inclusionHashes)} hashes put your message at leaf ` +
    `${fmtN(r.leafIndex)} of that same tree, root ` +
    `<span class="mono">${escapeText(r.root)}</span>. The only value the operator chose here is the ` +
    `one in step two's answer, and step two is what pins it to the chain's.` +
    // What one anchor does not cover. An anchor written after this one catches
    // a rewind that happened between the two, and this check never looked at
    // it. Saying so costs a sentence; not saying it makes the claim slightly
    // wider than what was checked.
    (r.anchored.count < r.anchored.total
      ? ` This is the oldest of the ${fmtN(r.anchored.total)} anchors that already covers your ` +
        `order, so it names the earliest block that committed to it. It says nothing about the ` +
        `${fmtN(r.anchored.total - r.anchored.count)} anchors written after it. "Check every ` +
        `anchor" below does that, one proof each.`
      : "") +
    `</span>`;
}

// One order's proof, reported as a sentence about the order and about what the
// check cost.
async function verifyOrderProof(orderId) {
  const o = sent.find((r) => r.id === orderId);
  if (!o) return;
  const out = document.getElementById("ax-proof-" + orderId);
  if (!out) return;
  out.className = "said";
  let r;
  try {
    r = await checkInclusion(o.id, (step) => { out.textContent = step + "…"; });
  } catch (e) {
    out.className = "said";
    out.innerHTML = e instanceof ProofFailure
      // The step is the first thing on the line. A visitor who reads only the
      // first four words has to learn whether the operator failed a check or
      // the network did, and those are the two ends of what can go wrong here.
      ? `<span class="neg">This check failed at: ${escapeText(e.step)}.</span> ` +
        `${escapeText(e.message)} Nothing after that step was checked, so this page claims nothing.`
      : `<span class="neg">This browser could not run the check.</span> ${escapeText(e.message)}`;
    return;
  }
  const whole = windowCostFor(o.id);
  const compared = isRootAnchored()
    ? `This root is the operator's own number: they signed it a moment ago and they could sign ` +
      `another. "Check against ${escapeText(anchorConfig.chain_name)}" above is the same proof with ` +
      `one more in front of it, and it ends at a root they cannot sign twice.`
    : whole
    ? `The whole-window check on this order reads ${fmtN(whole.messages)} messages, about ` +
      `${fmtSize(whole.bytes)}, and it answers the other question: whether that log is the log ` +
      `anchor #${whole.anchor.count} wrote into ${escapeText(anchorConfig.chain_name)}.`
    : `No anchor covers this order yet, so the whole-window check has nothing to compare against ` +
      `here. When one lands it will read every message of that anchor's window.`;
  out.className = "proven";
  out.innerHTML =
    `Message #${fmtN(o.id)} is leaf ${fmtN(r.leafIndex)} of the tree of ${fmtN(r.treeSize)} messages ` +
    `the sequencer signed. <b>Checked with ${fmtN(r.hashes)} hashes, ${fmtBytes(r.proofBytes)}.</b> ` +
    `This browser downloaded ${fmtBytes(r.downloaded)} in ${r.requests} requests and finished in ` +
    `${Math.max(1, Math.round(r.ms))} ms.<br>` +
    `<span class="dim">That tree head was signed at ${fmtUTC(Math.floor(r.timestamp / 1000), true)}. ` +
    `Its signature is Ed25519 over <span class="mono">exchange-feed-sth-v1</span>, session ` +
    `<span class="mono">${escapeText(r.session)}</span>, the timestamp and ${fmtN(r.treeSize)} ` +
    `leaves, and this page checked it here against key ` +
    `<span class="mono">${escapeText(r.publicKey)}</span> before it fetched the proof. Root ` +
    `<span class="mono">${escapeText(r.root)}</span>. ${compared}</span>`;
}

// One order's own verification: the anchor that first covers it, checked over
// its own window, reported as a sentence about the order rather than about the
// anchor.
async function verifyOrder(orderId, count) {
  const o = sent.find((r) => r.id === orderId);
  const a = anchors.find((x) => x.count === count);
  if (!o || !a) return;
  const out = document.getElementById("ax-order-" + orderId);
  const win = anchorWindow(a);
  if (!win) {
    out.innerHTML = `<span class="neg">This browser did not load the anchor before anchor ` +
      `#${a.count}. So it cannot check this window yet.</span>`;
    return;
  }
  out.className = "said";
  const run = startRun();
  let done = 0;
  let result;
  // Written once, number replaced after that, so the stop stays clickable.
  out.innerHTML = `hashing <b class="ax-n">0</b> of ${fmtN(a.lastId - win.fromId)} messages in this ` +
    `browser. <button class="go" data-verify-stop="1">stop</button>`;
  const counter = out.querySelector(".ax-n");
  try {
    result = await foldFeed(win.fromId, a.lastId, win.startHash, (n) => {
      done = n;
      counter.textContent = fmtN(n);
    }, run);
  } catch (e) {
    out.innerHTML = stopped(e)
      ? `<span class="dim">Stopped.</span> This browser hashed ${fmtN(done)} messages. A check that ` +
        `stops early says nothing about this order.`
      : `<span class="neg">This browser could not check the order.</span> ${escapeText(e.message)}`;
    return;
  } finally {
    if (verifyRun === run) verifyRun = null;
  }
  if (result.hash === a.chainHash) {
    out.className = "proven";
    out.innerHTML = `Order #${o.id} is inside the log that ${escapeText(anchorConfig.chain_name)} ` +
      `holds. The block is ${fmtN(a.block)}, at ${fmtUTC(a.anchoredAt, true)}. Your browser checked ` +
      `this. It hashed ${fmtN(result.messages)} messages again, and the result matches the value on ` +
      `the chain.`;
  } else {
    out.className = "said";
    out.innerHTML = `<span class="neg">This browser cannot show that order #${o.id} is in that ` +
      `log.</span> It hashed ${fmtN(result.messages)} messages here. The result is ` +
      `<span class="mono">${result.hash}</span>. The anchor holds ` +
      `<span class="mono">${a.chainHash}</span>. The sequencer does not serve the log this anchor covers.`;
  }
}

// ---------------------------------------------------------------------------
// Checking the same things without this page
// ---------------------------------------------------------------------------

function renderSelfCheck() {
  if (!anchorsOpen) return;
  const chain = escapeText(anchorConfig.chain_name);
  const call = JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "eth_call",
    params: [{ to: anchorConfig.address, data: LATEST_SELECTOR }, "latest"],
  });
  const explorer = anchorConfig.explorer
    ? `<p>See the contract, its balance and every transaction into it on a site nobody here runs: ` +
      `<a href="${escapeText(anchorConfig.explorer)}/address/${escapeText(anchorConfig.address)}" ` +
      `target="_blank" rel="noopener noreferrer">${escapeText(anchorConfig.explorer)}/address/` +
      `${escapeText(anchorConfig.address)}</a>. Every write comes from ` +
      `<code>${escapeText(anchorConfig.writer)}</code>. The contract refuses every other address.</p>`
    : "";
  // The oldest anchor loaded is the one that makes the point below concrete, so
  // the paragraph names its real numbers rather than an example.
  const old = anchors.length ? anchors[anchors.length - 1] : null;
  const now = anchors.length ? anchors[0] : null;
  const stale = old && now && old.kind === "root"
    ? `<p><b>Why the newest anchor alone is not enough.</b> Suppose the operator moves the exchange ` +
      `back to ${fmtN(old.treeSize)} messages, replays different orders, and writes a new anchor at ` +
      `${fmtN(now.treeSize)}. A check that reads only <code>latest()</code> passes: the tree they ` +
      `serve now really does have the root they just wrote. But the consistency proof from anchor ` +
      `#${old.count} fails. ${chain} holds <span class="mono">${escapeText(old.rootHash)}</span> for ` +
      `${fmtN(old.treeSize)} messages since ${fmtUTC(old.anchoredAt, true)}, and their new tree is ` +
      `not an extension of it. The old anchor catches the change. That is why this page checks every ` +
      `anchor, not only the last one.</p>`
    : old && now
    ? `<p><b>Why the newest anchor alone is not enough.</b> Suppose the operator moves the exchange ` +
      `back to message ${fmtN(old.lastId)}. The operator then replays different orders and writes a ` +
      `new anchor at message ${fmtN(now.lastId)}. A check that reads only <code>latest()</code> ` +
      `passes. The log the sequencer serves now does hash to the value the contract holds for ` +
      `${fmtN(now.lastId)}. But the check fails on anchor #${old.count}. ${chain} holds ` +
      `<span class="mono">${escapeText(old.chainHash)}</span> for message ${fmtN(old.lastId)} since ` +
      `${fmtUTC(old.anchoredAt, true)}. Hashing the log as it stands now to message ` +
      `${fmtN(old.lastId)} gives a different value. The old anchor catches the change. That is why ` +
      `this page checks every anchor, not only the last one.</p>`
    : `<p><b>Why the newest anchor alone is not enough.</b> An operator moves the exchange back, ` +
      `replays different messages and writes a new anchor. That operator passes any check that reads ` +
      `only <code>latest()</code>. The log they serve now does hash to the value they just wrote. An ` +
      `older anchor catches them. Hashing the log as it stands to that earlier message gives a value ` +
      `the chain does not hold. That is why this page checks every anchor.</p>`;
  // The same selector answers both contracts, and the width of the answer is
  // what tells them apart. A reader running this by hand needs that said, or
  // they will decode seven words as six and get a root where a session is.
  const shape = isRootAnchored()
    ? `<p>Read the newest anchor in one request. You need no library and no key. The answer is 224 ` +
      `bytes, seven fixed-width values, 32 bytes each: tree size, message number, session, Merkle ` +
      `root, state root, timestamp, count. An <code>ExchangeAnchor</code> answers the same selector ` +
      `with 192 bytes and a chain hash where the root is, so the length is what tells you which ` +
      `contract you are reading.</p>`
    : `<p>Read the newest anchor in one request. You need no library and no key. The answer is 192 ` +
      `bytes, six fixed-width values: message number, session, chain hash, state root, timestamp, ` +
      `count. An <code>ExchangeRootAnchor</code> answers the same selector with 224 bytes and a ` +
      `Merkle root, so the length is what tells you which contract you are reading.</p>`;
  const proofs = isRootAnchored()
    ? `<p>The three steps this page runs, with nothing from this repository. The first number comes ` +
      `off the chain above; the two proofs come from the sequencer and are checked against it.</p>` +
      `<pre>curl -s '${escapeText(feedUrl || "")}/sth'\ncurl -s '${escapeText(feedUrl || "")}` +
      `/proof/consistency?first=${anchorLatest ? anchorLatest.treeSize : 0}&second=&lt;tree_size&gt;'\n` +
      `curl -s '${escapeText(feedUrl || "")}/proof/inclusion?leaf=&lt;n-1&gt;&amp;tree_size=&lt;tree_size&gt;'</pre>` +
      `<p>RFC 9162 section 2.1.4.2 verifies the first proof and section 2.1.3.2 the second. ` +
      `<code>anchor/merkle.go</code> and <code>services/src/merkle.rs</code> are two independent ` +
      `transcriptions of both, and <code>docs/API.md</code> carries a Python one.</p>`
    : "";
  document.getElementById("ax-self").innerHTML =
    explorer + shape +
    `<pre>curl -s ${escapeText(rpcAnswering())} \\\n  -H 'content-type: application/json' \\\n  -d '${
      escapeText(call)}'</pre>` +
    proofs +
    `<p>The full check runs the log of the sequencer again. It compares every state root the ` +
    `exchange claimed. An anchor says nothing about that part.</p>` +
    `<pre>services/target/release/services --audit-url ${escapeText(location.origin)}</pre>` +
    stale;
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// One delegated listener rather than a binding after every render: the strip is
// rebuilt from scratch twice a second, and rebinding a handler at that rate to
// catch a click that happens once is work for nothing.
document.getElementById("verify").addEventListener("click", (e) => {
  if (e.target.closest("[data-open-anchors]")) openAnchors();
});
document.getElementById("ax-close").onclick = closeAnchors;
// Back and forward, and a hash edited in the address bar: the second event is
// not covered by the first, and running both is harmless because `showAnchors`
// does nothing when the screen already matches the hash.
window.addEventListener("popstate", syncAnchors);
window.addEventListener("hashchange", syncAnchors);
// The third way out. Escape belongs to whatever is focused before it belongs to
// this view: a browser uses it to abandon what is being typed in a field or
// chosen in a dropdown, and taking it from them would be a surprise. This view
// holds no such control. Every field on the page is in the market view, which
// is display:none while this is up. So the guard is there for the day one is
// added rather than for a case that can happen now.
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape" || !anchorsOpen) return;
  const el = document.activeElement;
  if (el && (el.matches("input, select, textarea") || el.isContentEditable)) return;
  e.preventDefault();
  closeAnchors();
});
document.getElementById("ax-verify-all").onclick = () => verifyAllClicked();
document.getElementById("anchors").addEventListener("click", async (e) => {
  const copy = e.target.closest(".copy");
  if (copy) {
    const full = copy.dataset.full;
    try {
      await navigator.clipboard.writeText(full);
      const was = copy.textContent;
      copy.textContent = "copied";
      setTimeout(() => { copy.textContent = was; }, 900);
    } catch (err) {
      // No clipboard permission, or a page not on https. The value is the point,
      // so it is shown whole to be selected by hand rather than lost to a
      // failure the reader cannot do anything about.
      copy.textContent = full;
    }
    return;
  }
  // The stop on a single anchor's progress line, and the "not now" that clears
  // a confirmation without running it.
  if (e.target.closest("[data-verify-stop]")) { cancelRun(); return; }
  // The proof. Three small requests and a dozen hashes, so it runs on the click
  // it was given: the two-step confirmation below exists for the folds that cost
  // megabytes, and putting one in front of a check that costs half a kilobyte
  // would teach a visitor to click through the one that matters. It does not
  // touch `verifyRun` either: that holds the fold's stop button, and a proof
  // running beside a fold cannot cancel it.
  // The check against the chain. One eth_call and four small reads, so it runs
  // on the click it was given for the same reason the proof does.
  const byChain = e.target.closest("[data-verify-base]");
  if (byChain && !byChain.disabled) {
    byChain.disabled = true;
    await verifyOrderChain(Number(byChain.dataset.verifyBase));
    byChain.disabled = false;
    return;
  }
  const byProof = e.target.closest("[data-verify-proof]");
  if (byProof && !byProof.disabled) {
    byProof.disabled = true;
    await verifyOrderProof(Number(byProof.dataset.verifyProof));
    byProof.disabled = false;
    return;
  }
  // The fold over the whole log. Megabytes, so it says what it costs and waits
  // to be told again, the same two-step the anchor windows use.
  const byLog = e.target.closest("[data-verify-log]");
  if (byLog && !byLog.disabled) {
    const id = Number(byLog.dataset.verifyLog);
    const out = document.getElementById("ax-log-" + id);
    const size = lastMarket && lastMarket.last_feed_id ? Number(lastMarket.last_feed_id) : 0;
    if (size > CONFIRM_OVER && !byLog.dataset.armed) {
      byLog.dataset.armed = "1";
      out.className = "said";
      out.innerHTML = `This reads every message of the log, <b>${fmtN(size)} messages, about ` +
        `${fmtSize(size * bytesPerMessage())}, ${fmtHowLong(size / foldRate())}</b>, and hashes them ` +
        `here. It ends at the head the operator signed, not at anything on a chain. Click "fold the ` +
        `whole log" again to start it.`;
      return;
    }
    byLog.disabled = true;
    await verifyWholeLog(id, (html) => {
      const el = document.getElementById("ax-log-" + id);
      if (el) { el.className = "said"; el.innerHTML = html; }
    });
    byLog.disabled = false;
    return;
  }
  const off = e.target.closest("[data-verify-off]");
  if (off) {
    const el = document.getElementById("ax-result-" + off.dataset.verifyOff);
    if (el) el.innerHTML = "";
    return;
  }

  const row = e.target.closest("[data-verify]");
  if (row) {
    const a = anchors.find((x) => x.count === Number(row.dataset.verify));
    if (a && !row.disabled) {
      const cost = anchorCost(a);
      // A big window says what it costs and waits to be told again. A small one
      // runs on the click it was given, which is the common case and the one
      // that has to stay a single click.
      if (cost && cost.messages > CONFIRM_OVER) {
        reportOn(a, `<b>${costLine(cost)}.</b> Messages #${fmtN(a.lastId - cost.messages + 1)} to ` +
          `#${fmtN(a.lastId)}. ` +
          `${a.count === 1
            ? "The sequencer had already put all of them in the log when the sender wrote its first " +
              "anchor. That is why this row is much larger than the others. "
            : `This is the window between anchor #${a.count - 1} and this anchor. `}` +
          `<button class="go" data-verify-go="${a.count}">hash ${fmtN(cost.messages)} messages</button> ` +
          `<button class="linkish" data-verify-off="${a.count}">not now</button>`);
        return;
      }
      row.disabled = true;
      await verifyAnchor(a, (html) => reportOn(a, html));
      row.disabled = false;
      // The costs on the other rows were estimates from a constant until this
      // fold measured the real bytes and the real rate. Redrawn so they say
      // what this feed and this machine just did; the results already on screen
      // survive the redraw.
      renderAnchorTable();
    }
    return;
  }
  const go = e.target.closest("[data-verify-go]");
  if (go && !go.disabled) {
    const a = anchors.find((x) => x.count === Number(go.dataset.verifyGo));
    if (a) {
      go.disabled = true;
      await verifyAnchor(a, (html) => reportOn(a, html));
      renderAnchorTable();
    }
    return;
  }
  const order = e.target.closest("[data-verify-order]");
  if (order && !order.disabled) {
    const id = Number(order.dataset.verifyOrder);
    const count = Number(order.dataset.anchor);
    const a = anchors.find((x) => x.count === count);
    const cost = a && anchorCost(a);
    // The same two-step as a row, on the button rather than in a second
    // control: this one is already a sentence about one order, and the answer
    // to "how much" is "click it again".
    if (cost && cost.messages > CONFIRM_OVER && !order.dataset.armed) {
      order.dataset.armed = "1";
      const out = document.getElementById("ax-order-" + id);
      out.className = "said";
      out.innerHTML = `This check reads the whole window of anchor #${count}. ` +
        `<b>${costLine(cost)}.</b> It is the check that ends at ` +
        `${escapeText(anchorConfig.chain_name)}, so there is no smaller version of it. ` +
        `Click "check the whole window" again to start it. ` +
        `"Check with a proof" is the cheap one, and it answers the other question.`;
      return;
    }
    order.disabled = true;
    await verifyOrder(id, count);
    order.disabled = false;
  }
});

// Read once, at startup. A 404 means this exchange is anchored to nothing, and
// then the whole section leaves the page rather than sitting there empty: there
// is no chain to read, so there is nothing for a visitor to click.
async function startAnchor() {
  anchorConfig = await readAnchorConfig();
  if (!anchorConfig) {
    document.getElementById("anchors").remove();
    return;
  }
  // Someone may have arrived straight at /#anchors, from a link or from their
  // own history. Before the first read of the chain rather than after it, so a
  // slow RPC does not hold the view they asked for off the screen.
  syncAnchors();
  await pollAnchor();
}

// ===========================================================================
// Resizable layout
//
// Which panel matters depends on what the visitor came to look at: the book,
// the chart, the accounts underneath. The page cannot know which. So the
// three columns, the split inside each of the two stacked ones, the Traders
// panel's height and its own three columns are all theirs to set, by dragging
// the space that is already between the panels.
//
// Nothing here changes what the page does. It moves the boundaries the panels
// are drawn between, and remembers where they were put.
//
// The sizes live in custom properties whose fallbacks are the values the page
// shipped with (see `main` in the stylesheet), so if this script never runs
// the page is laid out exactly as it always was rather than not at all.
// ===========================================================================

const LAYOUT_ITEM = "verifiable-exchange.layout";

// The stylesheet's fallbacks, repeated. A change to one is a change to both.
// `chart` is the share of the middle column the chart takes, above the order
// ticket. `trades` is the share of the right column Recent Trades takes, above
// Order Flow. Both are percentages, so both survive a change of window height.
const DEFAULTS = { left: 340, right: 340, traders: 296, chart: 70, trades: 55, tcol1: 27.4, tcol2: 31.5 };

// Floors, in pixels. A panel dragged to nothing is a panel that cannot be
// dragged back; there is no edge left to take hold of. So every handle stops
// short of that, and so does a layout restored onto a smaller screen than the
// one it was set on.
const MIN = { col: 220, centre: 260, split: 88, traders: 96, above: 160, tcol: 180 };

const mainEl = document.querySelector("main");
const box = (id) => document.getElementById(id).getBoundingClientRect();
const tcolBox = (i) => document.querySelectorAll("#traders-body .tcol")[i].getBoundingClientRect();
const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), Math.max(lo, hi));
const pct = (px, whole) => (px / whole) * 100;

let layout = { ...DEFAULTS };
// The column widths a visitor dragged, in pixels: one set per fitted table,
// keyed by table name and then by column number. Kept apart from DEFAULTS
// because there is no default width: a column is sized from its content until
// someone drags it, and an empty set says exactly that.
const colWidths = {};
try {
  const stored = JSON.parse(localStorage.getItem(LAYOUT_ITEM) || "{}");
  for (const key of Object.keys(DEFAULTS)) {
    if (Number.isFinite(stored[key])) layout[key] = stored[key];
  }
  const sets = stored.cols && typeof stored.cols === "object" ? { ...stored.cols } : {};
  // `acct` is where these widths were stored while Accounts was the only table
  // with columns to drag. Read it, so a layout set then still opens as it was.
  if (!sets.accounts && stored.acct && typeof stored.acct === "object") sets.accounts = stored.acct;
  for (const [name, set] of Object.entries(sets)) {
    if (!set || typeof set !== "object") continue;
    const w = colWidths[name] = {};
    for (const [col, px] of Object.entries(set)) {
      if (Number.isFinite(px)) w[col] = px;
    }
  }
} catch (e) {
  // Storage switched off, or something else's key under this name. The page
  // opens at its default sizes, which is the same thing a first visit does.
}

function saveLayout() {
  try {
    localStorage.setItem(LAYOUT_ITEM, JSON.stringify({ ...layout, cols: colWidths }));
  } catch (e) {}
}

// The gutter tracks and main's own padding, read out of the stylesheet rather
// than written down twice: they are not the panels' to divide up.
const mainStyle = getComputedStyle(mainEl);
const GUT = parseFloat(mainStyle.getPropertyValue("--gut")) || 8;
const PAD_X = parseFloat(mainStyle.paddingLeft) + parseFloat(mainStyle.paddingRight);
const PAD_Y = parseFloat(mainStyle.paddingTop) + parseFloat(mainStyle.paddingBottom);

// What each boundary has to divide up, measured now rather than remembered:
// the window is whatever the window is.
function room() {
  return {
    cols: mainEl.clientWidth - PAD_X - 2 * GUT,
    rows: mainEl.clientHeight - PAD_Y - GUT,
    mid: document.getElementById("midcol").clientHeight,
    right: document.getElementById("rightcol").clientHeight,
    body: document.getElementById("traders-body").clientWidth,
  };
}

// A split held as a percentage rather than in pixels, so that it still means
// the same thing after the window's height changes.
// `below` is the floor for the panel under the split. It defaults to the same
// 88px the panel above gets, and the chart passes the ticket's real floor
// instead: the ticket holds controls, and controls that do not fit are not a
// smaller ticket, they are a ticket with a scrollbar over the Buy button.
const share = (value, whole, below = MIN.split) => {
  const lo = pct(MIN.split, whole);
  const hi = 100 - pct(below + GUT, whole);
  // Too short for both floors, which is a 1280x800 window: the middle column
  // is 397px and the ticket is laid out two controls to a row, so the controls
  // alone are 274px of it. The chart takes its own floor and the ticket takes
  // the rest, because a chart 88px tall is a chart with fewer candles in it
  // and a ticket 88px tall is a Buy button under the fold.
  return hi > lo ? clamp(value, lo, hi) : lo;
};

// Read from the stylesheet rather than written down here, because what it
// depends on is decided there: see `--ticket-floor`.
const ticketFloor = () =>
  parseFloat(getComputedStyle(document.getElementById("chart-panel"))
    .getPropertyValue("--ticket-floor")) || MIN.split;

// Writes the layout out, clamped to what this window can actually show.
// `commit` is true when a person just moved a handle, and then the clamped
// numbers are kept: what is stored is what they can see. It is false when the
// window changed size, and then they are not: a layout set on a wide monitor
// should come back whole on that monitor, not shrunk to whatever a laptop
// could show of it in between.
function applyLayout(commit) {
  const r = room();
  const style = mainEl.style;
  const shown = { ...layout };

  if (r.cols > MIN.col * 2 + MIN.centre) {
    shown.left = clamp(layout.left, MIN.col, r.cols - MIN.centre - Math.max(layout.right, MIN.col));
    shown.right = clamp(layout.right, MIN.col, r.cols - MIN.centre - shown.left);
  }
  style.setProperty("--col-left", Math.round(shown.left) + "px");
  style.setProperty("--col-right", Math.round(shown.right) + "px");

  if (r.rows > MIN.above + MIN.traders) {
    shown.traders = clamp(layout.traders, MIN.traders, r.rows - MIN.above);
  }
  style.setProperty("--traders-h", Math.round(shown.traders) + "px");

  shown.chart = share(layout.chart, r.mid, ticketFloor());
  style.setProperty("--chart-share", shown.chart.toFixed(2) + "%");
  shown.trades = share(layout.trades, r.right);
  style.setProperty("--trades-share", shown.trades.toFixed(2) + "%");

  if (r.body > MIN.tcol * 3) {
    const floor = pct(MIN.tcol, r.body);
    shown.tcol1 = clamp(layout.tcol1, floor, 100 - 2 * floor);
    shown.tcol2 = clamp(layout.tcol2, floor, 100 - shown.tcol1 - floor);
  }
  style.setProperty("--tcol-1", shown.tcol1.toFixed(2) + "%");
  style.setProperty("--tcol-2", shown.tcol2.toFixed(2) + "%");

  if (commit) layout = shown;
}

// One handle. `at` says where its boundary is now, in pixels along the axis it
// moves; `to` is handed where the boundary should be and stores what that
// makes the panel. Everything else is the same for every one of them:
// capturing the pointer so the drag survives leaving the gutter, the
// double-click back to the default, the arrow keys.
function handle(id, axis, at, to, back) {
  const el = document.getElementById(id);
  const held = axis === "x" ? "rs-col" : "rs-row";
  el.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    el.setPointerCapture(e.pointerId);
    el.classList.add("on");
    document.body.classList.add(held);
    const from = at();
    const start = axis === "x" ? e.clientX : e.clientY;
    const move = (ev) => {
      to(from + (axis === "x" ? ev.clientX : ev.clientY) - start);
      applyLayout(true);
    };
    const stop = () => {
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", stop);
      el.removeEventListener("pointercancel", stop);
      el.classList.remove("on");
      document.body.classList.remove(held);
      saveLayout();
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", stop);
    el.addEventListener("pointercancel", stop);
  });
  // Two ways back: this boundary on its own, and the header's reset for all of
  // them.
  el.addEventListener("dblclick", () => { back(); applyLayout(true); saveLayout(); });
  el.addEventListener("keydown", (e) => {
    const step = e.shiftKey ? 48 : 12;
    if (e.key === "ArrowLeft" || e.key === "ArrowUp") to(at() - step);
    else if (e.key === "ArrowRight" || e.key === "ArrowDown") to(at() + step);
    else if (e.key === "Home") back();
    else return;
    e.preventDefault();
    applyLayout(true);
    saveLayout();
  });
}

handle("gut-left", "x",
  () => box("book-panel").width,
  (v) => { layout.left = v; },
  () => { layout.left = DEFAULTS.left; });

// Measured from the same end as every other horizontal handle: the boundary
// moves right, so the column on its right gets narrower.
handle("gut-right", "x",
  () => room().cols - box("rightcol").width,
  (v) => { layout.right = room().cols - v; },
  () => { layout.right = DEFAULTS.right; });

handle("gut-chart", "y",
  () => box("chart-panel").height,
  (v) => { layout.chart = pct(v, room().mid); },
  () => { layout.chart = DEFAULTS.chart; });

handle("gut-trades", "y",
  () => box("trades-panel").height,
  (v) => { layout.trades = pct(v, room().right); },
  () => { layout.trades = DEFAULTS.trades; });

handle("gut-traders", "y",
  () => room().rows - box("traders").height,
  (v) => { layout.traders = room().rows - v; },
  () => { layout.traders = DEFAULTS.traders; });

handle("gut-t1", "x",
  () => tcolBox(0).width,
  (v) => { layout.tcol1 = pct(v, room().body); },
  () => { layout.tcol1 = DEFAULTS.tcol1; });

handle("gut-t2", "x",
  () => tcolBox(0).width + tcolBox(1).width,
  (v) => { layout.tcol2 = pct(v - tcolBox(0).width, room().body); },
  () => { layout.tcol2 = DEFAULTS.tcol2; });

document.getElementById("layout-reset").onclick = () => {
  layout = { ...DEFAULTS };
  for (const name of Object.keys(colWidths)) colWidths[name] = {};
  try { localStorage.removeItem(LAYOUT_ITEM); } catch (e) {}
  applyLayout(false);
  fitTables();
};

// ===========================================================================
// The columns of the fitted tables
//
// Everything else on this page has its widths written in the stylesheet. These
// five tables do not, for two reasons. Their figures have no upper bound; the
// demo bot passes +99999.99 in an afternoon. So the only width that is right
// is the width of what is in the cell. And their panels are dragged, so that
// width has to be decided again whenever a panel changes.
//
// One mechanism, five descriptions. A description says where the three boxes
// are, which column holds text and may be cut, and the order the columns go in
// when the room runs out. Nothing under this list knows what a column holds.
// ===========================================================================

// Two columns in a wide panel put one figure against each edge with a hole
// between them, which is harder to read than a table that lost a column. So no
// table goes below three columns, whatever else is on its drop list.
//
// This is why a drop list below holds at most (columns − 3) entries. A fourth
// entry in a five column table can never fire, and a list that names a column
// which never goes reads as if it worked. Whoever lowers this floor adds those
// entries back, and knows from here why they were missing.
const KEEP_COLS = 3;
// A column dragged narrower than this leaves no line to take hold of again.
const MIN_COL_W = 46;
// How much room a column that is off screen needs before it comes back, in
// pixels. Two characters: enough that a figure one or two characters wider on
// the next tick does not send it away again. See fitTable.
const HYST = 16;
// The floor of the column that holds text, in characters.
const TEXT_FLOOR = "9ch";

const TABLE_LIST = [
  // Unreal. first, then Realized. Account, Total and Open stay: Total is the
  // sum of the two that go, so the row still answers the first question anyone
  // asks of it, and five columns less two is the floor.
  { name: "accounts", box: "accounts-scroll", head: "accounts-head", text: 1, drop: [3, 2] },
  // Three columns already, so nothing here can go. Time stays.
  { name: "trades", box: "trades-scroll", head: "trades-head", text: null, drop: [] },
  // Side and account together, so the first column is a name and not a number:
  // it holds "Sell #1000042", the widest a visitor's own id makes it, and it is
  // the column the ellipsis takes from. Three columns, so nothing is dropped.
  { name: "flow", box: "flow-scroll", head: "flow-head", text: 1, drop: [] },
  // Entry and Mark go first: both are prices, and Unreal. already says what the
  // distance between them is worth. Realized goes next: it is profit from
  // quantity this row no longer holds. Symbol, Quantity and Unreal. stay.
  { name: "positions", box: "positions-scroll", head: "positions-head", text: 1, drop: [3, 4, 6] },
  // Role goes first, then Time, then Side. What is left is Symbol, Price and
  // Quantity: what was traded, at what price, how much.
  { name: "acct-trades", box: "acct-trades-scroll", head: "acct-trades-head", text: 2, drop: [6, 1, 3] },
];

// Every table by name, built from its description.
const tables = new Map();
for (const desc of TABLE_LIST) {
  const box = document.getElementById(desc.box);
  const head = document.getElementById(desc.head);
  const cells = [...head.children];
  const t = {
    ...desc,
    box,
    table: box.querySelector(".table"),
    cells,
    // The column numbers, in the order they are drawn.
    cols: cells.map((_, i) => i + 1),
    // The columns on screen after the last fit.
    shown: [],
    // A row's side padding falls inside the outer tracks. Once the empty track
    // is on the end of the list, the padding on the right belongs to that
    // track, so the columns have this much less to divide between them.
    tail: parseFloat(getComputedStyle(head).paddingRight) || 0,
  };
  if (t.text != null) box.dataset.text = String(t.text);
  if (!colWidths[t.name]) colWidths[t.name] = {};
  tables.set(t.name, t);
  addColumnHandles(t);
  // A panel changes width when a layout handle is dragged, and the window never
  // moved, so a resize listener on the window is the wrong signal. One frame
  // at a time, as the two canvases below are.
  let waiting = 0;
  new ResizeObserver(() => {
    if (waiting) return;
    waiting = requestAnimationFrame(() => { waiting = 0; fitTable(t.name); });
  }).observe(box);
}

// The tracks the table is drawn with. Content is the floor and the room left
// over is shared, so the grid ends exactly at the panel edge; a grid narrower
// than its box leaves the line under the heading stopping short of it. Once
// `cut` is set the text column is floored in characters instead of at its
// content. See fitTable for when that happens.
//
// A pixel width cannot stretch. So the first drag fixes every column, not only
// the one under the pointer; a drag that also moved the columns beside it
// would be a drag of something else. An empty track goes on the end to take
// whatever the fixed columns do not use.
//
// `drags` is false while the fit is measuring. Which columns are shown is a
// question about the figures and the panel, not about a width a visitor chose;
// a column that vanished because the column beside it was dragged wider would
// look like a fault. A drag is held inside the panel instead. See setWidth.
function colTemplate(t, shown, cut, drags) {
  const w = drags ? colWidths[t.name] : {};
  const fixed = shown.some((n) => w[n] != null);
  const parts = shown.map((n) =>
    w[n] != null ? w[n] + "px"
      : n === t.text ? `minmax(${cut ? TEXT_FLOOR : "max-content"}, 1.4fr)`
      : "minmax(max-content, 1fr)");
  if (fixed) parts.push("1fr");
  return parts.join(" ");
}

// Lays the columns out at the width they need, measures the result, and drops
// the next column when the total does not fit. Measured rather than guessed:
// the width of "+42928.74" in this font is not a number this script can know.
//
// Measured with the tracks the table is really drawn with, minus the drags,
// and measured against a width the table is actually given. Neither of those
// is fussiness. A template that is only nearly the same measures a different
// table, and a table laid out at `max-content` is not the same table either:
// an `fr` track under max-content is grown until every track fits its share,
// so the Positions rows that draw in 310px reported 336px that way. The fit
// used to measure one number and draw another, and the Realized column went
// off, fitted, came back, and did it again on the next tick.
//
// scrollWidth against the width given, both whole pixels, so a track that
// lands a third of a pixel over the edge is not read as a table that does not
// fit. clientWidth of the box, so the vertical scrollbar is already gone from
// the number.
function fitTable(name) {
  const t = tables.get(name);
  const room = t.box.clientWidth;
  if (!room) return;  // the Traders row is collapsed: there is nothing to fit
  const hidden = [];
  let shown = t.cols.slice();
  // What was on screen when this table was last fitted. Everything, the first
  // time, so a fresh page keeps whatever fits.
  const before = t.shown.length ? t.shown : t.cols;
  // The name in the text column is cut only after there is nothing left to
  // drop. A column that is gone is plainly gone, while "MERKLE-…" reads as
  // another symbol, so the table gives up a whole column first and the name
  // last. Until then the text column is floored at its content like the rest.
  let cut = false;
  for (;;) {
    t.box.dataset.hide = hidden.join(" ");
    t.table.style.setProperty("--cols", colTemplate(t, shown, cut, false));
    // A column that is on screen stays while the table fits. A column that is
    // off comes back only with a margin to spare, because the figures in these
    // columns change width as the market moves: one tick's Realized is
    // "+645.51" and the next is "+13.72". Without the margin the Positions
    // Realized column crossed the edge of its box in both directions and
    // blinked twice a second at 1024.
    const budget = room - (shown.some((n) => !before.includes(n)) ? HYST : 0);
    t.table.style.width = budget + "px";
    const fits = t.table.scrollWidth <= budget;
    t.table.style.width = "";
    if (fits) break;
    const next = shown.length > KEEP_COLS ? t.drop.find((n) => shown.includes(n)) : null;
    if (next == null) { cut = true; break; }
    hidden.push(next);
    shown = shown.filter((n) => n !== next);
  }
  t.shown = shown;
  // Which columns are on the two ends now, for the cells that carry no gap and
  // no line on their outer side.
  t.box.dataset.first = String(shown[0]);
  t.box.dataset.last = String(shown[shown.length - 1]);
  // The widths a visitor dragged, if they still fit. They are pixels, and one
  // localStorage entry is read by every window the same browser opens this page
  // in: a set dragged in a 2560px window is 900px of columns in a 300px panel
  // on the same person's phone, and the table would run off the side of it.
  // Measured the way everything else here is measured, and dropped for this
  // panel when it does not fit: the fit's own widths are used instead and the
  // stored set is left alone, so the wide window still opens as it was left.
  t.table.style.setProperty("--cols", colTemplate(t, shown, cut, true));
  t.table.style.width = room + "px";
  const dragsFit = t.table.scrollWidth <= room;
  t.table.style.width = "";
  if (!dragsFit) t.table.style.setProperty("--cols", colTemplate(t, shown, cut, false));
}

function fitTables() {
  for (const name of tables.keys()) fitTable(name);
}

// Every column takes the width it has on screen right now. Called before the
// first drag, so that moving one line moves that line only. The room the empty
// track is about to want comes off the column that takes whatever the others
// leave: the text column, or the first column on screen when the table has no
// text column and every column stretches alike.
function freezeCols(t) {
  const w = {};
  for (const [i, cell] of t.cells.entries()) {
    const width = cell.getBoundingClientRect().width;
    if (width) w[i + 1] = Math.round(width);
  }
  const give = t.text != null && t.shown.includes(t.text) ? t.text : t.shown[0];
  if (w[give] != null) w[give] = Math.max(MIN_COL_W, w[give] - t.tail);
  colWidths[t.name] = w;
}

function autoCols(t) {
  colWidths[t.name] = {};
  fitTable(t.name);
  saveLayout();
}

// A handle on the right edge of every heading cell but the last. The pointer is
// captured so that a fast drag stays on the column it started on. The arrow
// keys do the same job for a visitor with no mouse, and Home and a double-click
// both hand the widths back to the fit, the same two ways back the panel
// handles give.
function addColumnHandles(t) {
  t.cells.forEach((cell, i) => {
    const n = i + 1;
    if (n === t.cells.length) return;
    const el = document.createElement("i");
    el.className = "ch";
    el.tabIndex = 0;
    el.setAttribute("role", "separator");
    el.setAttribute("aria-orientation", "vertical");
    el.setAttribute("aria-label", cell.textContent.trim() + " column width");
    el.title = "Drag to change the column width. Double-click for automatic widths.";
    cell.appendChild(el);

    // The columns beside this one keep the widths they have, so this one may
    // only take what they leave. Held inside the panel on purpose: a table
    // dragged wider than its panel pushes its last column out of sight, and the
    // only way back is a sideways scrollbar in a box 13 rows tall.
    const setWidth = (px) => {
      const w = colWidths[t.name];
      let left = t.box.clientWidth - t.tail;
      for (const c of t.shown) if (c !== n) left -= w[c] || 0;
      w[n] = Math.max(MIN_COL_W, Math.min(Math.round(px), Math.round(left)));
      fitTable(t.name);
    };

    el.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      el.setPointerCapture(e.pointerId);
      el.classList.add("on");
      document.body.classList.add("rs-col");
      freezeCols(t);
      const from = colWidths[t.name][n];
      const start = e.clientX;
      const move = (ev) => setWidth(from + ev.clientX - start);
      const stop = () => {
        el.removeEventListener("pointermove", move);
        el.removeEventListener("pointerup", stop);
        el.removeEventListener("pointercancel", stop);
        el.classList.remove("on");
        document.body.classList.remove("rs-col");
        saveLayout();
      };
      el.addEventListener("pointermove", move);
      el.addEventListener("pointerup", stop);
      el.addEventListener("pointercancel", stop);
    });

    el.addEventListener("dblclick", (e) => { e.preventDefault(); autoCols(t); });

    el.addEventListener("keydown", (e) => {
      const step = e.shiftKey ? 48 : 12;
      if (e.key === "Home") autoCols(t);
      else if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
        if (colWidths[t.name][n] == null) freezeCols(t);
        setWidth(colWidths[t.name][n] + (e.key === "ArrowLeft" ? -step : step));
        saveLayout();
      } else return;
      e.preventDefault();
    });
  });
}

// Both canvases are drawn at the size of their box, and a box now changes size
// for reasons that are not a window resize. Watched rather than redrawn from
// inside the drag: this covers the Traders panel being hidden and shown too,
// and it runs after layout, when the box is the size the canvas is about to be
// drawn at. One frame at a time, so a drag redraws once per frame instead of
// once per pointer event.
let redrawing = 0;
const boxes = new ResizeObserver(() => {
  if (redrawing) return;
  redrawing = requestAnimationFrame(() => {
    redrawing = 0;
    drawChart(lastCandles);
    drawPnl();
  });
});
boxes.observe(document.getElementById("chart-wrap"));
boxes.observe(document.getElementById("pnl-wrap"));

// #book changes height for three reasons: the window resizes, the gut-traders
// handle is dragged, and the Traders row is hidden or shown. Only the first is
// a window resize, so a resize listener on the window is the wrong signal,
// the same reason the tables and the two canvases above are watched. One frame
// at a time, so a drag measures once per frame and not once per pointer event.
//
// fitBook must never change the height of #book. It cannot today, because
// #book is flex: 1 inside a panel that is a fixed grid cell; a later change
// that makes the book panel content-sized would turn this into a loop.
//
// This watches #book and not #asks or #bids. Their boxes are the same size
// whatever is in them, so they would never fire, but renderBook replaces
// their content twice a second, and watching a box whose content is replaced
// that often is a loop waiting for a later edit to create.
//
// Nothing here sends a request. It writes `depth`, and the 500ms refresh below
// reads it on its next tick. That bounds a drag at 2 requests a second with no
// second timer anywhere.
let fitting = 0;
new ResizeObserver(() => {
  if (fitting) return;
  fitting = requestAnimationFrame(() => { fitting = 0; fitBook(); });
}).observe(document.getElementById("book"));

window.addEventListener("resize", () => applyLayout(false));
applyLayout(false);
// Once before any data arrives. Without it a table has no --cols until its
// first render, and a grid with no tracks stacks its heading cells one under
// the other.
fitTables();
// Once before the first request, so it already asks for the number of levels
// the panel can show. The observer above would do it a frame later, and the
// first book would be 12 levels deep for half a second.
fitBook();

startTrading();
// Its own start rather than a step inside startTrading: an exchange with no
// anchor, and an anchor whose RPC is unreachable, must both leave the trading
// panel exactly as it was.
startAnchor();
// The wheel, drag, key and button controls on both charts. Set up before the
// first refresh, so a reader can move the chart from the first picture on.
attachCharts();
// One tick at a time.
//
// This was `setInterval(refresh, 500)`, which starts a tick every 500ms whether
// or not the last one finished. Measured on the live exchange before the two
// changes above: a tick took longer than 500ms, so ticks overlapped, and the
// browser held 10.5 requests at once on average and 25 at the peak. Every one
// of them asked the exchange for work it was already doing.
//
// 500ms after the answer, not 500ms after the question. A tick that takes
// longer than 500ms now slows the page down instead of multiplying it.
const REFRESH_MS = 500;
(function tick() {
  refresh().finally(() => setTimeout(tick, REFRESH_MS));
})();
// The zero-sum check, on its own timer. Once now, so the Accounts table holds
// every account within a second of the page opening, and every 30 seconds
// after that. See renderZeroSum for why it is not on the 500ms timer and why
// it does not ask the exchange for the total.
walkPositions();
setInterval(walkPositions, ZERO_SUM_EVERY_MS);
