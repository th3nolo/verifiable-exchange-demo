//! The exchange, behind the market-harness stdio protocol.
//!
//! `docs/GENERATOR-RFC.md` describes an order-flow generator and a set of
//! market-health checks. A separate Rust workspace, `market-harness`,
//! implements them. It holds its own matching engine, its own generator, and
//! 18 checks. It can drive **another** engine over a pipe, and score that
//! engine with the same 18 checks.
//!
//! This module is that other engine. It reads the harness's commands on
//! standard input, drives a real `MatcherState`, and writes the harness's
//! events on standard output. Nothing of the harness is copied into this
//! repository. The harness stays a separate program.
//!
//! # The protocol
//!
//! One JSON object per line, both ways.
//!
//! The harness sends one `init` line first:
//!
//! ```text
//! {"type":"init","markets":[{"name":"M1","tick_size":0.01}],"stp":"reject_incoming"}
//! ```
//!
//! This module answers `{"type":"ready"}`.
//!
//! Then the harness sends one command line at a time:
//!
//! ```text
//! {"type":"command","cmd_seq":7,"command":{"type":"Limit","symbol":0,
//!  "order_id":1099511627777,"account":3,"side":"Buy","price_ticks":9990,"qty":1}}
//! ```
//!
//! This module answers with zero or more event lines and then one terminator:
//!
//! ```text
//! {"type":"Trade","seq":12,"symbol":0,"price_ticks":9990,"qty":1,...}
//! {"type":"events_end","cmd_seq":7}
//! ```
//!
//! Event `seq` counts up and never repeats. Standard output carries events and
//! nothing else. Every log line goes to standard error.
//!
//! # The price conversion, exactly
//!
//! This is the one place a unit error can hide, so it is written out.
//!
//! **Both engines match on whole numbers, so this conversion is a whole number
//! to a whole number.** Nothing is rounded and nothing is scaled.
//!
//! The harness carries a price as a whole number of ticks. A tick is not a
//! money amount there: `tick_size` on a market is a display number and its
//! engine never reads it. A price of 9990 ticks means "level 9990 on the price
//! ladder", and every check the harness runs measures a distance in ticks.
//!
//! This exchange carries a price as a whole number of cents. `matcher.rs` keeps
//! each book as `BTreeMap<i64, VecDeque<RestingOrder>>`, and matching step 5
//! compares and subtracts those `i64` prices for the whole match. There is no
//! `f64` on the matching path. The `f64` lives at the edge only: on the wire,
//! where `domain::to_grid` turns it into a whole number of cents once, on the
//! way in.
//!
//! **Why that matters here.** A price this exchange disagrees with the harness
//! about is a difference in a matching rule. It cannot be a lost decimal,
//! because no decimal is carried into a book on either side. The report on this
//! run rests on that.
//!
//! ## The two ladders have the same origin
//!
//! Checked, and not assumed. A constant offset between the two would pass every
//! smoke test and then fail every check for a reason nobody could see.
//!
//! | | the harness | this exchange |
//! |---|---|---|
//! | what a price is | `Ticks(i64)`, a level | `i64`, whole cents |
//! | lowest price it takes | 1 | 1 |
//! | what it does with 0 or less | refuses it: `BadPrice` | refuses it: `off_grid` |
//! | highest price it takes | whatever an `i64` holds | 1,000,000,000 (`domain::MAX_GRID_UNITS`) |
//! | step between two prices | 1 | 1, because `price_step` is 0.01 |
//!
//! Both ladders count 1, 2, 3 upward from a zero neither of them takes. So the
//! two agree at every level with no offset, and
//!
//! ```text
//! price_cents = price_ticks
//! ```
//!
//! **One harness tick is one cent.** A distance of 3 ticks in the harness is a
//! distance of 3 cents here, so every check that counts ticks reads this
//! exchange the way it reads its own engine.
//!
//! The two ends do not match, and both ends are far away. The harness's
//! generator floors a price at 1 tick, which is the lowest price this exchange
//! takes as well. The top is the real difference: this exchange refuses a price
//! above 1,000,000,000 cents and the harness's engine does not. Over 200,000
//! messages the two scenarios used prices from 961 to 100,586 ticks, which is
//! four orders of magnitude below that limit.
//!
//! ## What the wire hop does to the number
//!
//! `OrderMessage::New` carries `price` as an `f64`, so the whole number takes
//! one hop through a float and `domain::to_grid` turns it back:
//!
//! ```text
//! price_ticks  ->  price_ticks as f64 / 100.0  ->  to_grid(.., 100.0)  ->  price_cents
//! ```
//!
//! It gives the same whole number back over the whole range. An `f64` holds
//! every whole number up to 9,007,199,254,740,992 exactly, so `n as f64` loses
//! nothing. The divide and the multiply each round once, and two roundings of a
//! number below 1,000,000,000 move it by less than 0.0000003. `to_grid` takes
//! anything within 0.000001 of a whole number and rounds it. The test
//! `the_wire_hop_gives_the_same_whole_number_back` checks both ends of the
//! range and the prices these scenarios use.
//!
//! ## What the harness's tick size becomes
//!
//! Nothing. This module reads `tick_size` off the `init` line and drops it, and
//! dropping it is right. The harness's fixed scenario lists market M1 with
//! `tick_size` 0.001, which is a tenth of a cent, and this exchange holds whole
//! cents only. Multiplying by `tick_size` would round two neighbouring ticks
//! onto one cent and lose the ladder. The prices printed here are therefore not
//! the harness's display prices, and no check reads a display price. M1 shows
//! 100.00 here where the harness shows 10.000.
//!
//! ## Quantity
//!
//! The same shape, and easier. The harness sends a whole number of units. This
//! exchange holds whole tenths, and lists every market with `quantity_step`
//! 0.1. So `qty_tenths = qty * 10`, and every fill comes back a whole number of
//! tenths that divides by 10, because every quantity that ever entered a book
//! was a whole number of units.
//!
//! # What a market becomes
//!
//! The harness's `init` line names its markets. Each one becomes one
//! `ListSymbol` message in this exchange's log, under the market's own name
//! (`M1`, `M2`, `M3`), with `price_step` 0.01 and `quantity_step` 0.1. The
//! names pass `operator::valid_symbol`, which allows `A`-`Z`, `0`-`9` and `-`.
//!
//! An `EngineRule` message naming rule set 2 goes in front of the listings.
//! Rule set 2 is the self-trade rule, and the harness runs its engine with
//! self-trade prevention on. Without that message this exchange would run under
//! rule set 1 and let an account trade with itself, which the harness counts as
//! a hard fault.
//!
//! Those messages are operator messages, so they carry an Ed25519 signature.
//! This module makes one signing key from a fixed 32 bytes and signs with it.
//! The key names nobody. It exists because the exchange refuses an unsigned
//! listing, and a run of this module leaves no log anybody keeps.
//!
//! # Time
//!
//! The harness has no clock. Logical time is the message number, and a
//! scenario states how many messages a second the incident ran at. This
//! exchange needs a millisecond on every message, because the collar's
//! reference price is an average of the middle price over the last 30,000
//! milliseconds (ENGINE.md section 4.2.1).
//!
//! So this module turns the command number into a millisecond:
//!
//! ```text
//! timestamp = command_number * 1000 / messages_per_second
//! ```
//!
//! `--stdio-messages-per-second` sets the rate, and 6 is the incident's rate.
//! At 6 a second, the 30,000 millisecond window holds 180 commands.
//!
//! # How to run it
//!
//! The harness spawns this program. Build both, then, from the harness's own
//! directory:
//!
//! ```text
//! market-harness verify-external \
//!     --scenario scenarios/fixed.toml \
//!     --engine-cmd "/path/to/services --stdio-engine" \
//!     --messages 200000 --out out-ours
//! ```
//!
//! It prints the 18 checks and writes `out-ours/health.json`. It exits 0 when
//! every check passes and every correctness invariant held.
//!
//! Measured on 16 August 2026, 200,000 messages, seed 42, on both scenarios:
//! no correctness invariant was broken on either run. `scenarios/fixed.toml`
//! passed all 18 checks, which is what the harness's own engine does.
//! `scenarios/buggy.toml` failed 14 of 18, where the harness's own engine
//! fails 13. The one difference is matching step 4, and section 4.1 of
//! `docs/ENGINE.md` states this exchange's rule.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufWriter, Write};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::domain::{
    AccountId, OPERATOR_ACCOUNT, OrderId, OrderMessage, OrderType, Side, TimeInForce,
};
use crate::matcher::MatcherState;
use crate::operator;

/// The 32 bytes the operator signing key is made from. Any fixed value works.
/// The key signs the listings and the rule-set message this module writes, and
/// it names nobody.
const KEY_BYTES: [u8; 32] = [0x5a; 32];

/// The rule set that turns the self-trade rule on. `matcher/step4_self_trade_check.rs`
/// holds the rule. The harness runs its own engine with self-trade prevention
/// on, so this exchange must run with it on too.
const SELF_TRADE_RULE_SET: u32 = 2;

/// The price step every market is listed with: 0.01 means every whole cent is
/// a price, so one harness tick is one cent. See the module comment.
const PRICE_STEP: f64 = 0.01;

/// The quantity step every market is listed with: 0.1 means every whole tenth
/// is a quantity, so one harness unit is ten tenths.
const QUANTITY_STEP: f64 = 0.1;

/// The price a market buy order signs. The collar in matching step 3 pulls it
/// down to the reference price plus 2 percent, so the number only has to be
/// far above any price the harness quotes. `domain::MAX_GRID_UNITS` is the
/// largest price the exchange takes, in cents.
const MARKET_BUY_CEILING_CENTS: i64 = crate::domain::MAX_GRID_UNITS;

/// The price a market sell order signs. The collar pulls it up to the
/// reference price minus 2 percent. One cent is the smallest price the
/// exchange takes.
const MARKET_SELL_FLOOR_CENTS: i64 = 1;

/// One line the harness sends.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Incoming {
    /// The first line: the markets and the self-trade mode.
    #[serde(rename = "init")]
    Init {
        markets: Vec<MarketSpec>,
        #[allow(dead_code)]
        stp: String,
    },
    /// One command, with the number the terminator must repeat.
    #[serde(rename = "command")]
    Command { cmd_seq: u64, command: Order },
}

/// One market on the harness's `init` line. `tick_size` is read and dropped.
/// The module comment says why.
#[derive(Debug, Deserialize)]
struct MarketSpec {
    name: String,
    #[allow(dead_code)]
    tick_size: f64,
}

/// One command from the harness. The field names and the shape are the
/// harness's, not this repository's.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Order {
    /// A limit order, good till cancel.
    Limit {
        symbol: u16,
        order_id: u64,
        account: AccountId,
        side: Side,
        price_ticks: i64,
        qty: u64,
    },
    /// A market order. It never rests.
    Market {
        symbol: u16,
        order_id: u64,
        account: AccountId,
        side: Side,
        qty: u64,
    },
    /// Take a resting order off the book.
    Cancel { symbol: u16, order_id: u64 },
}

/// One event this module writes. The field names and the shape are the
/// harness's. `serde` writes `Ticks` as a plain number there, so a price is an
/// `i64` here.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum Emitted {
    /// The exchange took the order. For a limit order the part that does not
    /// fill rests.
    OrderAccepted {
        seq: u64,
        symbol: u16,
        order_id: u64,
        account: AccountId,
        side: Side,
        price_ticks: Option<i64>,
        qty: u64,
        market: bool,
    },
    /// The exchange refused the order and changed nothing.
    OrderRejected {
        seq: u64,
        symbol: u16,
        order_id: u64,
        account: AccountId,
        reason: &'static str,
    },
    /// A fill between the arriving order and one resting order.
    Trade {
        seq: u64,
        symbol: u16,
        price_ticks: i64,
        qty: u64,
        aggressor: u64,
        resting: u64,
        accounts: (AccountId, AccountId),
    },
    /// Quantity left the book without filling.
    OrderCancelled {
        seq: u64,
        symbol: u16,
        order_id: u64,
        account: AccountId,
        qty: u64,
        reason: &'static str,
    },
}

/// What this module remembers about one order the harness sent.
#[derive(Debug, Clone, Copy)]
struct Placed {
    /// The message number the exchange knows the order by.
    message_id: OrderId,
    /// The account that sent it. A `Cancel` from the harness names no account,
    /// and the exchange only lets the owner cancel.
    account: AccountId,
    /// The market index the harness numbers the order under.
    symbol: u16,
}

/// The exchange, and everything needed to speak the harness's protocol over it.
struct Bridge {
    engine: MatcherState,
    /// Market index to symbol name. The harness numbers its markets from 0.
    symbols: Vec<String>,
    /// The message number the next message this module writes carries. The
    /// exchange takes message numbers 1, 2, 3 and refuses a gap.
    next_message_id: OrderId,
    /// The harness's order number to what the exchange knows about it.
    placed: HashMap<u64, Placed>,
    /// The exchange's message number back to the harness's order number. A
    /// fill names the resting order by the exchange's number, and the harness
    /// only knows its own.
    harness_ids: HashMap<OrderId, u64>,
    /// The event number. It counts up and never repeats.
    seq: u64,
    /// How many refusals the exchange has counted, by reason. The exchange
    /// answers `Ok(())` for a refused order, so this module reads the counters
    /// to find out what happened.
    refusals: BTreeMap<String, u64>,
    /// The total of `refusals`. Comparing one number is cheaper than comparing
    /// the map, and the map is only read when this number moves.
    refusals_total: u64,
    /// Messages a second, for turning a command number into a millisecond.
    messages_per_second: f64,
}

impl Bridge {
    /// Build the exchange, list the markets, and turn the self-trade rule on.
    fn start(markets: &[MarketSpec], messages_per_second: f64) -> Bridge {
        let key = SigningKey::from_bytes(&KEY_BYTES);
        let mut bridge = Bridge {
            engine: MatcherState::new(),
            symbols: markets.iter().map(|m| m.name.clone()).collect(),
            next_message_id: 1,
            placed: HashMap::new(),
            harness_ids: HashMap::new(),
            seq: 0,
            refusals: BTreeMap::new(),
            refusals_total: 0,
            messages_per_second,
        };

        // The rule-set message goes first. Rule set 2 is the self-trade rule,
        // and an order matched before it arrives may trade with itself.
        let id = bridge.take_message_id();
        let rule = operator::signed_as(
            &key,
            "",
            OrderMessage::EngineRule {
                id,
                timestamp: 0,
                account: OPERATOR_ACCOUNT,
                version: SELF_TRADE_RULE_SET,
                nonce: Some(format!("{id:032x}")),
                public_key: String::new(),
                signature: String::new(),
            },
        );
        bridge.write_message(&rule);

        // One listing per market the harness named.
        for name in bridge.symbols.clone() {
            let id = bridge.take_message_id();
            let listing = operator::signed_as(
                &key,
                "",
                OrderMessage::ListSymbol {
                    id,
                    timestamp: 0,
                    account: OPERATOR_ACCOUNT,
                    symbol: name,
                    price_step: PRICE_STEP,
                    quantity_step: QUANTITY_STEP,
                    nonce: Some(format!("{id:032x}")),
                    public_key: String::new(),
                    signature: String::new(),
                },
            );
            bridge.write_message(&listing);
        }

        // A listing the exchange refused would leave a market that takes no
        // order, and every later check would read an empty book. Say so now,
        // and not 200,000 commands later.
        for (index, name) in bridge.symbols.iter().enumerate() {
            assert!(
                bridge.engine.is_listed(name),
                "market {index} ({name}) is not listed: the exchange refused the listing"
            );
        }
        bridge
    }

    /// The next message number, and step the counter.
    fn take_message_id(&mut self) -> OrderId {
        let id = self.next_message_id;
        self.next_message_id += 1;
        id
    }

    /// Hand one message to the exchange and read the refusal counters again.
    fn write_message(&mut self, message: &OrderMessage) {
        self.engine
            .apply_message(message)
            .expect("this module numbers its own messages, so they are always in order");
        self.refusals = self.engine.orders_ignored_by_kind().clone();
        self.refusals_total = self.refusals.values().sum();
    }

    /// The next event number.
    fn take_seq(&mut self) -> u64 {
        let seq = self.seq;
        self.seq += 1;
        seq
    }

    /// The millisecond a command carries. See the module comment.
    fn timestamp(&self, cmd_seq: u64) -> u64 {
        ((cmd_seq as f64) * 1000.0 / self.messages_per_second) as u64
    }

    /// Which refusal the exchange counted for the message it just read, or
    /// `None` when it counted none.
    ///
    /// The exchange answers `Ok(())` for an order it refuses. The reason is a
    /// counter and a log line, so this is the only way to read it back. The
    /// total moves first, and the map is only walked when it does.
    fn refusal(&mut self) -> Option<String> {
        let counted = self.engine.orders_ignored_by_kind();
        let total: u64 = counted.values().sum();
        if total == self.refusals_total {
            return None;
        }
        let grew = counted
            .iter()
            .find(|(kind, count)| **count > self.refusals.get(*kind).copied().unwrap_or(0))
            .map(|(kind, _)| kind.clone());
        self.refusals = counted.clone();
        self.refusals_total = total;
        grew
    }

    /// One command from the harness, and the events it produced.
    fn command(&mut self, cmd_seq: u64, order: Order) -> Vec<Emitted> {
        match order {
            Order::Limit {
                symbol,
                order_id,
                account,
                side,
                price_ticks,
                qty,
            } => self.new_order(
                cmd_seq,
                symbol,
                order_id,
                account,
                side,
                price_ticks,
                qty,
                OrderType::Limit,
            ),
            Order::Market {
                symbol,
                order_id,
                account,
                side,
                qty,
            } => {
                // A market order signs a price the collar can only tighten.
                // ENGINE.md section 4.2: this exchange has one resting order
                // type, and a market order is a limit order priced to cross.
                let price_ticks = match side {
                    Side::Buy => MARKET_BUY_CEILING_CENTS,
                    Side::Sell => MARKET_SELL_FLOOR_CENTS,
                };
                self.new_order(
                    cmd_seq,
                    symbol,
                    order_id,
                    account,
                    side,
                    price_ticks,
                    qty,
                    OrderType::Market,
                )
            }
            Order::Cancel { symbol, order_id } => self.cancel(cmd_seq, symbol, order_id),
        }
    }

    /// A limit or market order.
    #[allow(clippy::too_many_arguments)]
    fn new_order(
        &mut self,
        cmd_seq: u64,
        symbol: u16,
        order_id: u64,
        account: AccountId,
        side: Side,
        price_ticks: i64,
        qty: u64,
        order_type: OrderType,
    ) -> Vec<Emitted> {
        let market = order_type == OrderType::Market;
        let Some(name) = self.symbols.get(symbol as usize).cloned() else {
            let seq = self.take_seq();
            return vec![Emitted::OrderRejected {
                seq,
                symbol,
                order_id,
                account,
                reason: "UnknownSymbol",
            }];
        };

        let message_id = self.take_message_id();
        self.placed.insert(
            order_id,
            Placed {
                message_id,
                account,
                symbol,
            },
        );
        self.harness_ids.insert(message_id, order_id);

        let trades_before = self.engine.trades_total();
        // price_cents == price_ticks, and qty_tenths == qty * 10. The module
        // comment states both conversions.
        let message = OrderMessage::New {
            id: message_id,
            timestamp: self.timestamp(cmd_seq),
            account,
            symbol: name,
            side,
            price: price_ticks as f64 / 100.0,
            quantity: qty as f64,
            nonce: None,
            order_type,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        };
        self.write_message_without_counters(&message);

        let trades_after = self.engine.trades_total();
        let rested_tenths = self
            .engine
            .open_order(message_id)
            .map_or(0, |(_, _, _, tenths)| tenths);
        let refusal = self.refusal();

        // A refusal that filled nothing and rested nothing is a plain refusal.
        // A refusal after a fill is not: matching step 5 stops on a position
        // that would overflow, and the fills before it are real. Those events
        // must be written, or the quantity the harness counts stops adding up.
        let refused_outright =
            refusal.filter(|_| trades_after == trades_before && rested_tenths == 0);
        if let Some(kind) = refused_outright {
            let seq = self.take_seq();
            return vec![Emitted::OrderRejected {
                seq,
                symbol,
                order_id,
                account,
                reason: reject_reason(&kind),
            }];
        }

        let mut events = Vec::new();
        let seq = self.take_seq();
        events.push(Emitted::OrderAccepted {
            seq,
            symbol,
            order_id,
            account,
            side,
            // A market order carries no price here. The harness's own engine
            // writes `null` for one, and its book never rests it.
            price_ticks: (!market).then_some(price_ticks),
            qty,
            market,
        });

        let mut filled_tenths = 0;
        for trade_id in (trades_before + 1)..=trades_after {
            let trade = self
                .engine
                .trade(trade_id)
                .expect("a trade this message made is still in the window");
            let price_cents = (trade.price * 100.0).round() as i64;
            let qty_tenths = (trade.quantity * 10.0).round() as i64;
            let maker_account = trade.maker_account;
            let maker = *self
                .harness_ids
                .get(&trade.maker_order)
                .expect("every resting order came from a command the harness sent");
            filled_tenths += qty_tenths;
            let seq = self.take_seq();
            events.push(Emitted::Trade {
                seq,
                symbol,
                price_ticks: price_cents,
                qty: tenths_to_units(qty_tenths),
                aggressor: order_id,
                resting: maker,
                accounts: (account, maker_account),
            });
        }

        // What was neither filled nor left resting has gone. A market order
        // never rests, so its whole unfilled part goes here.
        let submitted_tenths = (qty as i64) * 10;
        let gone_tenths = submitted_tenths - filled_tenths - rested_tenths;
        if gone_tenths > 0 {
            let seq = self.take_seq();
            events.push(Emitted::OrderCancelled {
                seq,
                symbol,
                order_id,
                account,
                qty: tenths_to_units(gone_tenths),
                reason: if market { "MarketRemainder" } else { "User" },
            });
        }
        events
    }

    /// Take a resting order off the book.
    fn cancel(&mut self, cmd_seq: u64, symbol: u16, order_id: u64) -> Vec<Emitted> {
        let placed = self.placed.get(&order_id).copied();
        let resting = placed.and_then(|p| {
            self.engine
                .open_order(p.message_id)
                .map(|(_, _, _, tenths)| (p, tenths))
        });
        let Some((placed, resting_tenths)) = resting else {
            // The harness asked for an order this exchange is not holding. Its
            // own engine answers the same way, and neither book changes.
            let seq = self.take_seq();
            return vec![Emitted::OrderRejected {
                seq,
                symbol,
                order_id,
                account: placed.map_or(0, |p| p.account),
                reason: "UnknownOrder",
            }];
        };

        let message_id = self.take_message_id();
        let message = OrderMessage::Cancel {
            id: message_id,
            timestamp: self.timestamp(cmd_seq),
            account: placed.account,
            target_id: placed.message_id,
            nonce: None,
        };
        self.write_message_without_counters(&message);
        let _ = self.refusal();

        if self.engine.open_order(placed.message_id).is_some() {
            // The exchange kept the order. Nothing left the book, so nothing
            // is written.
            return Vec::new();
        }
        let seq = self.take_seq();
        vec![Emitted::OrderCancelled {
            seq,
            symbol: placed.symbol,
            order_id,
            account: placed.account,
            qty: tenths_to_units(resting_tenths),
            reason: "User",
        }]
    }

    /// Hand one trader's message to the exchange, and leave the refusal
    /// counters for `refusal` to read.
    fn write_message_without_counters(&mut self, message: &OrderMessage) {
        self.engine
            .apply_message(message)
            .expect("this module numbers its own messages, so they are always in order");
    }
}

/// Tenths to whole units.
///
/// Every quantity this module sends is a whole number of units, so every
/// quantity that ever rests is a whole ten tenths, and so is every fill: a
/// fill is at most what one resting order holds. The remainder is therefore
/// always zero, and the division loses nothing.
fn tenths_to_units(tenths: i64) -> u64 {
    debug_assert_eq!(tenths % 10, 0, "a quantity here is a whole number of units");
    (tenths / 10) as u64
}

/// What the harness calls the refusal this exchange counted.
///
/// The harness has seven reasons and this exchange has ten. The map is
/// therefore not one to one, and the report on this run names every place the
/// two differ. Nothing the harness checks reads this word: a refused order
/// changes no book, so the harness's own checks skip it. The word is for a
/// person reading the event log.
fn reject_reason(kind: &str) -> &'static str {
    match kind {
        "unlisted_symbol" => "UnknownSymbol",
        "off_price_step" | "off_grid" => "BadPrice",
        "off_quantity_step" => "BadQty",
        "self_trade" => "SelfTrade",
        // The exchange refuses a market order until it has watched a two-sided
        // book for a nonzero time (ENGINE.md section 4.2.2). The harness has
        // no word for that. `NoLiquidity` is its word for a market order it
        // cannot fill, which is the same outcome for the sender.
        "no_reference_price" => "NoLiquidity",
        // Neither of these can happen here: this module sends no post-only
        // order and no fill-or-kill order.
        "post_only_market" | "post_only_not_resting" | "post_only_would_take" => "BadPrice",
        "fill_or_kill_unavailable" | "fill_or_kill_collared" => "BadQty",
        // A fill that would take an account's position past what an `i64`
        // holds. The order stops where it is and does not rest.
        _ => "BadQty",
    }
}

/// Read the harness's commands on standard input and write its events on
/// standard output. It returns when standard input ends.
pub fn run(messages_per_second: f64) -> std::io::Result<()> {
    assert!(
        messages_per_second > 0.0,
        "--stdio-messages-per-second must be above zero"
    );
    let input = std::io::stdin();
    let mut output = BufWriter::new(std::io::stdout());
    let mut bridge: Option<Bridge> = None;

    for line in input.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let incoming: Incoming = match serde_json::from_str(&line) {
            Ok(incoming) => incoming,
            Err(e) => {
                eprintln!("stdio engine: cannot read {line:?}: {e}");
                continue;
            }
        };
        match incoming {
            Incoming::Init { markets, .. } => {
                let started = Bridge::start(&markets, messages_per_second);
                eprintln!(
                    "stdio engine: listed {} market(s) under rule set {}",
                    started.symbols.len(),
                    SELF_TRADE_RULE_SET
                );
                bridge = Some(started);
                writeln!(output, "{}", serde_json::json!({"type": "ready"}))?;
            }
            Incoming::Command { cmd_seq, command } => {
                let bridge = bridge
                    .as_mut()
                    .expect("the harness sends its init line before any command");
                for event in bridge.command(cmd_seq, command) {
                    writeln!(output, "{}", serde_json::to_string(&event)?)?;
                }
                writeln!(
                    output,
                    "{}",
                    serde_json::json!({"type": "events_end", "cmd_seq": cmd_seq})
                )?;
            }
        }
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three markets, named the way the harness names them.
    fn markets() -> Vec<MarketSpec> {
        vec![
            MarketSpec {
                name: "M1".to_string(),
                tick_size: 0.001,
            },
            MarketSpec {
                name: "M2".to_string(),
                tick_size: 0.01,
            },
        ]
    }

    /// A bridge over three markets, at the incident's 6 messages a second.
    fn bridge() -> Bridge {
        Bridge::start(&markets(), 6.0)
    }

    fn limit(order_id: u64, account: AccountId, side: Side, price_ticks: i64, qty: u64) -> Order {
        Order::Limit {
            symbol: 0,
            order_id,
            account,
            side,
            price_ticks,
            qty,
        }
    }

    #[test]
    fn a_market_the_harness_names_becomes_a_listed_symbol() {
        let bridge = bridge();
        assert!(bridge.engine.is_listed("M1"));
        assert!(bridge.engine.is_listed("M2"));
        assert_eq!(bridge.engine.listed_symbols(), vec!["M1", "M2"]);
    }

    #[test]
    fn one_harness_tick_is_one_cent() {
        // The harness says 9990 ticks. The exchange must hold 9990 cents, and
        // not 9990 times any tick size. The module comment states the rule.
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 9990, 1));
        assert_eq!(bridge.engine.best_bid_cents("M1"), Some(9990));

        // A market whose harness tick size is a tenth of a cent maps the same
        // way. Nothing rounds, so two neighbouring ticks stay two prices.
        bridge.command(2, limit(2, 3, Side::Buy, 9991, 1));
        assert_eq!(bridge.engine.best_bid_cents("M1"), Some(9991));
        assert_eq!(bridge.engine.level_qty_tenths("M1", Side::Buy, 9990), 10);
    }

    #[test]
    fn the_lowest_price_each_engine_takes_is_the_same_price() {
        // The two ladders must have the same origin. The harness refuses a
        // price of 0 or less as `BadPrice`, and its generator floors a price at
        // 1 tick. This exchange refuses 0 or less as `off_grid`. So 1 tick and
        // 1 cent are the same rung, and there is no offset between the two.
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 1, 1));
        assert_eq!(bridge.engine.best_bid_cents("M1"), Some(1));
    }

    #[test]
    fn the_wire_hop_gives_the_same_whole_number_back() {
        // A price takes one hop through an `f64` on the wire. Both ends of the
        // range, and the prices the two scenarios used over 200,000 messages.
        for ticks in [
            1,
            2,
            961,
            982,
            9990,
            10_200,
            100_586,
            crate::domain::MAX_GRID_UNITS,
        ] {
            assert_eq!(
                crate::domain::to_grid(ticks as f64 / 100.0, 100.0),
                Some(ticks),
                "{ticks} ticks must come back as {ticks} cents"
            );
        }
    }

    #[test]
    fn one_harness_unit_is_ten_tenths() {
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 9990, 7));
        assert_eq!(bridge.engine.level_qty_tenths("M1", Side::Buy, 9990), 70);
    }

    #[test]
    fn an_order_that_rests_is_accepted_and_nothing_else() {
        let mut bridge = bridge();
        let events = bridge.command(1, limit(1, 3, Side::Buy, 9990, 1));
        assert!(
            matches!(
                events.as_slice(),
                [Emitted::OrderAccepted {
                    seq: 0,
                    symbol: 0,
                    order_id: 1,
                    account: 3,
                    side: Side::Buy,
                    price_ticks: Some(9990),
                    qty: 1,
                    market: false,
                }]
            ),
            "{events:?}"
        );
    }

    #[test]
    fn a_crossing_order_prints_at_the_resting_price() {
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Sell, 10010, 2));
        // Account 4 buys at 10020, above the resting sell. The fill is at the
        // resting order's price, and not at the arriving order's price.
        let events = bridge.command(2, limit(2, 4, Side::Buy, 10020, 2));
        let printed: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Emitted::Trade {
                    price_ticks,
                    qty,
                    aggressor,
                    resting,
                    accounts,
                    ..
                } => Some((*price_ticks, *qty, *aggressor, *resting, *accounts)),
                _ => None,
            })
            .collect();
        assert_eq!(printed, vec![(10010, 2, 2, 1, (4, 3))]);
    }

    #[test]
    fn the_events_add_up_to_the_quantity_submitted() {
        // The harness adds up submitted, filled, cancelled and resting for
        // every order, and a run fails when they do not agree. Two fills and
        // one rest, from one arriving order.
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Sell, 10010, 1));
        bridge.command(2, limit(2, 5, Side::Sell, 10011, 1));
        let events = bridge.command(3, limit(3, 4, Side::Buy, 10011, 5));
        let filled: u64 = events
            .iter()
            .filter_map(|e| match e {
                Emitted::Trade { qty, .. } => Some(*qty),
                _ => None,
            })
            .sum();
        let cancelled: u64 = events
            .iter()
            .filter_map(|e| match e {
                Emitted::OrderCancelled { qty, .. } => Some(*qty),
                _ => None,
            })
            .sum();
        assert_eq!(filled, 2);
        assert_eq!(cancelled, 0);
        // 5 submitted, 2 filled, 3 left resting.
        let resting = bridge
            .engine
            .open_order(bridge.placed[&3].message_id)
            .map_or(0, |(_, _, _, tenths)| tenths);
        assert_eq!(resting, 30);
    }

    #[test]
    fn every_event_number_is_new_and_larger() {
        let mut bridge = bridge();
        let mut seen = Vec::new();
        bridge.command(1, limit(1, 3, Side::Sell, 10010, 1));
        bridge.command(2, limit(2, 4, Side::Sell, 10011, 1));
        for cmd_seq in 3..8 {
            let events = bridge.command(cmd_seq, limit(cmd_seq, 5, Side::Buy, 10011, 1));
            for event in &events {
                seen.push(match event {
                    Emitted::OrderAccepted { seq, .. }
                    | Emitted::OrderRejected { seq, .. }
                    | Emitted::Trade { seq, .. }
                    | Emitted::OrderCancelled { seq, .. } => *seq,
                });
            }
        }
        let mut sorted = seen.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(seen, sorted, "event numbers must count up and never repeat");
    }

    #[test]
    fn an_account_that_would_meet_its_own_order_is_refused() {
        // Rule set 2 is on, so matching step 4 refuses the arriving order.
        // The harness runs its own engine the same way, and it counts a fill
        // between one account and itself as a hard fault.
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Sell, 10010, 1));
        let events = bridge.command(2, limit(2, 3, Side::Buy, 10020, 1));
        assert!(
            matches!(
                events.as_slice(),
                [Emitted::OrderRejected {
                    order_id: 2,
                    account: 3,
                    reason: "SelfTrade",
                    ..
                }]
            ),
            "{events:?}"
        );
        // The resting order stays. Cancel newest, ENGINE.md section 4.1.
        assert_eq!(bridge.engine.best_ask_cents("M1"), Some(10010));
    }

    #[test]
    fn a_cancel_takes_the_order_off_the_book() {
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 9990, 4));
        let events = bridge.command(
            2,
            Order::Cancel {
                symbol: 0,
                order_id: 1,
            },
        );
        assert!(
            matches!(
                events.as_slice(),
                [Emitted::OrderCancelled {
                    order_id: 1,
                    account: 3,
                    qty: 4,
                    reason: "User",
                    ..
                }]
            ),
            "{events:?}"
        );
        assert_eq!(bridge.engine.best_bid_cents("M1"), None);
    }

    #[test]
    fn a_cancel_of_an_order_the_exchange_is_not_holding_is_refused() {
        let mut bridge = bridge();
        let events = bridge.command(
            1,
            Order::Cancel {
                symbol: 0,
                order_id: 99,
            },
        );
        assert!(
            matches!(
                events.as_slice(),
                [Emitted::OrderRejected {
                    order_id: 99,
                    reason: "UnknownOrder",
                    ..
                }]
            ),
            "{events:?}"
        );
    }

    #[test]
    fn a_market_order_with_no_reference_price_is_refused() {
        // ENGINE.md section 4.2.2: the collar has no reference price yet, so
        // the exchange refuses the order rather than fill it at any price.
        // The harness's own engine fills it, and the report names the
        // difference.
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Sell, 10010, 5));
        let events = bridge.command(
            2,
            Order::Market {
                symbol: 0,
                order_id: 2,
                account: 4,
                side: Side::Buy,
                qty: 1,
            },
        );
        assert!(
            matches!(
                events.as_slice(),
                [Emitted::OrderRejected {
                    order_id: 2,
                    reason: "NoLiquidity",
                    ..
                }]
            ),
            "{events:?}"
        );
    }

    #[test]
    fn a_market_order_fills_once_the_book_has_held_for_a_while() {
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 9990, 5));
        bridge.command(2, limit(2, 3, Side::Sell, 10010, 5));
        // Two commands later the two-sided book has held for 333 milliseconds,
        // so the reference price is a number and the collar has a band.
        let events = bridge.command(
            4,
            Order::Market {
                symbol: 0,
                order_id: 4,
                account: 4,
                side: Side::Buy,
                qty: 2,
            },
        );
        let accepted = events.iter().any(|e| {
            matches!(
                e,
                Emitted::OrderAccepted {
                    market: true,
                    price_ticks: None,
                    ..
                }
            )
        });
        let printed: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Emitted::Trade {
                    price_ticks, qty, ..
                } => Some((*price_ticks, *qty)),
                _ => None,
            })
            .collect();
        assert!(accepted, "a market order carries no price: {events:?}");
        assert_eq!(printed, vec![(10010, 2)]);
    }

    #[test]
    fn a_market_order_that_fills_nothing_leaves_as_a_cancel() {
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 9990, 5));
        bridge.command(2, limit(2, 3, Side::Sell, 10010, 1));
        bridge.command(3, limit(3, 9, Side::Buy, 10010, 1));
        // Every sell is gone, so the market buy fills nothing. It never rests,
        // so its whole quantity leaves as a cancel and the quantity the
        // harness counts still adds up.
        let events = bridge.command(
            4,
            Order::Market {
                symbol: 0,
                order_id: 4,
                account: 4,
                side: Side::Buy,
                qty: 3,
            },
        );
        assert!(
            matches!(
                events.as_slice(),
                [
                    Emitted::OrderAccepted { market: true, .. },
                    Emitted::OrderCancelled {
                        qty: 3,
                        reason: "MarketRemainder",
                        ..
                    }
                ]
            ),
            "{events:?}"
        );
    }

    #[test]
    fn each_market_keeps_its_own_book() {
        let mut bridge = bridge();
        bridge.command(1, limit(1, 3, Side::Buy, 9990, 1));
        bridge.command(
            2,
            Order::Limit {
                symbol: 1,
                order_id: 2,
                account: 3,
                side: Side::Buy,
                price_ticks: 500,
                qty: 1,
            },
        );
        assert_eq!(bridge.engine.best_bid_cents("M1"), Some(9990));
        assert_eq!(bridge.engine.best_bid_cents("M2"), Some(500));
    }

    #[test]
    fn a_market_the_harness_never_named_is_refused() {
        let mut bridge = bridge();
        let events = bridge.command(
            1,
            Order::Limit {
                symbol: 7,
                order_id: 1,
                account: 3,
                side: Side::Buy,
                price_ticks: 9990,
                qty: 1,
            },
        );
        assert!(
            matches!(
                events.as_slice(),
                [Emitted::OrderRejected {
                    reason: "UnknownSymbol",
                    ..
                }]
            ),
            "{events:?}"
        );
    }

    #[test]
    fn a_command_line_reads_as_the_harness_wrote_it() {
        // The harness's own words, from the protocol comment in
        // `market-health/src/adapter.rs`.
        let line = r#"{"type":"command","cmd_seq":7,"command":{"type":"Limit","symbol":0,"order_id":1099511627777,"account":3,"side":"Buy","price_ticks":9990,"qty":1}}"#;
        let incoming: Incoming = serde_json::from_str(line).expect("the harness's own line");
        match incoming {
            Incoming::Command { cmd_seq, command } => {
                assert_eq!(cmd_seq, 7);
                assert!(matches!(
                    command,
                    Order::Limit {
                        symbol: 0,
                        order_id: 1_099_511_627_777,
                        account: 3,
                        side: Side::Buy,
                        price_ticks: 9990,
                        qty: 1,
                    }
                ));
            }
            other => panic!("expected a command, got {other:?}"),
        }
    }

    #[test]
    fn an_event_writes_the_shape_the_harness_reads() {
        let trade = Emitted::Trade {
            seq: 12,
            symbol: 0,
            price_ticks: 9990,
            qty: 1,
            aggressor: 2,
            resting: 1,
            accounts: (3, 17),
        };
        assert_eq!(
            serde_json::to_string(&trade).expect("an event writes as JSON"),
            r#"{"type":"Trade","seq":12,"symbol":0,"price_ticks":9990,"qty":1,"aggressor":2,"resting":1,"accounts":[3,17]}"#
        );
    }
}
