# Glossary

One name for each thing. This file is the source. The user interface, the
README and the reference documentation all use these names.

Two vocabularies existed before this file. The documentation said "the feed"
130 times. The user interface said "the sequencer". They are the same program.
A reader who read one and then opened the other had to work out that two words
meant one thing.

Source code keeps the short module names. `feed.rs` cannot become
`sequencer.rs` without changing every import for no gain. The table below is
the mapping, so a difference between a file name and a screen is documented
instead of confusing.

## The programs

| Name to use | Module | What it does |
|---|---|---|
| the sequencer | `feed.rs` | Puts messages in order. Signs the log. Serves the messages. |
| part of the sequencer | `feed/tree.rs` | Keeps the log's Merkle tree as rows in `feed.db`, and serves the proofs from them. |
| the exchange | `matcher.rs` | Runs the messages. Matches orders. Signs what it did. |
| the separate service | `inbox.rs` | Records an order that the sequencer must then put in the log. |
| a validator | `validator.rs` | Reads the log and says which messages it saw, in which order. |
| the checker | `verify.rs` | Runs the messages again with different code, and compares. |
| part of the checker | `verify/self_trade.rs` | The checker's own copy of the self-trade rule, and its two checks. |
| part of the checker | `verify/order_terms.rs` | The checker's own copy of the order types, the reference price and the collar. |
| part of the checker | `verify/listings.rs` | The checker's own copy of the listing rule, on both walks of the log. |
| part of the checker | `verify/operator_key.rs` | The checker's own copy of the operator rule, worked out again from the log's own messages. |
| part of the checker | `verify/trades.rs` | Reads the run's trade record one row at a time and holds no row, so the checker's peak memory does not follow the length of the history. |
| part of the checker | `verify/testkit.rs` | The test builders the checker's modules share. Test builds only. |
| the audit | `prove.rs` | Checks the exchange's claims against the log. |
| shared by the checker and the audit | `reporting.rs` | Counts the rows one check read, prints what failed, and checks the signed head. |
| the bot | `bot.rs` | Places orders so the market has traffic. |
| the anchor sender | `anchor/` | Writes a commitment to Base every five minutes. |

## The things

| Name to use | What it means |
|---|---|
| the log | Every message, in order. |
| a message | One order, or one cancel. The unit the log holds. |
| a message number | The position of a message in the log. Starts at 1. |
| the chain hash | One hash that covers every message up to a point. |
| a session | A name for one log. A log with nothing signed in it yet gets a new session. Such a log is a new file, or a file that was emptied. |
| the book | The orders that are waiting to trade. |
| a resting order | An order in the book, waiting. |
| the taker | The order that arrives and trades against the book. |
| the maker | The order that was already in the book. |
| a claim | The exchange's signed statement of what a set of messages produced. |
| the state root | One hash that covers everything the exchange holds. |
| an anchor | A commitment written to Base, so a third party holds it. |
| the price step | The smallest price change allowed. |
| the quantity step | The smallest quantity change allowed. |
| the steps | The price step and the quantity step together. A price must be a whole number of price steps, and a quantity a whole number of quantity steps. |
| the matching engine | The part of the exchange that matches orders. Use this only when the distinction from the whole program matters. |
| the operator | The owner of the exchange. Only the operator opens a market, closes one, or changes the rule set. |
| the operator key | The one Ed25519 key the exchange trusts for the operator's messages. The sequencer is told its public key and publishes no message signed by another key. |
| the rule set | The version of the matching rules the messages after it run under. Message 1 names the first one. |

## Words to avoid

| Do not write | Write | Why |
|---|---|---|
| quorum | validators agree | "Quorum" needs to be looked up. |
| fold, re-hash | hash again | Two words for one action. |
| durable | written to disk | Says what happens. |
| off-grid | off the price step | "Grid" is not defined anywhere. |
| overdue | late | Shorter, and means the same. |
| canonical bytes | the bytes that were hashed | Says which bytes. |
| the feed | the sequencer | Two names for one program. |
| the matcher | the exchange | Two names for one program. |
| the inbox | the separate service | Two names for one program. |
| escape hatch, escape-hatch, the hatch | the separate service | A metaphor, and the thing already has a name. |

`services/tests/banned_words.rs` reads this repository and fails when a phrase
this table bans is written again. It enforces the last row only; the rows above
it are not obeyed everywhere yet, so enforcing them all today would fail on
code nobody has changed. Add a phrase to that test when its row is clean.

## How to write

Reference documents, `README.md` and `docs/API.md`, use Simplified Technical
English:

- One word, one meaning. Never change the word for a thing.
- 20 words in a sentence for an instruction. 25 for a description.
- One idea in each sentence.
- Active voice. Present tense.
- No metaphors. No idioms.

Story documents, `services/ROADMAP.md` and `docs/BOT.md`, explain decisions and
investigations. They keep the names from the tables above. They may use a longer
form that states the problem, suspects, rejected causes, actual cause, and
smallest successful fix.

The names do not change between the two. Only the shape does.
