mod cache;
mod db;
mod drain;
mod generate;
mod http;
mod limit;
mod metrics;
mod tree;

use axum::http::StatusCode;
use rand::Rng;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tracing::{Level, error, info, warn};
use tracing_subscriber::FmtSubscriber;

use crate::cors;
use crate::domain::{AccountId, OrderId, OrderMessage, SYMBOLS, to_grid};
use crate::inbox::{
    self, Clock, PRICE_SCALE, RateLimiter, TrustedProxies, log_trusted_proxies, wall_clock_ms,
    warn_if_public,
};
use crate::logchain::{self, Chain, EMPTY_CHAIN};
use crate::merkle::{self, Hash, MerkleTree, TreeError};
use crate::wire::{
    self, HEAD_CHAIN_HEADER, HEAD_LAST_ID_HEADER, HEAD_PUBKEY_HEADER, HEAD_SIGNATURE_HEADER,
    SESSION_HEADER,
};
use db::open_feed_db;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use generate::{MAX_OPEN_ORDERS, OpenOrder, a_life, band_of, produce_orders};
use http::run_server;
use limit::ReadLimiter;
use metrics::Metrics;
use tree::{Nodes, Unreadable};

/// The most messages any one `/orders` response returns.
///
/// Without a cap, `?since=0` on a sequencer that ran for a long time copies the
/// whole history while it holds the state lock. It then turns that copy into
/// one response held in memory. The generator and every other request wait for
/// it, and a history large enough takes the host's memory with it. `?n=<huge>`
/// did the same on request.
///
/// A consumer polls with `?since=` and takes more polls to catch up. The cap is
/// high on purpose. The generator is clamped to 1000 messages a second, so a
/// consumer that polls every 200ms still reads a whole page each time, with
/// room to spare.
pub const PAGE_LIMIT: usize = 1000;

/// The operator messages that must lead a deployment log before user or
/// generated traffic may enter it: one engine rule and one listing for each
/// compiled market.
///
/// The opening script publishes exactly this many messages. Holding every
/// other writer until the last one lands makes the opening deterministic. A
/// timing margin between four separate HTTP requests cannot provide that
/// guarantee on a loaded host.
pub const OPENING_MESSAGES: OrderId = 1 + SYMBOLS.len() as OrderId;

/// How many of the newest messages the sequencer keeps in memory.
///
/// The whole history lives in `feed.db` and is never deleted. This window is
/// only the part held in RAM, so `/orders` can answer the polls every live
/// consumer makes without reading the disk. Anything below the window is read
/// back from the database a page at a time (see `FeedState::page`).
///
/// 10,000 comes from two bounds, not from taste. It has to be at least
/// `PAGE_LIMIT` (1000), so any single response can be served from memory. It
/// also has to cover the largest lag a consumer can build up between polls. The
/// generator is clamped to 1000 messages a second and the exchange polls every
/// 200ms, so 10,000 is ten seconds of the fastest traffic this sequencer can
/// produce. A consumer would have to stop for that long before its next poll
/// costs a disk read. Above that it is only cost: the messages measured 600
/// bytes each in RAM, so this window is about 6 MB, and 100,000 would spend an
/// unnecessary 60 MB.
pub const MESSAGE_WINDOW: usize = 10_000;

/// Starts the sequencer. It sets up the logger, builds the first sequencer
/// state, and starts the order generator and the HTTP server.
///
/// With a database, every message is written to disk before it is published. A
/// restart reads the whole history back and continues the same message numbers
/// and the same session. A consumer cannot tell that the sequencer restarted. A
/// database the sequencer has never published into gets a new session instead.
/// That new session is what separates a database that was emptied behind the
/// sequencer's back from a database that is new.
///
/// Given the URL of the separate service, the sequencer reads that service on
/// every tick. Orders that users sent to the separate service go into the log
/// ahead of generated traffic. A sequencer that was told to read the service
/// and does not do so shows up on the service's own `/status` as overdue
/// entries.
///
/// `ui_origins` is the list of web origins whose browsers may submit here. It
/// is a flag and not a constant, because the user interface and this sequencer
/// share an origin in no deployment. On one machine they are two ports. Behind
/// a reverse proxy they are two hostnames or two paths.
///
/// `operator_key` is the one key whose `EngineRule`, `ListSymbol` and
/// `DelistSymbol` messages this sequencer publishes. Given a key, the sequencer
/// adds the `/operator` route and holds user, inbox and generated traffic until
/// the operator has written the complete opening. Without a key there is no
/// `/operator` route, and the sequencer generates orders as it did before the
/// key existed.
pub async fn start_feed(
    bind: IpAddr,
    port: u16,
    num_accounts: u32,
    rate: f64,
    db: Option<PathBuf>,
    inbox_url: Option<String>,
    ui_origins: Vec<String>,
    trusted_proxies: TrustedProxies,
    operator_key: Option<VerifyingKey>,
) {
    // The subscriber prints the log lines this process writes.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // The port is bound before the database is opened, on purpose. Only one
    // process can hold the port, so a second sequencer started by mistake dies
    // here, before it has touched feed.db. A second writer once slowed the live
    // sequencer's inserts enough to lose two messages. Binding the port first
    // makes that order of events impossible.
    let addr = SocketAddr::new(bind, port);
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(
                "could not bind feed to {}: {} (is another feed running? try --feed-port)",
                addr, e
            );
            std::process::exit(2);
        }
    };
    warn_if_public(addr, "an unauthenticated order-submission endpoint");

    // The wall clock is read once, here. Every message timestamp is that one
    // reading plus the monotonic time that passed since. Reading the wall clock
    // per message meant an `unwrap` on every submission and every tick. On a
    // host whose clock is before 1970, that `unwrap` panics while the state
    // lock is held. Rust then marks the lock as poisoned, so every later
    // request panics when it takes the lock. The process stays up and the port
    // stays open, so a supervisor sees a live service that answers nothing.
    let Some(wall_base_ms) = wall_clock_ms() else {
        error!("the system clock is before 1970; feed messages cannot be timestamped");
        std::process::exit(2);
    };

    let mut state = match &db {
        Some(path) => {
            // The signing key sits next to the database (feed.db -> feed.key),
            // so a copy takes both: the history, and the key that signs the
            // history.
            let key_path = path.with_extension("key");
            let signing_key = match logchain::load_or_create_key(&key_path) {
                Ok(key) => key,
                Err(e) => {
                    error!("cannot use signing key {}: {}", key_path.display(), e);
                    std::process::exit(2);
                }
            };
            match FeedState::with_db(num_accounts, path, signing_key, wall_base_ms) {
                Ok(state) => {
                    info!(
                        "feed database {}: session {}, {} messages verified, the newest {} held \
                         in memory",
                        path.display(),
                        state.session,
                        state.last_id(),
                        state.messages.len()
                    );
                    state
                }
                // The operator asked for a sequencer that writes to disk.
                // Publishing anyway would run a sequencer whose history cannot
                // survive a restart, and nothing would say so. Worse, it could
                // sign a history that is not the one it published. So the
                // sequencer stops here instead, as the exchange does for its
                // own state.
                Err(e) => {
                    error!("cannot use feed database {}: {}", path.display(), e);
                    std::process::exit(2);
                }
            }
        }
        None => {
            warn!(
                "no feed database: this feed keeps its history in memory only, \
                 and a restart loses every published message"
            );
            FeedState::new(num_accounts, wall_base_ms)
        }
    };
    info!(
        "feed public key: {}",
        logchain::to_hex(state.signing_key.verifying_key().as_bytes())
    );
    // These two fields are set after the state is built, and are not passed
    // through both constructors. They are the operator's deployment settings,
    // not part of the history a database restores.
    log_trusted_proxies(&trusted_proxies);
    state.trusted_proxies = trusted_proxies;
    state.operator_key = operator_key;
    match &state.operator_key {
        Some(key) => info!(
            "operator public key: {}. POST /operator publishes what that key signs",
            logchain::to_hex(key.as_bytes())
        ),
        None => info!("no operator key: this sequencer serves no /operator route"),
    }
    // The generator repeats this line later, but it is also printed at startup.
    // An operator who reads only the first lines then still learns why nothing
    // is published.
    if !state.log_is_open() {
        info!(
            "this log has {} of {} opening messages, so only POST /operator may publish",
            state.last_id().min(OPENING_MESSAGES),
            OPENING_MESSAGES
        );
    }

    // The sequencer state is wrapped so the generator task and the HTTP server
    // share one copy of it.
    let shared_state = Arc::new(Mutex::new(state));

    // The order generator runs in its own async task.
    let generator_state = Arc::clone(&shared_state);
    tokio::spawn(async move {
        produce_orders(generator_state, rate, inbox_url).await;
    });

    cors::log_ui_origins("feed", &ui_origins);

    // The HTTP server starts and answers the requests that arrive.
    run_server(shared_state, listener, ui_origins, operator_key).await;
}

/// Names one entry of the separate service across databases: the service's
/// epoch, and the entry id inside that epoch.
///
/// The epoch is half of the key because entry ids restart at 1 when the
/// separate service gets a new database. With the id alone as the key, this
/// sequencer's record "entry 1 became message 7" also applied to a *new* entry
/// 1 that held a different order. The sequencer marked that new entry with
/// message 7. The service refused the mark, because the content did not match.
/// The entry could then never go in the log and never be marked, and the code
/// had no way out of that state.
type InboxKey = (String, i64);

/// The key the sequencer stores a used nonce under: the account, and the 128
/// bits of the nonce, not its text. A nonce is a number a submission carries
/// once, so the same submission cannot be accepted twice. The account is part
/// of the key on purpose. Two accounts that draw the same nonce is a
/// coincidence with no meaning. If that counted as a repeat, anyone could block
/// another account's submissions by guessing its next nonce.
type NonceKey = (AccountId, [u8; inbox::NONCE_BYTES]);

/// The nonce key a published message uses, if the message carries a nonce.
fn nonce_key(msg: &OrderMessage) -> Option<NonceKey> {
    let nonce = inbox::canonical_nonce(msg.nonce()?)?;
    Some((msg.account(), nonce))
}

// ---------------------------------------------------------------------------
// A published message, as bytes
// ---------------------------------------------------------------------------
//
// The chain hashes the bytes of each message, one message after the other. The
// sequencer writes those bytes once, when it creates the message. Everything
// after that uses that one byte string: the hashing, the `feed_messages` row,
// and every page served.
//
// Making the bytes and reading the bytes back are different jobs, and the
// sequencer does both. It makes the bytes of a message it has just created. It
// is a reader for a message it loads out of its own database. That row is data,
// and serde writes what *this build* declares, not what the build that created
// the row declared. Turning a loaded message back into bytes is how the
// sequencer would serve bytes that do not hash to the chain value stored beside
// them. It is also how a sequencer binary older than its own `feed.db` would
// refuse to start over a history it published itself.
//
// So nothing below the producer ever turns a message back into bytes. Parsing
// stays, for the places that have to read what a message says rather than serve
// it.

/// One published message, held as the bytes the chain covers.
#[derive(Clone, Debug)]
struct Published {
    /// The message number. It is kept beside the bytes because the window is
    /// indexed by it, and every page and every head is measured against it.
    id: OrderId,
    /// The message's JSON, byte for byte as `feed_messages.json` holds it.
    /// Text rather than bytes because that is what the column is, and serde
    /// writes JSON as UTF-8.
    json: String,
}

/// How many unreadable messages the startup names one by one. After this many
/// it stops naming them and prints a count instead. A binary rolled back to an
/// older version can meet thousands of them, and one log line for each makes a
/// log nobody reads.
const UNREADABLE_REPORTED: usize = 5;

/// Where this sequencer keeps the history it has published, and the Merkle tree
/// over that history.
///
/// Not `crate::store`, which is the matching engine's state on disk.
///
/// One field, and not a connection next to a tree, because the two then cannot
/// disagree about which of them is in use. With a database the messages are
/// rows in `feed_messages`, the nodes are rows in `merkle_nodes`, and the only
/// part of the tree in memory is the number of leaves. Without a database there
/// is nowhere to put either, so the tree is the whole `MerkleTree` in RAM, and a
/// restart loses the tree along with every message.
///
/// The difference in memory is the reason `Storage` exists. The tree in memory
/// is a little under two hashes per message, and it grows for as long as the
/// sequencer runs. It was 8.5 MB of the resident memory of a sequencer holding
/// 134,500 messages, measured by starting the binary on the same database twice
/// (see `with_db`), and nothing in the design stopped it growing. Worse, the
/// tree was rebuilt from every stored message at every start. A history that had
/// grown past RAM could then not be started at all: the database was whole, and
/// there was no way to open it.
enum Storage {
    /// `--no-feed-db`. Nothing this sequencer publishes survives the process, so
    /// the tree does not either.
    Memory(MerkleTree),
    /// `feed.db`, and the number of leaves its `merkle_nodes` holds.
    Disk { conn: Connection, leaves: u64 },
}

impl Storage {
    /// The database. A reader falls back to it when the window does not hold
    /// what the reader wants, and a writer needs it to write at all.
    fn conn(&self) -> Option<&Connection> {
        match self {
            Storage::Memory(_) => None,
            Storage::Disk { conn, .. } => Some(conn),
        }
    }

    /// The tree's size: one leaf per published message.
    fn leaves(&self) -> u64 {
        match self {
            Storage::Memory(tree) => tree.len(),
            Storage::Disk { leaves, .. } => *leaves,
        }
    }

    /// The tree, in the form `merkle.rs` walks to make a root or a proof.
    fn nodes(&self) -> Nodes<'_> {
        match self {
            Storage::Memory(tree) => Nodes::Memory(tree),
            Storage::Disk { conn, leaves } => Nodes::Disk {
                conn,
                leaves: *leaves,
            },
        }
    }
}

/// Everything the sequencer holds at one moment.
pub struct FeedState {
    /// The newest `MESSAGE_WINDOW` messages, in log order. The whole history is
    /// `feed_messages` in the database. This window is the part kept in RAM, so
    /// an ordinary poll is answered without a disk read.
    ///
    /// The window has a limit because it used to have none. At 600 bytes a
    /// message in memory and 162 on disk, a sequencer that held its whole
    /// history in RAM eventually exhausted the deployment budget. It could then
    /// never start again, because the startup check loaded the same history a
    /// second time to verify it.
    ///
    /// Bytes, and not `OrderMessage` values, so a page served from here and the
    /// same page served from `feed_messages` are the same bytes. After a restart
    /// these *are* rows read back off the disk, and this sequencer did not write
    /// them: see `Published`.
    messages: VecDeque<Published>,
    /// The chain value after each message in `messages`, same length and same
    /// order. It is kept so a paged response can carry a head that stands
    /// exactly at the last message in that page. The last entry is `chain`.
    /// Messages below the window carry their chain value in the row beside them,
    /// and a page served from disk reads it there.
    chains: VecDeque<Chain>,
    /// The number the next message gets.
    next_id: OrderId,
    /// The price each symbol last traded at. The generator sets prices from the
    /// books it holds open, and reads this field only when one side of a book is
    /// empty. See `generate::remember_the_price`.
    mids: HashMap<String, f64>,
    /// The orders the generator sent and has not cancelled yet. They are the
    /// only orders it cancels. See `generate::OpenOrder`.
    open_orders: Vec<OpenOrder>,
    /// How many crossing orders the generator has sent. The three markets take
    /// turns at the next one, so every market trades on a cadence instead of
    /// whenever a random draw lands on it. See `generate::TAKE_EVERY`.
    crossings: u64,
    /// How many messages the generator has sent since the last crossing order.
    /// Cancels are not counted. See `generate::TAKE_EVERY`.
    since_crossing: u32,
    /// How many messages in a row the generator has spent on cancels. It stops
    /// spending every message on cancels when a book built for a busier
    /// activity state drains. See `generate::CANCELS_IN_A_ROW`.
    cancels_in_a_row: u32,
    /// Which activity state the generator is in: how many messages a second it
    /// sends now, and how far from the touch it places a quote. `produce_orders`
    /// builds it from the rate, so a state built anywhere else runs flat at the
    /// floor. See `generate::Activity`.
    activity: generate::Activity,
    /// The source of random numbers the generator draws from. It is held here,
    /// and not taken from the thread, so a test can seed it and get the same
    /// history twice.
    rng: rand::rngs::StdRng,
    /// The number of simulated accounts placing orders.
    num_accounts: u32,
    /// The name of this log. It is served with every response. See
    /// `SESSION_HEADER`.
    ///
    /// The name names a *signed history*, not a file. A restart onto a database
    /// that holds a checkpoint continues under the same name, because the
    /// history is the same. A database with no checkpoint gets a new name,
    /// because nothing was ever signed under the name that database holds. The
    /// name is written to disk in the same transaction as the first checkpoint,
    /// and nowhere else.
    session: String,
    /// Where messages are written before they are published, and where the
    /// Merkle tree over them is kept. See `Storage`.
    storage: Storage,
    /// A hash chain over every message published so far. Extending the chain is
    /// the last step of publishing, and the chain always covers exactly
    /// `messages`.
    ///
    /// The Merkle tree over the same messages holds one leaf per message, in log
    /// order, so leaf `n` is message `n + 1`. The leaf is
    /// `SHA-256(0x00 || stored bytes)`. Those are the same bytes this chain
    /// hashes, and the same bytes `/messages.ndjson` serves. A reader computes
    /// the leaf again from the line it was served, and needs to know nothing
    /// about what the message says.
    ///
    /// The tree stands beside the chain and does not replace it. Every consumer
    /// checks the chain today, so both are kept up to date for one commit. The
    /// commit that moves consumers to the tree deletes the chain. The tree lives
    /// in `storage` and not here, because it is the one part of this state that
    /// grows with the whole history.
    chain: Chain,
    /// The last signed tree head this process made, or `None` before the first
    /// one.
    ///
    /// It is kept for two jobs. RFC 9162 requires each timestamp to be later
    /// than the one before it, and the next timestamp is compared against this
    /// one. And when nothing has changed since this head, the sequencer serves
    /// it again instead of signing a new one.
    tree_head: Option<SignedTreeHead>,
    /// Signs the head of the log. It is loaded from a key file next to the
    /// database, so the sequencer keeps one key across restarts.
    signing_key: SigningKey,
    /// The entries of the separate service this sequencer has already put in
    /// the log, and the message number each one became. The record is written in
    /// the same transaction as the message itself. So a crash between writing
    /// the message and telling the service cannot put one entry in the log
    /// twice. After a restart the sequencer finds the entry here and only sends
    /// the mark again.
    inbox_sequenced: HashMap<InboxKey, OrderId>,
    /// Where message timestamps come from. See the note in `start_feed`.
    clock: Clock,
    /// Per-caller cap on `POST /order` and `POST /cancel`.
    limiter: RateLimiter,
    /// Per-caller cap on the read endpoints, counted in messages rather than
    /// requests. See `READ_BURST`.
    read_limiter: ReadLimiter,
    /// What `GET /metrics` answers with. It is an `Arc`, because the counting
    /// layer around the router uses the same counters without taking this lock.
    metrics: Arc<Metrics>,
    /// The proxies whose `X-Forwarded-For` header this sequencer believes when
    /// it decides which caller a submission is counted against. Empty by
    /// default. See `TrustedProxies` in `inbox.rs`.
    trusted_proxies: TrustedProxies,
    /// The one key that may publish an `EngineRule`, a `ListSymbol` or a
    /// `DelistSymbol` here. `--operator-key` names that key. `None` means this
    /// sequencer names no operator: it serves no `/operator` route, and it
    /// generates traffic from its first tick.
    ///
    /// The key is here as well as in the router because each non-operator path
    /// checks whether the opening is complete. See `log_is_open`.
    operator_key: Option<VerifyingKey>,
    /// The public key each account submits under. The key is fixed on that
    /// account's first accepted submission, and copied from `feed_accounts`.
    ///
    /// The keys are held in memory as well as on disk, because a sequencer
    /// started with `--no-feed-db` has no disk. That sequencer still refuses to
    /// let two keys share one account for as long as it runs. That is all a
    /// sequencer which forgets its history on restart can promise.
    accounts: HashMap<AccountId, VerifyingKey>,
    /// Which message each used `(account, nonce)` pair became. This map is the
    /// repeat check, and the sequencer is the only place it exists. Only the
    /// sequencer creates messages, so only the sequencer can refuse to create a
    /// second message from the same nonce.
    ///
    /// The map has no table of its own and needs none. Every nonce is inside the
    /// message it authorised, so the map is one pass over the history read back
    /// at startup. The map is therefore written to disk exactly as well as the
    /// history is, and an edit to it shows up exactly as well.
    ///
    /// Nothing here ever expires. The published history is never deleted (a gap
    /// in it already stops the start), so the set of used nonces is complete,
    /// and a repeat cannot wait for its record to fall out. The other option was
    /// a set with a size limit and a time limit. That option puts a clock in the
    /// path of `sequence_drained`. A sequencer that was down for long enough
    /// would then refuse a waiting entry that was never a repeat. Its own outage
    /// would then look like the sequencer holding an order out of the log on
    /// purpose.
    nonces: HashMap<NonceKey, OrderId>,
    /// How many stored messages this build could not read as an `OrderMessage`
    /// at startup. It is zero on every sequencer that has not been rolled back
    /// past a message kind its database holds.
    ///
    /// The history those messages belong to is still hashed, still checked
    /// against the signed checkpoint, and still served byte for byte. Hashing
    /// and serving do not need to know what a message means. This field counts
    /// the part of the startup that did need to know, the generator's last
    /// prices and the orders it can cancel, and did not get it.
    unreadable: u64,
}

/// The sequencer's own record of where its history stood the last time it
/// published. It is signed with the same key and the same statement as any
/// other head.
///
/// The checkpoint is what makes an edit to `feed.db` visible instead of hidden.
/// The old code computed the chain again from the stored messages. When the
/// stored links did not match, it *rewrote the links to match* and kept on
/// signing. An edit to the message text then cost one warning line, and after
/// that nothing told it apart from real history. There was nothing left to
/// compare against.
///
/// The checkpoint is that missing thing. It is a separate statement of what the
/// history was, and an edit to `feed_messages` does not update it. Faking the
/// checkpoint needs the sequencer's signing key, and anyone who holds that key
/// can rewrite the history anyway.
///
/// # Why the root is here too
///
/// `merkle_nodes` had the same problem the chain links had, and worse. The
/// startup check counted its rows and read its highest leaf index, and never
/// read a hash back. So a tree written over the top of it was served as the
/// sequencer's own: the same rows, the same leaf count, over messages that are
/// not the ones in `feed_messages`. A failed proof could not catch it, because
/// the root the sequencer signs is computed from those same rows. The rewrite
/// moves the root, and every proof over the rewritten tree checks out against
/// the moved root. `/sth` then carries the operator's own signature over a
/// commitment to messages that were never published.
///
/// So the root belongs in the one statement in this file that an edit to the
/// storage beside it does not update, the same as the chain does.
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    last_id: OrderId,
    /// Hex of the chain over messages 1..last_id.
    chain: String,
    /// Hex Ed25519 signature over `logchain::sign_head(session, last_id, chain)`.
    ///
    /// This field was left exactly as it was when the root was added below. A
    /// binary older than the database it opens, after an operator rolled a
    /// release back, reads this field, skips the two fields it has never heard
    /// of, and continues. If the root had gone into this signature instead, that
    /// binary would have reported its own whole history as signed by the wrong
    /// key, and refused to start.
    signature: String,
    /// Hex of `MTH` over messages 1..last_id: the root of the tree in
    /// `merkle_nodes` at the moment this checkpoint was written.
    ///
    /// It is `None` in a checkpoint written before this field existed. That is
    /// not a tree to trust less. It is no statement about the tree at all, so
    /// such a start builds the tree again from the messages instead of reading
    /// it. See `with_db`.
    #[serde(default)]
    root: Option<String>,
    /// Hex Ed25519 signature over
    /// `logchain::sign_checkpoint(session, last_id, chain, root)`. It covers all
    /// four values, and not the root alone. So a root cannot be copied out of
    /// another history's checkpoint, or out of an earlier point in this one.
    #[serde(default)]
    root_signature: Option<String>,
}

impl Checkpoint {
    /// The row a publish writes, signed under both statements.
    ///
    /// `to_string` cannot fail here, because every field is a number or a
    /// string. That is not true one field up in `sequence`, where a message
    /// carries `f64` prices, and serde refuses a price that is not finite.
    fn row(
        key: &SigningKey,
        session: &str,
        last_id: OrderId,
        chain: &Chain,
        root: &Hash,
    ) -> String {
        serde_json::to_string(&Checkpoint {
            last_id,
            chain: logchain::to_hex(chain),
            signature: logchain::to_hex(
                &logchain::sign_head(key, session, last_id, chain).to_bytes(),
            ),
            root: Some(logchain::to_hex(root)),
            root_signature: Some(logchain::to_hex(
                &logchain::sign_checkpoint(key, session, last_id, chain, root).to_bytes(),
            )),
        })
        .expect("a checkpoint is a number and four strings")
    }
}

impl FeedState {
    /// Builds a new sequencer state, with the first price of each symbol.
    pub fn new(num_accounts: u32, wall_base_ms: u64) -> Self {
        let mut mids = HashMap::new();
        for (symbol, mid, _) in SYMBOLS {
            mids.insert(symbol.to_string(), mid);
        }
        FeedState {
            messages: VecDeque::new(),
            chains: VecDeque::new(),
            next_id: 1,
            mids,
            open_orders: Vec::new(),
            crossings: 0,
            since_crossing: 0,
            cancels_in_a_row: 0,
            // The quiet state and nothing else, until `produce_orders` is told
            // the rate. A state built here and never given a rate publishes the
            // market this deployment ran before the activity state existed.
            activity: generate::Activity::of(generate::QUIET_RATE),
            rng: generate::new_rng(),
            num_accounts: num_accounts.max(1),
            session: new_session(),
            storage: Storage::Memory(MerkleTree::new()),
            chain: EMPTY_CHAIN,
            tree_head: None,
            signing_key: logchain::ephemeral_key(),
            inbox_sequenced: HashMap::new(),
            clock: Clock::from_wall(wall_base_ms),
            limiter: RateLimiter::new(),
            read_limiter: ReadLimiter::new(),
            metrics: Arc::new(Metrics::new()),
            // No proxy, until `start_feed` is told otherwise. A state built
            // anywhere else reads the socket address and no header. That is
            // every test, and `with_db`, which builds on this function.
            trusted_proxies: TrustedProxies::none(),
            // No operator, for the same reason, and set in the same place. A
            // sequencer that names no operator has no `/operator` route, and it
            // generates from its first tick.
            operator_key: None,
            accounts: HashMap::new(),
            nonces: HashMap::new(),
            unreadable: 0,
        }
    }

    /// Makes the generator draw the same random numbers on every run.
    ///
    /// For tests and for measurement only. A live sequencer seeds itself from
    /// the operating system in `new`, so two of them publish different
    /// histories.
    #[doc(hidden)]
    pub fn seed_the_generator(&mut self, seed: u64) {
        self.rng = generate::seeded_rng(seed);
    }

    /// The next message the generator would publish, stamped with the given
    /// millisecond.
    ///
    /// For measurement only. The time is a parameter because the generator
    /// cancels an order when the order's life ends, and a life is a number of
    /// milliseconds. A measurement that sent 50,000 messages through the real
    /// clock would take two hours. See `generate::generate_message_at`.
    #[doc(hidden)]
    pub fn generate_at(&mut self, timestamp: u64) -> OrderMessage {
        generate::generate_message_at(self, timestamp)
    }

    /// Opens the sequencer database, creates it if it is not there, and builds
    /// the sequencer state back from it.
    ///
    /// The start restores everything a consumer can see: the messages, the next
    /// message number, the session, and the hash chain. The generator's own
    /// values are computed from those messages: the last price of each market,
    /// and the orders it holds open. So the generator continues with the books
    /// it left, and not with empty ones.
    ///
    /// The chain is computed again from the stored bytes, and checked against
    /// the checkpoint the sequencer signed when it last published. The start
    /// refuses any difference, and the error names what did not match. A
    /// difference can be an edited message, a deleted message, a rewritten chain
    /// link, a cut end, or a missing checkpoint. Nothing is repaired.
    ///
    /// Refusing is the only correct option. The sequencer's signature is the
    /// evidence the whole design depends on. A sequencer that starts and signs a
    /// history it cannot show is the one it published makes that signature worth
    /// nothing. Refusing loses no data: the database is not changed, and an
    /// operator can look at it.
    ///
    /// # The one case that is neither continued nor refused
    ///
    /// A database with no checkpoint and no rows. There is nothing to refuse:
    /// no messages, no signature, nothing that disagrees with anything. There is
    /// nothing to continue either, because a checkpoint is the only record that
    /// a history was ever signed here. That start makes a new session instead of
    /// reading one back. A database that was emptied and a database that is new
    /// cannot be told apart: after `DELETE FROM feed_messages` and the delete of
    /// the checkpoint row, the two hold the same three facts, byte for byte, and
    /// the only thing left is a name whose history is gone. Reusing that name
    /// puts two histories under one name, signed by one key, with no way to tell
    /// them apart.
    ///
    /// This start writes nothing. The new session reaches the disk in the first
    /// publish's transaction, next to the checkpoint that gives the session a
    /// meaning. Until then the file is exactly as the operator left it.
    ///
    /// # Why the hashing never parses
    ///
    /// The rows are hashed as `json.as_bytes()`, exactly as they are stored and
    /// exactly as they are served. Parsing a row and hashing the result looks
    /// like the same thing and is not. Serde writes what this build declares, so
    /// a field or a message kind added after this binary was compiled comes back
    /// out missing. The hashing then reaches a chain the sequencer never signed.
    /// A sequencer binary older than its own `feed.db`, after an operator rolled
    /// a release back, would refuse to start. It would report its own history as
    /// edited, over a database that is whole.
    ///
    /// Parsing stays for the parts of the start that have to read what a message
    /// says: the generator's last price per symbol, and the orders it can
    /// cancel. A row this build cannot read is counted and named in the log. It
    /// does not stop the start, because nothing about the history depends on it.
    /// The nonces that block a repeat do not depend on it either. They are read
    /// out of the bytes (`wire::envelope`), so a nonce spent by a message kind
    /// this binary has never heard of is still spent.
    ///
    /// # Why this reads one row at a time
    ///
    /// The check reads the rows one at a time, and keeps only what it still
    /// uses: the running chain, the Merkle tree, the counters, the used nonces,
    /// and the last `MESSAGE_WINDOW` messages that become the window it serves
    /// from. It used to collect every row into two vectors first. Starting the
    /// sequencer then cost as much memory as the whole history, so a sequencer
    /// whose history had grown past RAM could not be restarted at all. Not
    /// "restarted slowly": the process died on the read every time, with a whole
    /// database on disk and no way to open it. What is checked did not change.
    /// Only how much is held while checking it changed.
    ///
    /// # What the tree costs here, measured
    ///
    /// Nothing is hashed and nothing is held. The nodes are rows in
    /// `merkle_nodes`. This pass reads their highest leaf index, which is an
    /// index seek at 0.05 ms. It counts them, which is a scan of that table at
    /// 1.8 ms over 268,993 rows. Then it carries the message count forward as
    /// the tree's size. The count is what separates a database whose tree is
    /// missing or too short from one whose tree is ready to serve.
    ///
    /// One more read was added on top of that when the root went into the
    /// checkpoint. It computes `MTH` over the stored nodes and compares it
    /// against the root the sequencer signed. That reads one node per set bit of
    /// the message count, which is 17 rows at 100,000 messages, and does the
    /// same number of hashes. This read is what makes the counts above mean
    /// anything. A table of the right size over the wrong messages has exactly
    /// the shape those counts measure.
    ///
    /// This function used to build the whole tree here, from every message, into
    /// `MerkleTree`. Nothing limited that. `messages` has the `MESSAGE_WINDOW`
    /// limit because a structure that holds one item per message, with no limit,
    /// once took this sequencer's host down, and the tree grew the same way.
    ///
    /// Measured on a database of 134,500 messages, release build. The deployed
    /// binary was started on it and asked for `/sth`:
    ///
    /// ```text
    ///                    before      after
    ///   start            122 ms      88 ms
    ///   resident        29.1 MB    20.6 MB
    /// ```
    ///
    /// The 8.5 MB is the tree: 268,993 hashes at 32 bytes, 63 bytes a message,
    /// now out of RAM. What is left in RAM grows with `MESSAGE_WINDOW` and the
    /// number of symbols, and not with the history.
    ///
    /// A database written before `merkle_nodes` existed has no nodes to read.
    /// Building them from its messages is a cost paid once, by `tree::rebuild`,
    /// on that first open: 279 ms for those 134,500 messages, which made that
    /// one start 374 ms instead of 88 ms. What must not happen is paying it at
    /// every start, which is what the old code did.
    ///
    /// # What a checkpoint from before the signed root costs
    ///
    /// The same build, and the same rebuild, for a different reason. That
    /// checkpoint says nothing about the tree, so there is nothing to check the
    /// nodes against, and they are built from the messages instead of read.
    /// Measured here on 100,000 messages, release build:
    ///
    /// ```text
    ///   ordinary restart, tree read and checked          62 ms
    ///   checkpoint with no root, tree built again       284 ms
    /// ```
    ///
    /// The cost is paid at every start until the sequencer publishes one
    /// message, because publishing is what writes a checkpoint that carries a
    /// root. A sequencer that publishes pays it once. A sequencer started with
    /// `--num-accounts 0` and no submissions pays it every time it starts. Those
    /// 222 ms of a start are the price of not trusting a tree that no signature
    /// covers.
    pub fn with_db(
        num_accounts: u32,
        path: &Path,
        signing_key: SigningKey,
        wall_base_ms: u64,
    ) -> Result<Self, String> {
        let mut conn = open_feed_db(path)?;

        // How much of the tree this database already holds, before one message
        // is read. These two values decide whether this start has to build any
        // nodes at all. On every start after the first, it does not.
        let stored_leaves = tree::stored_leaves(&conn).map_err(|e| e.to_string())?;
        let stored_nodes = tree::stored_nodes(&conn).map_err(|e| e.to_string())?;

        // One pass over the stored history, one row at a time. Everything the
        // start needs is built up as the rows go past: the chain, the used
        // nonces, the generator's last prices and the orders it can cancel, and
        // the window of recent messages the sequencer serves from memory.
        // Nothing grows except what `MESSAGE_WINDOW` or the symbol count limits.
        let mut messages: VecDeque<Published> = VecDeque::new();
        let mut chains: VecDeque<Chain> = VecDeque::new();
        let mut nonces: HashMap<NonceKey, OrderId> = HashMap::new();
        let mut candidates: Vec<OpenOrder> = Vec::new();
        let mut last_price: Vec<(String, f64)> = Vec::new();
        let mut chain = EMPTY_CHAIN;
        // The chain as it stood after the last message the tree already covers.
        // A rebuild that has to build only the end starts its own hashing from
        // here. See `tree::rebuild`.
        let mut chain_at_stored = EMPTY_CHAIN;
        let mut first_bad_link: Option<OrderId> = None;
        let mut count: u64 = 0;
        let mut unreadable: u64 = 0;
        {
            // The `id` column is read as well as the bytes. `ORDER BY id` sorted
            // on that column, so that column fixed the order the hashing below
            // runs in, and the gap check must use the same value. The id inside
            // the bytes is checked against it a few lines later.
            let mut statement = conn
                .prepare("SELECT id, json, chain FROM feed_messages ORDER BY id")
                .map_err(|e| e.to_string())?;
            let mut rows = statement.query([]).map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let stored_id: i64 = row.get(0).map_err(|e| e.to_string())?;
                let json: String = row.get(1).map_err(|e| e.to_string())?;
                let stored: Option<Vec<u8>> = row.get(2).map_err(|e| e.to_string())?;
                let id = OrderId::try_from(stored_id).unwrap_or(0);

                // Ids are 1..N with no gaps. Everything here depends on that,
                // from `next_id` to the way the window is indexed. A gap means
                // rows were removed from the middle.
                count += 1;
                if id != count {
                    return Err(format!(
                        "message ids in {} are not 1..N with no gaps: row {} holds message {}. \
                         Rows were removed or renumbered; this database is not the history this \
                         feed published",
                        path.display(),
                        count,
                        stored_id
                    ));
                }

                // The hashing, over the bytes as stored. No parsing: see the
                // note on this function.
                chain = logchain::extend_bytes(&chain, json.as_bytes());
                if first_bad_link.is_none() && stored.as_deref() != Some(chain.as_slice()) {
                    first_bad_link = Some(id);
                }
                if count == stored_leaves {
                    chain_at_stored = chain;
                }

                // What this build can read out of the row without knowing what
                // kind of message it is. A row that fails here is not a message
                // at all. That is a different thing from a kind this binary is
                // too old for, and the start refuses it.
                let fields = wire::envelope(json.as_bytes()).map_err(|e| {
                    format!(
                        "row {} of {} is not a feed message: {}",
                        count,
                        path.display(),
                        e
                    )
                })?;
                // What the row calls itself. The two lines below use it to name
                // a message an operator has to go and look at.
                let kind = &fields.kind;
                if fields.id != id {
                    return Err(format!(
                        "row {} of {} stores message {}, and the bytes on that row say they are \
                         message {}. The id a consumer reads is the one in the bytes, so this \
                         file would serve a history in an order it does not claim",
                        count,
                        path.display(),
                        id,
                        fields.id
                    ));
                }

                // The used nonces, read from the bytes themselves. No query and
                // no table. The checkpoint below proves these messages are the
                // history this sequencer published, so this map is exactly the
                // set of nonces it has accepted.
                //
                // The nonce is read here, and not off a parsed `OrderMessage`,
                // so a message kind this build cannot read still spends its
                // nonce. Skipping it would leave the sequencer ready to publish
                // that submission a second time. The next binary that can read
                // both messages would then find two messages under one nonce and
                // refuse to start. Going back to an older binary would make the
                // database unusable, and nothing would say so.
                if let Some(nonce) = &fields.nonce {
                    let key: Option<NonceKey> = fields.account.zip(inbox::canonical_nonce(nonce));
                    let Some(key) = key else {
                        // Intake only ever accepts a nonce in the one form,
                        // under an account. So reaching here is a fault in this
                        // program, or a message kind that keeps its nonce
                        // somewhere else. It is not an edited file, which the
                        // checkpoint would have caught. Either way the map
                        // would be incomplete. An incomplete repeat check that
                        // says nothing is the one outcome worth refusing to
                        // start over.
                        return Err(format!(
                            "message {} in {} is a '{}' carrying the nonce {:?} under account \
                             {:?}, which is not a nonce this feed can key. It cannot rebuild \
                             which nonces it has already honoured, so it cannot promise a replay \
                             of that submission would be refused",
                            id,
                            path.display(),
                            kind,
                            nonce.chars().take(80).collect::<String>(),
                            fields.account
                        ));
                    };
                    if let Some(first) = nonces.insert(key, id) {
                        // Two messages under one `(account, nonce)`. That is the
                        // repeat this whole check exists to stop, and it sits in
                        // the published history. This code cannot produce it, so
                        // it came from somewhere else. Continuing would sign it
                        // as if it were normal.
                        return Err(format!(
                            "messages {} and {} in {} are both under account {} with the same \
                             nonce, so one of them is a replay of the other that this feed \
                             published. That cannot happen through any path this feed accepts",
                            first,
                            id,
                            path.display(),
                            key.0
                        ));
                    }
                }

                // The generator's own state is the one part of the start that
                // needs to know what the message says. So it is the one part a
                // kind this build cannot read is left out of. Nothing about the
                // history depends on it. A missing last price starts that
                // symbol again from the price it was listed at, and a missing
                // order is one fewer order the generator can cancel.
                match serde_json::from_str::<OrderMessage>(&json) {
                    Ok(message) => {
                        if let OrderMessage::New { symbol, price, .. } = &message {
                            // Only the symbols this sequencer lists. Those are
                            // the only prices the generator reads back, and a
                            // history that names other symbols must not grow
                            // this list.
                            if SYMBOLS.iter().any(|(listed, _, _)| listed == symbol) {
                                match last_price.iter_mut().find(|(s, _)| s == symbol) {
                                    Some(entry) => entry.1 = *price,
                                    None => last_price.push((symbol.clone(), *price)),
                                }
                            }
                        }
                        // The orders the generator still holds open. They are
                        // built again by running its own records over the
                        // stored messages. Without this step a restart forgets
                        // every order it placed, and a forgotten order is one
                        // that nothing can take off the book again.
                        generate::replay_into_the_open_orders(&mut candidates, &message);
                    }
                    Err(e) => {
                        unreadable += 1;
                        if unreadable <= UNREADABLE_REPORTED as u64 {
                            warn!(
                                "message {} in {} is a '{}' this build cannot interpret ({}). Its \
                                 bytes are still hashed into the chain and still served \
                                 unchanged, so the history is intact; this binary is older than \
                                 the message format its own database holds",
                                id,
                                path.display(),
                                kind,
                                e
                            );
                        }
                    }
                }

                if messages.len() == MESSAGE_WINDOW {
                    messages.pop_front();
                    chains.pop_front();
                }
                messages.push_back(Published { id, json });
                chains.push_back(chain);
            }
        }
        if unreadable > UNREADABLE_REPORTED as u64 {
            warn!(
                "{} messages in {} are of kinds this build cannot interpret; the {} above are \
                 the first of them",
                unreadable,
                path.display(),
                UNREADABLE_REPORTED
            );
        }

        let last_id = count;
        let stored_session: Option<String> = conn
            .query_row(
                "SELECT value FROM feed_meta WHERE key = 'session'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let checkpoint: Option<String> = conn
            .query_row(
                "SELECT value FROM feed_meta WHERE key = 'checkpoint'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        // The session and the checkpoint are decided together, because neither
        // means anything without the other. The session names a signed history,
        // not a file. The checkpoint is the only thing in the file that says a
        // history was ever signed here. The first publish writes both, in one
        // transaction (see `sequence`).
        //
        // So there are exactly these three cases, and the middle one is the one
        // that matters. Reading a session back and reusing it with no
        // checkpoint beside it is what made an emptied database look the same
        // as a new one. `DELETE FROM feed_messages; DELETE FROM feed_meta WHERE
        // key='checkpoint';` leaves a session, no checkpoint and no rows. A
        // file that is new holds those same three facts. Every check below then
        // reads evidence the delete removed. The sequencer came back under the
        // name consumers had recorded, signed a second and different history
        // under that name, with the same key, and nothing anywhere refused.
        //
        // Making a new name instead is what makes the delete visible. The
        // anchor contract refuses a session change with `SessionChanged()`.
        // Validators reset their position and carry the new name in their
        // signed statement. The exchange opens a new run. Nothing is lost by it
        // either: a name nothing was ever signed under is a name no receipt
        // anywhere refers to.
        let (session, signed_root) = match checkpoint {
            None if count == 0 => {
                // Nothing was ever published here, so there is no history for
                // any stored name to belong to. Whatever that row says, this is
                // a new history and it gets a new name. The first publish
                // writes the name down next to the checkpoint that gives the
                // name a meaning.
                (new_session(), None)
            }
            None => {
                return Err(format!(
                    "{} holds {} messages but no signed checkpoint, so there is nothing to check \
                     them against. Either the checkpoint was removed or this file predates it; \
                     a feed cannot tell those apart, and signing this history as if it were its \
                     own is exactly what it must not do. Delete the database (and feed.key with \
                     it) to start a new history",
                    path.display(),
                    count
                ));
            }
            Some(stored) => {
                // The session row is written in the same transaction as the
                // checkpoint. So a checkpoint on its own means the session row
                // was removed. The start refuses here, and does not leave the
                // signature check to fail later under a new name. That later
                // failure would report a key problem over a missing row.
                let session = stored_session.ok_or_else(|| {
                    format!(
                        "{} holds a signed checkpoint but names no session, so nothing here says \
                         which history that signature covers. The two are written together and \
                         only one of them is left; this file was written to by something other \
                         than the feed",
                        path.display()
                    )
                })?;
                let checkpoint: Checkpoint = serde_json::from_str(&stored)
                    .map_err(|e| format!("the stored checkpoint is not readable: {}", e))?;
                let signed_chain =
                    logchain::from_hex::<32>(&checkpoint.chain).ok_or_else(|| {
                        "the stored checkpoint's chain is not 32 hex bytes".to_string()
                    })?;
                let signature = logchain::from_hex::<64>(&checkpoint.signature)
                    .map(|bytes| Signature::from_bytes(&bytes))
                    .ok_or_else(|| {
                        "the stored checkpoint's signature is not 64 hex bytes".to_string()
                    })?;
                if !logchain::verify_head(
                    &signing_key.verifying_key(),
                    &session,
                    checkpoint.last_id,
                    &signed_chain,
                    &signature,
                ) {
                    return Err(format!(
                        "the checkpoint in {} is not signed by this feed's key for session {}. \
                         Either the checkpoint was edited, or the key beside the database is not \
                         the key that wrote it. In both cases this process cannot honestly \
                         continue that history",
                        path.display(),
                        session
                    ));
                }
                if checkpoint.last_id != last_id || signed_chain != chain {
                    return Err(format!(
                        "{} does not hold the history this feed last published. It signed \
                         message {} with chain {}; these {} messages reach message {} with chain \
                         {}. Messages were changed, added or removed behind the feed's back. \
                         Nothing here is repaired: the feed will not sign a history it cannot \
                         show it published",
                        path.display(),
                        checkpoint.last_id,
                        checkpoint.chain,
                        count,
                        last_id,
                        logchain::to_hex(&chain)
                    ));
                }
                // The tree half of the same statement. It is the only value in
                // this file that says what `merkle_nodes` should hold. A
                // checkpoint written before these fields existed carries
                // neither. That is not a weaker statement about the tree. It is
                // no statement at all, so the tree block below builds the tree
                // again from the messages instead of reading it.
                //
                // One field without the other is refused. No publish has ever
                // written one alone, because they are two lines of the same
                // `Checkpoint::row`. So a row that holds one field is a row
                // something else wrote, and the missing half is exactly the
                // half that would have caught a rewritten tree.
                let signed_root = match (&checkpoint.root, &checkpoint.root_signature) {
                    (None, None) => None,
                    (Some(root), Some(signature)) => {
                        let root = logchain::from_hex::<32>(root).ok_or_else(|| {
                            "the stored checkpoint's root is not 32 hex bytes".to_string()
                        })?;
                        let signature = logchain::from_hex::<64>(signature)
                            .map(|bytes| Signature::from_bytes(&bytes))
                            .ok_or_else(|| {
                                "the stored checkpoint's root signature is not 64 hex bytes"
                                    .to_string()
                            })?;
                        if !logchain::verify_checkpoint(
                            &signing_key.verifying_key(),
                            &session,
                            checkpoint.last_id,
                            &signed_chain,
                            &root,
                            &signature,
                        ) {
                            return Err(format!(
                                "the Merkle root in the checkpoint of {} is not signed by this \
                                 feed's key for session {} at message {}. The chain half of that \
                                 checkpoint is signed and the root half is not, so the root was \
                                 edited after the feed wrote it",
                                path.display(),
                                session,
                                checkpoint.last_id
                            ));
                        }
                        Some(root)
                    }
                    _ => {
                        return Err(format!(
                            "the checkpoint in {} holds {} of the Merkle root and the signature \
                             over it, and a feed writes the two together or not at all. This file \
                             was written to by something other than the feed, and what is missing \
                             is what says whether its tree is the one its messages make",
                            path.display(),
                            if checkpoint.root.is_some() {
                                "only the first"
                            } else {
                                "only the second"
                            }
                        ));
                    }
                };
                (session, signed_root)
            }
        };
        // A head that matches still leaves one thing open: a link edited in the
        // middle of the table. The messages still hash to the signed head, so
        // the history is whole, but something wrote to this file.
        if let Some(id) = first_bad_link {
            return Err(format!(
                "the chain link stored with message {} in {} is not the chain its own messages \
                 produce. The messages match the signed checkpoint, so the history is intact, \
                 but this file was written to by something other than the feed",
                id,
                path.display()
            ));
        }

        // Only now, with these messages checked against the signature the
        // sequencer made over them, is it safe to build nodes from them. The
        // tree commits to the messages. Building it from bytes that had not been
        // checked would store a commitment to whatever the file happened to
        // hold.
        //
        // The `stored_leaves` rows at level 0 are kept only if they are the
        // first part of *this* history, and the table has the number of rows a
        // tree that size has. Anything else is not a tree these messages make,
        // and no part of it is worth keeping. That covers a table longer than
        // the history, and a table with rows missing.
        //
        // Rows are kept only if the checkpoint says what they should hash to.
        // Without that, this start has nothing to compare them against. Reading
        // the highest leaf index and counting the rows says only that a tree of
        // that shape is there, and a tree of the right shape over the wrong
        // messages has exactly that shape. That was the gap in the checks.
        // `merkle_nodes` was the one thing in this file no signature reached,
        // and rewriting a node moved the root the sequencer signs instead of
        // breaking any proof.
        let keeps = signed_root.is_some()
            && stored_leaves <= count
            && stored_nodes == tree::expected_nodes(stored_leaves);
        let from = if keeps { stored_leaves } else { 0 };
        if from < count {
            let rebuilt = tree::rebuild(
                &mut conn,
                from,
                count,
                if keeps { chain_at_stored } else { EMPTY_CHAIN },
                chain,
            )
            .map_err(|e| {
                format!(
                    "the Merkle tree in {} could not be built from its messages: {}",
                    path.display(),
                    e
                )
            })?;
            tree::report(
                path,
                count,
                stored_leaves,
                stored_nodes,
                signed_root.is_some(),
                &rebuilt,
            );
        }
        // And now the hashes, against the root the sequencer signed over the
        // same messages the checks above just matched. This costs `log2(n)`
        // reads. The root of a tree of any size is made from the full subtrees
        // on its right edge, one per set bit of the size. That is what makes
        // this check cheap enough for every start, where hashing the whole
        // history again would not be.
        //
        // A root that does not match refuses the start, and does not rebuild.
        // It is the same event as a chain link edited in the middle of a whole
        // history a few lines above, and gets the same answer. The messages are
        // the ones this sequencer published, so nothing is lost. But storage
        // computed from them that disagrees with what the sequencer signed means
        // something else wrote to this file. Rebuilding instead would repair it
        // with no message and destroy the only evidence. That is what the old
        // code did to the chain links, and it is the fault this project's README
        // is about. The operator takes the way back, and it is one line: `DELETE
        // FROM merkle_nodes` and start again, which builds the tree from the
        // messages.
        if let Some(signed) = signed_root {
            let built = tree::root(
                &Nodes::Disk {
                    conn: &conn,
                    leaves: count,
                },
                count,
            )
            .map_err(|e| {
                format!(
                    "the Merkle tree in {} could not be read: {}",
                    path.display(),
                    e
                )
            })?;
            if built != signed {
                return Err(format!(
                    "the Merkle tree in {} has root {} over its {} messages, and the checkpoint \
                     this feed signed at message {} says that tree has root {}. The messages \
                     match that checkpoint, so the history is intact and its nodes were written \
                     to by something other than the feed. Nothing here is repaired: a feed that \
                     rebuilt them would sign the same root either way and leave no trace that \
                     anything had happened. Delete merkle_nodes to build the tree from the \
                     messages again",
                    path.display(),
                    logchain::to_hex(&built),
                    count,
                    last_id,
                    logchain::to_hex(&signed)
                ));
            }
        }

        let mut state = FeedState::new(num_accounts, wall_base_ms);
        state.session = session;
        state.chain = chain;
        state.chains = chains;
        state.messages = messages;
        state.nonces = nonces;
        // The lives the restart gives the orders it read back. A life is a time
        // on this clock, in milliseconds, and the log holds no lives. So every
        // order gets a new life, and the control of how many orders stay open
        // starts again from here.
        let now_ms = state.clock.now_ms();
        for open in &mut candidates {
            let band = band_of(open.account);
            open.expires_at_ms = now_ms.saturating_add(a_life(&mut state.rng, band));
        }
        if candidates.len() >= MAX_OPEN_ORDERS {
            warn!(
                "the history in {} leaves {} orders open, which is the most this generator \
                 holds. Orders past that are ones it cannot cancel; they stay in the books \
                 until something trades with them",
                path.display(),
                candidates.len()
            );
        }
        state.open_orders = candidates;
        state.signing_key = signing_key;
        state.next_id = last_id + 1;
        state.unreadable = unreadable;

        // The last published price of a symbol is where the generator's price
        // walk left off. It is used only if the engine could have accepted that
        // price. A stored price that is not a whole number of price steps used
        // to go straight into the random walk. That happens with a database
        // written before intake checked the price, or one written through a
        // read path that did not check. In the walk, `1e307 * 1.002` is
        // `f64::INFINITY`. Serde writes that as JSON `null`, and nothing can
        // parse `null` back, including this sequencer on its next start. One
        // submitted price made the database unusable for good.
        for (symbol, price) in last_price {
            if to_grid(price, PRICE_SCALE).is_some() {
                state.mids.insert(symbol, price);
            } else {
                error!(
                    "the last published price for {} is {}, which is not a price this engine \
                     can represent; the generator restarts that symbol from its initial mid \
                     instead of walking from a value it cannot serialize",
                    symbol, price
                );
            }
        }

        // The keys fixed to accounts. A record that cannot be read refuses the
        // start, and is not skipped. Skipping it would make the account look
        // like it has no key yet. The next submission that names the account,
        // from anyone, would then fix a new key over the key this sequencer had
        // already accepted.
        let pins: Vec<(i64, String)> = conn
            .prepare("SELECT account, public_key FROM feed_accounts")
            .map_err(|e| e.to_string())?
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        for (account, hex) in pins {
            let key = logchain::from_hex::<32>(&hex)
                .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
                .ok_or_else(|| {
                    format!(
                        "the key pinned for account {} in {} is not a readable Ed25519 public key \
                         ({}). Starting without it would let the next submission naming that \
                         account pin a different key",
                        account,
                        path.display(),
                        hex
                    )
                })?;
            state.accounts.insert(account as AccountId, key);
        }

        state.inbox_sequenced = conn
            .prepare("SELECT epoch, inbox_id, feed_id FROM inbox_sequenced")
            .map_err(|e| e.to_string())?
            .query_map([], |row| {
                Ok((
                    (row.get::<_, String>(0)?, row.get::<_, i64>(1)?),
                    row.get::<_, i64>(2)? as OrderId,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(|e| e.to_string())?;

        // One leaf per message, so the tree's size is the message count this
        // pass just checked. That count is the only part of the tree this
        // process holds.
        state.storage = Storage::Disk {
            conn,
            leaves: count,
        };
        Ok(state)
    }

    /// Checks a submission's key against the keys this sequencer has fixed to
    /// accounts. If the account has no key yet, this fixes the key to it.
    ///
    /// The record is written before the message it authorises is published, and
    /// in its own transaction. If the publish then fails, the account keeps a
    /// key with no message in the log under it. That does no harm and it is
    /// true: that key did send a valid submission. The other order would allow
    /// a published message whose key record was lost in a crash, and anyone's
    /// key could then take that account.
    fn pin_or_check_account(
        &mut self,
        account: AccountId,
        key: &VerifyingKey,
    ) -> Result<(), (StatusCode, String)> {
        let decision = inbox::check_account_key(account, self.accounts.get(&account), key)?;
        if decision == inbox::AccountPin::First {
            if let Some(db) = self.storage.conn() {
                db.execute(
                    "INSERT INTO feed_accounts (account, public_key, pinned_at) VALUES (?1, ?2, ?3)",
                    params![account, logchain::to_hex(key.as_bytes()), self.clock.now_ms() as i64],
                )
                .map_err(|e| {
                    error!("could not pin account {}: {}", account, e);
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!(
                            "account {} could not be pinned to its key, so this submission is not \
                             accepted: {}",
                            account, e
                        ),
                    )
                })?;
            }
            self.accounts.insert(account, *key);
            info!(
                "pinned account {} to public key {}: only submissions signed by that key are \
                 accepted for it from now on",
                account,
                logchain::to_hex(key.as_bytes())
            );
            if account < self.num_accounts {
                // This is worth saying, and not worth refusing over. The
                // generator makes simulated traffic, and a flag sets which
                // account ids it uses. Nothing it publishes can cancel a real
                // order, because it only cancels ids it generated itself. But
                // its orders go under this account number, and they show up in
                // that account's position.
                warn!(
                    "account {} is also one of the {} accounts this feed generates simulated \
                     traffic for, so generated orders will appear under it. Use an account id of \
                     {} or higher for real submissions, or start the feed with --num-accounts 0",
                    account, self.num_accounts, self.num_accounts
                );
            }
        }
        Ok(())
    }

    /// Publishes one message. See `sequence`.
    fn publish(&mut self, msg: OrderMessage) -> Result<(), String> {
        self.sequence(vec![(None, msg)])
    }

    /// Publishes a group of generated messages. See `sequence`.
    fn publish_batch(&mut self, msgs: Vec<OrderMessage>) -> Result<(), String> {
        self.sequence(msgs.into_iter().map(|msg| (None, msg)).collect())
    }

    /// Puts a group of messages in the log. Each message can also fulfil one
    /// entry of the separate service. The chain is extended through all of
    /// them, everything is written in one transaction, and the messages become
    /// visible to consumers only if that write committed.
    ///
    /// Nothing is published unless it is written to disk. That trades
    /// availability for correctness on purpose, and it is the only state this
    /// protocol can state truthfully. A published message is hashed into the
    /// chain, served on `/orders`, and given to its submitter as a signed
    /// receipt. There is no way to un-publish it afterwards. The old code
    /// logged the write failure and published anyway. A short disk fault during
    /// messages 100-109 then left consumers holding a chain built over those
    /// ten messages, while the database held 1-99 and 110 onward. After the
    /// next restart the sequencer computed a different chain. Every consumer
    /// read that as proof the sequencer was serving a history it had not
    /// signed. Those consumers are the exchange, and every validator. A
    /// validator's dispute stays until an operator clears it, so two seconds of
    /// disk trouble became a permanent decision, across the whole system, that
    /// the sequencer had lied.
    ///
    /// One transaction per group is what lets the rate go up. A committed
    /// transaction costs one fsync, however many messages it carries. So a
    /// sequencer at 100 messages a second pays ten fsyncs a second at a 100ms
    /// tick, and not a hundred.
    ///
    /// The record of the service entry, the Merkle nodes, the checkpoint and
    /// the session go in the same transaction. So "entry N is message M", "the
    /// history ends at M", "the tree over it has root R" and "this history is
    /// called S" are written to disk exactly as well as message M itself. A
    /// crash can never make the sequencer put one service entry in the log
    /// twice. It can never leave a checkpoint that disagrees with the messages
    /// or with the tree beside it. And it can never leave a signature over a
    /// name the file does not hold.
    fn sequence(&mut self, batch: Vec<(Option<InboxKey>, OrderMessage)>) -> Result<(), String> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut chain = self.chain;
        let mut chains = Vec::with_capacity(batch.len());
        // The message is turned into bytes once, and this is the only place in
        // the sequencer that does it. The same byte string is hashed into the
        // chain, written to `feed_messages`, and served on every page. Those
        // three cannot disagree, because there is only one byte string. Making
        // the bytes once for the hashing and once for the row was two chances
        // to write two different byte strings for one message.
        let mut published: Vec<Published> = Vec::with_capacity(batch.len());
        // The Merkle leaves, over the same byte string, from that same one
        // conversion. Always `leaf_hash` and never anything else. It puts RFC
        // 9162's 0x00 prefix in front of the bytes, so nothing here can put an
        // inner node where a leaf belongs.
        let mut leaves: Vec<Hash> = Vec::with_capacity(batch.len());
        for (_, msg) in &batch {
            let json = serde_json::to_string(msg)
                .map_err(|e| format!("a feed message could not be serialized: {}", e))?;
            chain = logchain::extend_bytes(&chain, json.as_bytes());
            chains.push(chain);
            leaves.push(merkle::leaf_hash(json.as_bytes()));
            published.push(Published { id: msg.id(), json });
        }
        let first_id = batch[0].1.id();
        let last_id = batch[batch.len() - 1].1.id();

        // The name the checkpoint below is signed under, and the key that signs
        // it. They are copied out here because the checkpoint is built inside
        // the transaction, which borrows `self.storage` as mutable.
        let session = self.session.clone();
        let signing_key = self.signing_key.clone();

        let leaves_before = self.storage.leaves();
        let grown = leaves.len() as u64;
        if let Storage::Disk { conn, .. } = &mut self.storage {
            let written = conn.transaction().map_err(Unreadable::from).and_then(|tx| {
                {
                    // A plain INSERT, not INSERT OR REPLACE. Every id here
                    // comes from `next_id`, which only moves forward. So a row
                    // that is already there means something is wrong: a shared
                    // database, a restored one, or a fault that reuses an id.
                    // The old REPLACE wrote over history that was already
                    // published, and hid the problem. A constraint error
                    // refuses the whole group instead, and the operator sees it.
                    let mut insert = tx.prepare_cached(
                        "INSERT INTO feed_messages (id, json, chain) VALUES (?1, ?2, ?3)",
                    )?;
                    // The same reason applies here. A record is only written
                    // when the lookup found nothing, so a key that is already
                    // there is a fault, not a second try.
                    let mut fulfil = tx.prepare_cached(
                        "INSERT INTO inbox_sequenced (epoch, inbox_id, feed_id) VALUES (?1, ?2, ?3)",
                    )?;
                    for ((inbox_key, _), (row, chain)) in
                        batch.iter().zip(published.iter().zip(&chains))
                    {
                        let id = row.id as i64;
                        insert.execute(params![id, row.json, chain.as_slice()])?;
                        if let Some((epoch, inbox_id)) = inbox_key {
                            fulfil.execute(params![epoch, inbox_id, id])?;
                        }
                    }
                    // The session, one of the two replaces this file is allowed
                    // to make, in this transaction and nowhere else. That is
                    // what makes the two impossible to find apart: a checkpoint
                    // on disk is a signature over the name on the row beside
                    // it, committed with that row. A crash between the two
                    // cannot happen, because there is no point between them.
                    // The session used to be written when the database was
                    // opened. That put a name in the file before anything was
                    // signed under it, and a name that outlives the history it
                    // was made for is the whole of the attack that empties the
                    // database.
                    //
                    // The session is written on every group, and not only on
                    // the first. It is the same one-row page the checkpoint
                    // replace already changes. And it means the row on disk is
                    // always the name the checkpoint beside it was signed
                    // under, with no flag to keep in step.
                    tx.execute(
                        "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('session', ?1)",
                        params![session],
                    )?;
                    // The Merkle nodes, in this transaction and not in one of
                    // their own. A node written outside this transaction would
                    // give a tree that does not match the messages beside it
                    // after any crash between the two writes, and nothing later
                    // could say which of the two to believe. Here there is no
                    // point between: the message, its chain link, its record
                    // for the separate service, the checkpoint and the nodes
                    // over them all commit together or not at all.
                    //
                    // The first group of a history clears the table first. A
                    // database whose messages were deleted behind the
                    // sequencer's back starts a new history under a new session
                    // (see `with_db`). The new history's leaf 0 must not land
                    // on the old history's rows. That is a constraint failure,
                    // and it would leave the sequencer unable to publish at all.
                    if leaves_before == 0 {
                        tree::clear(&tx)?;
                    }
                    tree::append(&tx, leaves_before, &leaves)?;
                    // The checkpoint comes last, because it states the root of
                    // the tree the lines above just finished writing. That root
                    // is read back out of those rows, and not kept next to
                    // them. It costs `log2(n)` reads inside a transaction that
                    // is about to fsync anyway.
                    //
                    // This is the second of the two replaces this file is
                    // allowed to make. The checkpoint is one row that says
                    // where the history ends now, so every publish writes over
                    // the last one on purpose.
                    let size = leaves_before + grown;
                    let root = tree::root(&Nodes::Disk { conn: &tx, leaves: size }, size)?;
                    tx.execute(
                        "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
                        params![Checkpoint::row(
                            &signing_key,
                            &session,
                            last_id,
                            &chain,
                            &root
                        )],
                    )?;
                }
                tx.commit().map_err(Unreadable::from)
            });
            if let Err(e) = written {
                // Nothing above this line changed the published state, so there
                // is nothing to undo there. What must be undone is the ids the
                // callers already took. The ids in this group were never
                // published, so they go back to being the next ids to hand out.
                self.next_id = first_id;
                self.open_orders.retain(|open| open.id < self.next_id);
                let detail = format!(
                    "burst of {} messages ending at {} was not written to the feed database, so \
                     none of it is published: {}",
                    published.len(),
                    last_id,
                    e
                );
                error!("{}", detail);
                return Err(detail);
            }
        }

        self.chain = chain;
        for ((inbox_key, msg), (row, chain)) in
            batch.into_iter().zip(published.into_iter().zip(chains))
        {
            if let Some(key) = inbox_key {
                self.inbox_sequenced.insert(key, msg.id());
            }
            // This runs after the commit, so a nonce is only spent by a message
            // that is really published. The records for the separate service
            // follow the same rule, for the same reason. A write that failed
            // must leave the nonce free. If it did not, a submitter who tries
            // again after a disk error is told their order already exists when
            // no order does.
            if let Some(key) = nonce_key(&msg) {
                self.nonces.insert(key, msg.id());
            }
            self.push_window(row, chain);
        }
        // The tree also grows after the commit. A message that was not written
        // is not published, so it must not become a leaf either. A leaf with no
        // row behind it would give a root this sequencer could sign once and
        // never reach again. With a database the nodes are already on disk,
        // committed with the messages, and this step only brings the count up
        // to date. Without a database this step is the whole tree.
        match &mut self.storage {
            Storage::Memory(tree) => {
                for leaf in leaves {
                    tree.push_leaf_hash(leaf);
                }
            }
            Storage::Disk { leaves: size, .. } => *size += grown,
        }
        Ok(())
    }

    /// Adds one published message to the window in memory. When the window is
    /// full it drops the oldest message. What leaves memory is still in
    /// `feed_messages`, and is served from there. See `page`.
    fn push_window(&mut self, msg: Published, chain: Chain) {
        if self.messages.len() == MESSAGE_WINDOW {
            self.messages.pop_front();
            self.chains.pop_front();
        }
        self.messages.push_back(msg);
        self.chains.push_back(chain);
    }

    /// The id of the oldest message still in memory, and the id of the newest
    /// message published. On an empty sequencer `window_start > last_id`.
    fn window_start(&self) -> OrderId {
        self.messages.front().map_or(self.next_id, |m| m.id)
    }

    /// The newest message published. It is read off the window, and not
    /// computed from `next_id`. The callers that build messages hand out the
    /// ids, and this must be the id of a message that really exists. Everything
    /// that serves a page or signs a head is measured against it.
    fn last_id(&self) -> OrderId {
        self.messages.back().map_or(0, |m| m.id)
    }

    /// Whether user, inbox and generated traffic may publish yet.
    ///
    /// A sequencer that names an operator reserves the first
    /// `OPENING_MESSAGES` positions for the opening script. The script sends
    /// four separate requests. On a loaded host, generated traffic once landed
    /// between those requests and an order took the place of a listing. A
    /// timing margin cannot fix that race.
    ///
    /// A sequencer that names no operator is open from its first tick, as it
    /// always was. The check must depend on the key. A check that always applied
    /// would stop every sequencer started with `--rate` and no key from
    /// publishing, including the ones the crash and fault tests start.
    fn log_is_open(&self) -> bool {
        self.operator_key.is_none() || self.last_id() >= OPENING_MESSAGES
    }

    /// Where a message with this id sits in the window, if it is still there.
    /// Ids are 1..N with no gaps, so the position is one subtraction and not a
    /// search.
    fn window_index(&self, id: OrderId) -> Option<usize> {
        let start = self.window_start();
        if id < start || id > self.last_id() {
            return None;
        }
        usize::try_from(id - start).ok()
    }

    /// The bytes of the published message with this id, from the window or from
    /// the database. It is `None` only if the sequencer never published that
    /// message, or if the message left the window on a sequencer that has no
    /// database to read it back from.
    fn stored_json(&self, id: OrderId) -> Option<String> {
        if let Some(index) = self.window_index(id) {
            return self.messages.get(index).map(|msg| msg.json.clone());
        }
        let db = self.storage.conn()?;
        db.query_row(
            "SELECT json FROM feed_messages WHERE id = ?1",
            params![id as i64],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            error!(
                "cannot read message {} back from the feed database: {}",
                id, e
            );
        })
        .ok()?
    }

    /// The published message with this id, read as a value this build can act
    /// on.
    ///
    /// The only callers are the ones that have to read what a message *says*.
    /// That is the code which reads the separate service: it compares a
    /// published message against the order the service entry holds, and puts
    /// the message in the signed mark. Serving a message needs none of this and
    /// does none of it. See `page`.
    ///
    /// It is `None` for a kind this build cannot read. That is the true answer,
    /// and the callers already do the right thing with it. The entry stays
    /// waiting on the separate service and shows up there as overdue. It is not
    /// marked against a message this binary cannot show it matches.
    fn message(&self, id: OrderId) -> Option<OrderMessage> {
        let json = self.stored_json(id)?;
        match serde_json::from_str(&json) {
            Ok(msg) => Some(msg),
            Err(e) => {
                error!(
                    "this build cannot interpret stored message {}: {}. Its bytes are served and \
                     hashed unchanged; what cannot be done with it is anything that needs to know \
                     what it says",
                    id, e
                );
                None
            }
        }
    }

    /// The signed head standing at message `last_id`: "history `session`, after
    /// message `last_id`, has chain `chain`", under the sequencer's key.
    ///
    /// The sequencer can sign the head at any point in the history, because
    /// each chain value is hashed from the one before it. The value after
    /// message N is the same whatever comes later. So a head at N is a true
    /// statement about the history, whether or not the sequencer has published
    /// past N. A submitter's receipt is already such a head, and this is what
    /// lets a paged `/orders` response carry a head standing exactly at the
    /// last message in that page.
    ///
    /// The caller passes the chain with the id, and this function does not look
    /// the chain up. Both come from the same place the messages beside them came
    /// from: the window, or the same database rows. A head looked up apart from
    /// the page it covers can describe a different moment than the page body.
    fn signed_head_at(&self, last_id: OrderId, chain: Chain) -> SignedHead {
        let signature = logchain::sign_head(&self.signing_key, &self.session, last_id, &chain);
        SignedHead {
            session: self.session.clone(),
            last_id,
            chain: logchain::to_hex(&chain),
            public_key: logchain::to_hex(self.signing_key.verifying_key().as_bytes()),
            signature: logchain::to_hex(&signature.to_bytes()),
        }
    }

    /// The signed head of the whole history right now. Everything is read
    /// under one lock, so a head always matches the messages served beside it.
    fn signed_head(&self) -> SignedHead {
        self.signed_head_at(self.last_id(), self.chain)
    }

    /// The signed tree head over everything published: "history `session`, at
    /// this millisecond, had `tree_size` messages under this root."
    ///
    /// # Why the timestamp is not the clock reading
    ///
    /// RFC 9162 and `docs/ENGINE.md` section 1.3 require each timestamp to be
    /// later than the one before it. That stops an operator serving an old tree
    /// as if it were the current one. The clock counts whole milliseconds, and
    /// this sequencer answers reads and publishes faster than that. So two heads
    /// asked for inside one millisecond would otherwise carry one timestamp.
    ///
    /// There are two cases, and they are not the same:
    ///
    /// - The size and the clock reading are both unchanged. Nothing this head
    ///   states has changed, so the head already signed is still the true
    ///   answer, and it is served again. That also saves one Ed25519 signature,
    ///   about 25 microseconds under the state lock, on every read after the
    ///   first in a millisecond.
    /// - The tree grew inside that millisecond, so a new head must be signed.
    ///   Its timestamp is the next millisecond, and not a repeat of this one.
    ///   That runs at most one millisecond ahead of the clock per publish, and
    ///   the clock catches up as soon as publishing stops.
    ///
    /// Across a restart this states nothing. `tree_head` starts empty, and the
    /// first timestamp is whatever the wall clock says. To hold the rule across
    /// a restart, the sequencer must write the last timestamp down. The place it
    /// belongs is the checkpoint, which still commits to the chain and not to
    /// the tree.
    fn signed_tree_head(&mut self) -> Result<SignedTreeHead, Unreadable> {
        let tree_size = self.tree_size();
        let now = self.clock.now_ms();
        if let Some(last) = &self.tree_head
            && last.tree_size == tree_size
            && last.timestamp >= now
        {
            return Ok(last.clone());
        }
        let timestamp = match &self.tree_head {
            Some(last) => now.max(last.timestamp + 1),
            None => now,
        };
        // At most 64 stored nodes and 64 hashes. The root of a tree of any size
        // is made by combining the full subtrees on its right edge, one per set
        // bit of the size. Nothing here grows with the history.
        let root = self.tree_root()?;
        let signature = logchain::sign_tree_head(
            &self.signing_key,
            &self.session,
            timestamp,
            tree_size,
            &root,
        );
        let head = SignedTreeHead {
            session: self.session.clone(),
            timestamp,
            tree_size,
            root_hash: logchain::to_hex(&root),
            public_key: logchain::to_hex(self.signing_key.verifying_key().as_bytes()),
            signature: logchain::to_hex(&signature.to_bytes()),
        };
        self.tree_head = Some(head.clone());
        Ok(head)
    }

    /// The number of leaves in the tree: one per published message.
    fn tree_size(&self) -> u64 {
        self.storage.leaves()
    }

    /// `MTH` over every message published so far.
    fn tree_root(&self) -> Result<Hash, Unreadable> {
        tree::root(&self.storage.nodes(), self.tree_size())
    }

    /// The inclusion proof for one leaf against the tree of size `tree_size`.
    ///
    /// `tree_size` is the caller's size, not this sequencer's. A client that
    /// holds a signed tree head from an hour ago must be able to check against
    /// the tree that head names. The root of any earlier size can still be
    /// computed from the tree now. That is what `merkle::mth` and this parameter
    /// are for.
    ///
    /// The two kinds of error are different things, and they stay apart all the
    /// way to the response. `Proof` means the caller named a leaf or a size this
    /// log does not have. `Source` means this log cannot read its own nodes. See
    /// `http::get_inclusion_proof`.
    fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<Vec<String>, TreeError<Unreadable>> {
        let path = merkle::path(&self.storage.nodes(), leaf_index, tree_size)?;
        Ok(path.iter().map(|node| logchain::to_hex(node)).collect())
    }

    /// The consistency proof between two sizes. It shows that the tree at
    /// `first` is the start of the tree at `second`. Both sizes are the
    /// caller's, as above.
    fn consistency_proof(
        &self,
        first: u64,
        second: u64,
    ) -> Result<Vec<String>, TreeError<Unreadable>> {
        let path = merkle::proof(&self.storage.nodes(), first, second)?;
        Ok(path.iter().map(|node| logchain::to_hex(node)).collect())
    }

    /// One page of the history after `since`, with the head standing at the
    /// page's last message.
    ///
    /// The window answers every poll a consumer that is keeping up makes. A
    /// consumer that starts from the beginning asks for messages that left
    /// memory long ago. That is `--verify`, `--audit`, or a bot reading the log
    /// again after a session change. Those messages are read back out of
    /// `feed_messages` a page at a time, with the chain column. So the head over
    /// a page served from disk is the link the sequencer stored next to its last
    /// message, and not a value computed here.
    ///
    /// `Err` is the one case where a message this sequencer published cannot be
    /// served at all. It happens on a sequencer running without a database
    /// (`--no-feed-db`), once the window has moved past what is asked for.
    /// Saying so is the true answer. The other option is to serve the page from
    /// wherever memory happens to start. Every consumer hashes that page into a
    /// chain that then disagrees with the head, and reads the difference as the
    /// sequencer having rewritten its history.
    ///
    /// # Why nothing here is turned back into bytes
    ///
    /// Both branches return the bytes the chain was hashed over, unchanged. The
    /// window holds those bytes (`Published`) and the database stores them. So a
    /// page answered from memory and the same page answered from disk are the
    /// same bytes. They have to be, because the head beside them is the same
    /// chain either way.
    ///
    /// The old disk branch parsed each row into an `OrderMessage`, and the
    /// handlers wrote it back to bytes on the way out. That made the bytes this
    /// sequencer serves depend on the struct this binary was compiled with. A
    /// field or a message kind added later comes back out missing, and the
    /// sequencer serves a page that does not hash to the chain stored on the
    /// same rows. Every consumer reads that as the sequencer having rewritten
    /// its own history.
    fn page(
        &self,
        since: OrderId,
        limit: usize,
    ) -> Result<(Vec<Published>, Option<(OrderId, Chain)>), String> {
        let first = since.saturating_add(1);
        if first > self.last_id() {
            return Ok((Vec::new(), None));
        }
        if let Some(index) = self.window_index(first) {
            let end = (index + limit).min(self.messages.len());
            let messages: Vec<Published> = self
                .messages
                .iter()
                .skip(index)
                .take(end - index)
                .cloned()
                .collect();
            let head = messages.last().map(|msg| (msg.id, self.chains[end - 1]));
            self.metrics.messages_served(messages.len() as u64, false);
            return Ok((messages, head));
        }
        let started = Instant::now();
        let Some(db) = self.storage.conn() else {
            return Err(format!(
                "message {} is no longer in this feed's memory and this feed has no database to \
                 read it back from, so the history from there cannot be served. It keeps the last \
                 {} messages only; start it with a feed database to serve the whole history",
                first, MESSAGE_WINDOW
            ));
        };
        let mut messages = Vec::new();
        let mut head = None;
        let mut statement = db
            .prepare_cached(
                "SELECT id, json, chain FROM feed_messages WHERE id > ?1 ORDER BY id LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let mut rows = statement
            .query(params![since as i64, limit as i64])
            .map_err(|e| e.to_string())?;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let id: i64 = row.get(0).map_err(|e| e.to_string())?;
            let json: String = row.get(1).map_err(|e| e.to_string())?;
            let chain: Vec<u8> = row.get(2).map_err(|e| e.to_string())?;
            let id = OrderId::try_from(id).map_err(|_| {
                format!(
                    "the feed database holds a row with the negative message id {}",
                    id
                )
            })?;
            let chain: Chain = chain.try_into().map_err(|c: Vec<u8>| {
                format!(
                    "the chain stored with message {} is {} bytes, not 32",
                    id,
                    c.len()
                )
            })?;
            head = Some((id, chain));
            messages.push(Published { id, json });
        }
        // The time is measured here, and not around the whole call. This branch
        // is the one that reads the disk, and it holds the state lock while it
        // does. It is counted even when it returned nothing, because a page read
        // that found no rows still paid for the query.
        self.metrics.db_page(started.elapsed());
        self.metrics.messages_served(messages.len() as u64, true);
        Ok((messages, head))
    }

    /// The chain standing after message `id`, without reading the message.
    ///
    /// This exists for `If-None-Match`. The ETag of a full page names the chain
    /// at that page's last message. Answering 304 must produce that value
    /// without doing the work the 304 exists to avoid. From the window it is one
    /// index. From the database it is one row read on the primary key, instead
    /// of the `limit` rows a served page reads.
    fn chain_at(&self, id: OrderId) -> Option<Chain> {
        if let Some(index) = self.window_index(id) {
            return self.chains.get(index).copied();
        }
        let db = self.storage.conn()?;
        let chain: Vec<u8> = db
            .query_row(
                "SELECT chain FROM feed_messages WHERE id = ?1",
                params![id as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| {
                error!("cannot read the chain at message {}: {}", id, e);
            })
            .ok()??;
        chain.try_into().ok()
    }

    /// Takes a read's cost out of the caller's budget, or refuses the read.
    ///
    /// A call from the loopback address is never charged. Every consumer this
    /// exchange runs reaches the sequencer at `http://127.0.0.1:3000`, both in
    /// `demo.sh` and inside the deployed container. That is the exchange, the
    /// three validators, the bot and the anchor sender. Public traffic arrives
    /// from Traefik with the visitor's address in `X-Forwarded-For`. So this
    /// line is what makes the default safe. A limit that could refuse a
    /// validator would be worse than no limit at all. A validator that cannot
    /// check twenty polls in a row marks itself stalled (`validator.rs`,
    /// `UNCHECKED_POLLS_BEFORE_STALL`), and the exchange then stops counting it
    /// among the validators that agree. Not charging the loopback makes that
    /// impossible, and not only unlikely.
    ///
    /// It gives nothing away. A caller already on this host does not need to use
    /// up a read budget to stop the sequencer.
    fn charge_read(&mut self, ip: IpAddr, cost: u64, now: Instant) -> Result<(), u64> {
        if ip.is_loopback() {
            return Ok(());
        }
        self.read_limiter.charge(ip, cost, now)
    }

    /// Gives back the part of a page cost that was not used. It is skipped for
    /// the loopback address, which was never charged.
    fn refund_read(&mut self, ip: IpAddr, amount: u64) {
        if ip.is_loopback() {
            return;
        }
        self.read_limiter.refund(ip, amount);
    }

    /// The signed head standing at `last_id`, as response headers.
    fn head_headers_at(
        &self,
        last_id: OrderId,
        chain: Chain,
    ) -> [(axum::http::HeaderName, String); 5] {
        let head = self.signed_head_at(last_id, chain);
        [
            (
                axum::http::HeaderName::from_static(SESSION_HEADER),
                head.session,
            ),
            (
                axum::http::HeaderName::from_static(HEAD_LAST_ID_HEADER),
                head.last_id.to_string(),
            ),
            (
                axum::http::HeaderName::from_static(HEAD_CHAIN_HEADER),
                head.chain,
            ),
            (
                axum::http::HeaderName::from_static(HEAD_PUBKEY_HEADER),
                head.public_key,
            ),
            (
                axum::http::HeaderName::from_static(HEAD_SIGNATURE_HEADER),
                head.signature,
            ),
        ]
    }
}

/// A random name for one history of this sequencer.
fn new_session() -> String {
    format!("{:016x}", rand::thread_rng().r#gen::<u64>())
}

/// Takes the state lock, or ends the process.
///
/// A poisoned lock means a thread panicked while it held this state. The
/// separate service's lock guards a SQLite connection and a few counters, and
/// each statement there stands on its own. This lock is different. It guards
/// three things that must agree: the messages, the chain hashed over them, and
/// the checkpoint signed for that chain. Continuing with a state that may be
/// half updated means signing heads for a history the sequencer cannot show it
/// published. That is the one failure this service must never produce.
///
/// Exiting is also the repair. `feed.db` is written to disk and holds a
/// checkpoint, so a restart by the supervisor reads back exactly the history
/// that was published. The process dying is what makes the supervisor restart
/// it. The old code left the process up, with every request panicking on the
/// poisoned lock: alive, holding the port, and serving nothing.
fn lock(state: &Arc<Mutex<FeedState>>) -> MutexGuard<'_, FeedState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(_) => {
            error!(
                "the feed state lock is poisoned: a thread panicked while holding it, so the \
                 published messages, the hash chain and the signed checkpoint may no longer \
                 agree. Stopping; a restart reloads the history from the database"
            );
            std::process::exit(2);
        }
    }
}

/// Runs one operation against the sequencer state, off the async runtime.
///
/// Every publish ends in an `fsync` (`synchronous = FULL`) while the state lock
/// is held. On an async worker thread that stops every other request the
/// runtime had put on that thread. So the work runs on a blocking thread
/// instead. `inbox.rs` does the same thing for the same reason.
///
/// The lock is held across the write on purpose. The exchange takes a different
/// route: it moves its store out of the state and commits outside the lock. The
/// exchange can do that because it commits copies of its state in groups. Here
/// the order messages are added to the chain, and the order they are written in
/// *is* the order they are published in. Two publishes that overlap would
/// compute their chain values against a head that moved under them.
async fn with_state<T, F>(state: &Arc<Mutex<FeedState>>, f: F) -> Result<T, (StatusCode, String)>
where
    F: FnOnce(&mut FeedState) -> T + Send + 'static,
    T: Send + 'static,
{
    let state = Arc::clone(state);
    tokio::task::spawn_blocking(move || f(&mut lock(&state)))
        .await
        .map_err(|e| {
            error!("feed state worker failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "feed state worker failed".to_string(),
            )
        })
}

/// The signed head of the log, as served by `GET /head` and, field for
/// field, in the `x-feed-*` response headers. All byte values are hex.
#[derive(Serialize)]
struct SignedHead {
    session: String,
    last_id: OrderId,
    chain: String,
    public_key: String,
    signature: String,
}

/// The signed tree head, as served by `GET /sth`.
///
/// `timestamp`, `tree_size` and `root_hash` are RFC 9162 `TreeHeadDataV2`. The
/// session and the two hex key fields are this sequencer's. They are the same
/// three fields `SignedHead` carries, for the same reasons: a head names which
/// history it belongs to, and it carries the key that signed it.
///
/// When nothing has changed, the head is copied instead of signed again. That
/// is why it derives `Clone`. See `signed_tree_head`.
#[derive(Serialize, Clone)]
struct SignedTreeHead {
    session: String,
    /// Milliseconds since the Unix epoch, from the same clock message
    /// timestamps come from.
    timestamp: u64,
    tree_size: u64,
    root_hash: String,
    public_key: String,
    signature: String,
}

/// The answer to `GET /proof/inclusion`.
///
/// No root and no signature. The root a proof is checked against must come from
/// a signed tree head the client already holds. Serving an unsigned root next to
/// the proof would lead a client to check the proof against a root this
/// sequencer never signed. That check always passes, and it proves nothing.
///
/// `message_id` is here because the two ways of counting differ by one, and that
/// is the mistake a client makes. RFC 9162 counts leaves from 0, and this
/// sequencer numbers messages from 1, so leaf 33,753 is message 33,754. The code
/// that checks a proof needs `leaf_index`. A reader looking at
/// `/messages.ndjson` has `message_id`.
#[derive(Serialize)]
struct InclusionProof {
    session: String,
    leaf_index: u64,
    message_id: OrderId,
    tree_size: u64,
    /// The node hashes, the leaf's sibling first, each 64 hex characters.
    inclusion_path: Vec<String>,
}

/// The answer to `GET /proof/consistency`. No roots, for the reason given on
/// `InclusionProof`: both roots come from signed tree heads the client holds.
#[derive(Serialize)]
struct ConsistencyProof {
    session: String,
    first: u64,
    second: u64,
    consistency_path: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::cache::OPEN_CACHE_CONTROL;
    use super::drain::sequence_drained;
    use super::generate::{generate_message, produce_orders, round2};
    use super::http::{
        GetOrdersQuery, MessagesQuery, SUBMISSION_PATHS, SubmitCancelRequest,
        SubmitOperatorRequest, SubmitOrderRequest, SubmitResponse, feed_router,
        get_messages_ndjson, get_orders, submit_cancel, submit_operator, submit_order,
    };
    use super::limit::READ_BURST;
    use super::metrics::METRICS_CONTENT_TYPE;
    use super::*;
    use crate::cors::CorsPolicy;
    use crate::domain::{OPERATOR_ACCOUNT, OrderType, Side, TimeInForce};
    use crate::inbox::{Caller, Entry as InboxEntry, SUBMIT_BURST, SignedSubmission, Submission};
    use crate::merkle::{self, NodeSource};
    use crate::operator;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue};
    use axum::response::Response;
    use axum::{Json, Router};
    use std::time::Duration;
    use tempfile::TempDir;
    use tower::ServiceExt;

    const WALL: u64 = 1_700_000_000_000;

    // -----------------------------------------------------------------------
    // Cross-origin submissions
    //
    // The rules and their own tests are in `cors.rs`. These tests pin what
    // this sequencer grants under those rules. A browser asks permission
    // before a cross-site POST, and that question is the preflight. The tests
    // pin which paths answer a preflight, and that the answers reach the wire.
    // -----------------------------------------------------------------------

    use crate::cors::testing::{default_origins, headers};
    use crate::cors::{Cors, cors_for};
    // Only the router tests need these: the cross-origin rules live in a
    // middleware layer, so they are driven with whole requests and read off
    // whole responses.
    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{Method, header};

    /// This sequencer's policy, exactly as `feed_router` builds it.
    fn feed_policy(allowed: Vec<String>) -> CorsPolicy {
        CorsPolicy::new(allowed, &SUBMISSION_PATHS, "feed")
    }

    #[test]
    fn a_request_without_an_origin_is_not_a_browser_and_is_left_alone() {
        let (origin, decision) = cors_for(
            &feed_policy(default_origins()),
            &Method::POST,
            "/order",
            &headers(&[("content-type", "application/json")]),
        );
        assert_eq!(origin, None);
        assert_eq!(decision, Cors::NotBrowser);
    }

    #[test]
    fn a_preflight_is_answered_only_for_a_listed_origin_and_a_submission_path() {
        let allowed = feed_policy(default_origins());
        let preflight = headers(&[
            ("origin", "http://127.0.0.1:3001"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
        ]);
        for path in ["/order", "/cancel"] {
            let (_, decision) = cors_for(&allowed, &Method::OPTIONS, path, &preflight);
            assert_eq!(decision, Cors::PreflightAllowed, "{}", path);
        }
        // Every other path this sequencer serves takes no submissions. No
        // browser needs to preflight them, so the grant does not widen to
        // them.
        for path in [
            "/orders",
            "/head",
            "/symbols",
            "/messages.ndjson",
            "/anything",
        ] {
            let (_, decision) = cors_for(&allowed, &Method::OPTIONS, path, &preflight);
            assert_eq!(decision, Cors::PreflightRefused, "{}", path);
        }
        // A neighbouring port, a different scheme, a hostname that starts with
        // the real one, and `null` are all not on the list.
        for origin in [
            "http://127.0.0.1:3002",
            "https://127.0.0.1:3001",
            "http://127.0.0.1.evil.example",
            "null",
        ] {
            let refused = headers(&[
                ("origin", origin),
                ("access-control-request-method", "POST"),
            ]);
            let (seen, decision) = cors_for(&allowed, &Method::OPTIONS, "/order", &refused);
            assert_eq!(seen.as_deref(), Some(origin));
            assert_eq!(decision, Cors::PreflightRefused, "{}", origin);
        }
    }

    /// An `OPTIONS` without `Access-Control-Request-Method` is not a preflight.
    /// It is an ordinary request. If the code read it as a preflight, the
    /// answer would be 204 for a method the router refuses.
    #[test]
    fn options_without_a_requested_method_is_not_a_preflight() {
        let (_, decision) = cors_for(
            &feed_policy(default_origins()),
            &Method::OPTIONS,
            "/order",
            &headers(&[("origin", "http://127.0.0.1:3001")]),
        );
        assert_eq!(decision, Cors::Allowed);
    }

    /// The tests above check the decision. This test checks that the decision
    /// reaches the response headers.
    #[tokio::test]
    async fn the_router_grants_exactly_what_the_ui_needs_and_nothing_else() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        let router = || feed_router(Arc::clone(&state), default_origins(), None);

        let granted = router()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/order")
                    .header("origin", "http://localhost:3001")
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(granted.status(), StatusCode::NO_CONTENT);
        let head = granted.headers();
        assert_eq!(
            head.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "http://localhost:3001",
            "the matched entry from the operator's list, not a reflection"
        );
        assert_eq!(
            head.get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
            "POST"
        );
        assert_eq!(
            head.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "content-type"
        );
        assert_eq!(head.get(header::VARY).unwrap(), "origin");
        assert!(
            head.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).is_none(),
            "a submission must never carry cookies: the signature is what speaks for an account"
        );

        // An origin nobody named gets no grant, and is told which flag decides.
        let refused = router()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/order")
                    .header("origin", "https://evil.example")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(
            refused
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "an origin that is not on the list must never be echoed back"
        );
        assert_eq!(refused.headers().get(header::VARY).unwrap(), "origin");

        // A read from a listed origin is readable; the same read from an
        // unlisted one still runs, and the browser hides the answer.
        for (origin, expected) in [
            ("http://127.0.0.1:3001", Some("http://127.0.0.1:3001")),
            ("https://evil.example", None),
        ] {
            let response = router()
                .oneshot(
                    Request::builder()
                        .uri("/symbols")
                        .header("origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .expect("the router answers");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .map(|v| v.to_str().unwrap()),
                expected,
                "origin {}",
                origin
            );
        }

        // The CLI, the bot and curl send no Origin header. They are granted
        // nothing: no `Access-Control-Allow-Origin`. A browser could not read
        // this copy of the answer.
        //
        // `Vary: origin` is still there, and has to be. `Vary` is not a grant.
        // It stops a shared cache from handing this copy, the one with no
        // grant on it, to a browser. The browser would then refuse an answer
        // from a sequencer that is working. That matters here because closed
        // pages are served `public, immutable` and really are stored.
        let plain = router()
            .oneshot(
                Request::builder()
                    .uri("/symbols")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(plain.status(), StatusCode::OK);
        assert!(
            plain
                .headers()
                .get_all(header::VARY)
                .iter()
                .any(|v| v.to_str().is_ok_and(|v| v.contains("origin")))
        );
        assert!(
            plain
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    /// A sequencer started with no `--ui-origin` grants nothing. This needs a
    /// test: an empty list must mean "nobody", never "everybody".
    #[tokio::test]
    async fn an_empty_allowlist_lets_no_browser_submit() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        let response = feed_router(state, Vec::new(), None)
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/order")
                    .header("origin", "http://127.0.0.1:3001")
                    .header("access-control-request-method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    /// A caller that connects to the sequencer directly. Every test that is
    /// not about a proxy uses this caller.
    fn peer() -> Caller {
        Caller::from_socket("127.0.0.1:40000")
    }

    /// A caller from another machine. Every read-budget test needs one. The
    /// loopback address is exempt on purpose, because the exchange, the
    /// validators and the bot all connect from there. See
    /// `FeedState::charge_read`.
    fn reader(ip: &str) -> Caller {
        Caller::from_socket(&format!("{}:52000", ip))
    }

    /// Every header on a response, by name. These tests read the signed head
    /// and the cache headers this way.
    fn headers_of(response: &Response) -> HashMap<String, String> {
        response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    }

    async fn body_of(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body")
            .to_vec()
    }

    /// One `/orders` page for a caller on this machine, with no conditional
    /// headers. Every test written before the cache headers existed uses this.
    async fn orders(
        state: &Arc<Mutex<FeedState>>,
        since: Option<OrderId>,
        n: Option<usize>,
    ) -> Result<(HashMap<String, String>, Vec<OrderMessage>), (StatusCode, String)> {
        let response = orders_from(state, peer(), since, n, &[]).await?;
        let headers = headers_of(&response);
        let messages = serde_json::from_slice(&body_of(response).await)
            .expect("/orders answers with an array of messages");
        Ok((headers, messages))
    }

    /// The same, naming the caller and the request headers.
    async fn orders_from(
        state: &Arc<Mutex<FeedState>>,
        caller: Caller,
        since: Option<OrderId>,
        n: Option<usize>,
        request_headers: &[(&str, &str)],
    ) -> Result<Response, (StatusCode, String)> {
        get_orders(
            State(Arc::clone(state)),
            caller,
            header_map(request_headers),
            Query(GetOrdersQuery { since, n }),
        )
        .await
    }

    /// One `/messages.ndjson` page, naming the caller and the request headers.
    async fn ndjson_from(
        state: &Arc<Mutex<FeedState>>,
        caller: Caller,
        since: Option<OrderId>,
        limit: Option<usize>,
        request_headers: &[(&str, &str)],
    ) -> Result<Response, (StatusCode, String)> {
        get_messages_ndjson(
            State(Arc::clone(state)),
            caller,
            header_map(request_headers),
            Query(MessagesQuery { since, limit }),
        )
        .await
    }

    /// A GET the router can answer. The request carries the caller's address,
    /// because every read names its caller. The server adds the address with
    /// `into_make_service_with_connect_info`. A request without an address is
    /// refused, not put in one bucket shared with the whole internet.
    fn local_request(uri: &str) -> Request<Body> {
        use axum::extract::ConnectInfo;

        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("a request");
        request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
            "127.0.0.1:40000".parse().expect("a socket address"),
        ));
        request
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
                HeaderValue::from_str(value).expect("a header value"),
            );
        }
        map
    }

    // -----------------------------------------------------------------------
    // Submissions through a reverse proxy
    // -----------------------------------------------------------------------

    /// The operator's `--trusted-proxy` list, as the CLI hands it over.
    fn trusted(specs: &[&str]) -> TrustedProxies {
        TrustedProxies::parse(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("these values have to parse")
    }

    /// A sequencer that trusts one proxy, with the log held in memory.
    fn feed_behind(trusted_proxies: TrustedProxies) -> Arc<Mutex<FeedState>> {
        let mut state = on_test_session(FeedState::new(4, WALL));
        state.trusted_proxies = trusted_proxies;
        Arc::new(Mutex::new(state))
    }

    /// A `POST /order` body on the wire, as the UI and curl send one.
    fn order_body(req: &SubmitOrderRequest) -> Body {
        Body::from(
            serde_json::json!({
                "account": req.account,
                "symbol": req.symbol,
                "side": req.side,
                "price": req.price,
                "quantity": req.quantity,
                "nonce": req.nonce,
                "session": req.session,
                "order_type": req.order_type,
                "time_in_force": req.time_in_force,
                "post_only": req.post_only,
                "public_key": req.public_key,
                "signature": req.signature,
            })
            .to_string(),
        )
    }

    /// The bug this mechanism exists for, on the sequencer's own HTTP handler.
    /// Behind a proxy every visitor and the bot arrive from the proxy's
    /// address. They used to share one bucket of `SUBMIT_BURST` and lock each
    /// other out.
    #[tokio::test]
    async fn two_clients_behind_one_proxy_do_not_share_a_bucket() {
        let state = feed_behind(trusted(&["172.17.0.0/16"]));
        let owner = logchain::ephemeral_key();
        let first = Caller::with_forwarded("172.17.0.3:41000", &["203.0.113.9"]);
        let second = Caller::with_forwarded("172.17.0.3:41000", &["198.51.100.7"]);

        for i in 0..SUBMIT_BURST {
            let accepted = submit_order(
                State(Arc::clone(&state)),
                first.clone(),
                Ok(Json(order_request(&owner, 1000, 100.25, 5.0))),
            )
            .await;
            assert!(accepted.is_ok(), "submission {} from the first client", i);
        }
        let (status, _) = refused(
            submit_order(
                State(Arc::clone(&state)),
                first.clone(),
                Ok(Json(order_request(&owner, 1000, 100.25, 5.0))),
            )
            .await,
            "the first client has used its whole burst",
        );
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

        assert!(
            submit_order(
                State(Arc::clone(&state)),
                second,
                Ok(Json(order_request(&owner, 1000, 100.25, 5.0))),
            )
            .await
            .is_ok(),
            "a second client behind the same proxy must have its own bucket"
        );
    }

    /// The same header, sent by a peer the operator did not name. The
    /// sequencer ignores the header. It counts the submission against the
    /// address the socket reports, so writing addresses into a header buys no
    /// second bucket.
    #[tokio::test]
    async fn a_forged_header_from_an_untrusted_peer_is_ignored() {
        let state = feed_behind(trusted(&["172.17.0.0/16"]));
        let owner = logchain::ephemeral_key();
        for i in 0..SUBMIT_BURST {
            let caller =
                Caller::with_forwarded("203.0.113.9:52000", &[&format!("10.0.0.{}", i % 200)]);
            let accepted = submit_order(
                State(Arc::clone(&state)),
                caller,
                Ok(Json(order_request(&owner, 1000, 100.25, 5.0))),
            )
            .await;
            assert!(accepted.is_ok(), "submission {}", i);
        }
        let (status, message) = refused(
            submit_order(
                State(Arc::clone(&state)),
                Caller::with_forwarded("203.0.113.9:52000", &["10.9.9.9"]),
                Ok(Json(order_request(&owner, 1000, 100.25, 5.0))),
            )
            .await,
            "a header from an untrusted peer must not open a new bucket",
        );
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            message.contains("203.0.113.9"),
            "the refusal names the address it counted, which is the socket's: {}",
            message
        );
    }

    /// The same rule over a real request, not a direct handler call. The
    /// header name that is read and the peer address the server sees both come
    /// from the request itself.
    #[tokio::test]
    async fn the_header_is_read_from_the_request_only_when_the_peer_is_the_proxy() {
        use axum::extract::ConnectInfo;

        let state = feed_behind(trusted(&["172.17.0.3"]));
        let owner = logchain::ephemeral_key();
        // One client spends its whole burst through the handler. The test then
        // pays for one HTTP round trip, not a hundred.
        let client = Caller::with_forwarded("172.17.0.3:41000", &["203.0.113.9"]);
        for _ in 0..SUBMIT_BURST {
            let accepted = submit_order(
                State(Arc::clone(&state)),
                client.clone(),
                Ok(Json(order_request(&owner, 1000, 100.25, 5.0))),
            )
            .await;
            assert!(accepted.is_ok(), "the burst itself is allowed");
        }

        let through_proxy = |peer: &str, forwarded: &str, req: SubmitOrderRequest| {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/order")
                .header("content-type", "application/json")
                .header("x-forwarded-for", forwarded)
                .body(order_body(&req))
                .expect("a request");
            request.extensions_mut().insert(ConnectInfo::<SocketAddr>(
                peer.parse().expect("a socket address"),
            ));
            request
        };

        // The request comes from the proxy, so the header decides. This client
        // is out of submissions.
        let refused = feed_router(Arc::clone(&state), Vec::new(), None)
            .oneshot(through_proxy(
                "172.17.0.3:41000",
                "203.0.113.9",
                order_request(&owner, 1000, 100.25, 5.0),
            ))
            .await
            .expect("the router answers");
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);

        // The same header from an address the operator did not name is not
        // read at all. That caller has its own bucket, still full.
        let accepted = feed_router(Arc::clone(&state), Vec::new(), None)
            .oneshot(through_proxy(
                "198.51.100.7:52000",
                "203.0.113.9",
                order_request(&owner, 1000, 100.25, 5.0),
            ))
            .await
            .expect("the router answers");
        assert_eq!(accepted.status(), StatusCode::OK);
    }

    /// A sequencer on a real file, with one key that does not change. A reopen
    /// is then the same identity.
    fn feed_at(dir: &TempDir) -> (PathBuf, SigningKey) {
        (dir.path().join("feed.db"), logchain::ephemeral_key())
    }

    fn open(path: &Path, key: &SigningKey) -> Result<FeedState, String> {
        FeedState::with_db(4, path, key.clone(), WALL)
    }

    /// The reason a database refused to start. `expect_err` would need the
    /// whole `FeedState` to be `Debug`, only to build a message it never
    /// prints.
    fn refusal(result: Result<FeedState, String>, why: &str) -> String {
        match result {
            Ok(_) => panic!("this database must not start: {}", why),
            Err(e) => e,
        }
    }

    /// The same, for a refused request.
    fn refused<T>(result: Result<T, (StatusCode, String)>, why: &str) -> (StatusCode, String) {
        match result {
            Ok(_) => panic!("this request must be refused: {}", why),
            Err(e) => e,
        }
    }

    /// A generated order: no nonce, exactly as the generator publishes one.
    fn order(id: OrderId, price: f64) -> OrderMessage {
        OrderMessage::New {
            id,
            timestamp: WALL + id,
            account: 1,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price,
            quantity: 5.0,
            nonce: None,
            order_type: Default::default(),
            time_in_force: Default::default(),
            post_only: false,
        }
    }

    /// The same order with a submitter's nonce, which is what a signed
    /// submission turns into.
    fn order_with_nonce(id: OrderId, price: f64, nonce: &str) -> OrderMessage {
        match order(id, price) {
            OrderMessage::New {
                id,
                timestamp,
                account,
                symbol,
                side,
                price,
                quantity,
                order_type,
                time_in_force,
                post_only,
                ..
            } => OrderMessage::New {
                id,
                timestamp,
                account,
                symbol,
                side,
                price,
                quantity,
                nonce: Some(nonce.to_string()),
                order_type,
                time_in_force,
                post_only,
            },
            other => other,
        }
    }

    /// The session the request builders below sign for. Sixteen lowercase hex
    /// characters, the shape `new_session` prints. A sequencer these requests
    /// are sent to has to be on this session, and `on_test_session` puts one
    /// there.
    const TEST_SESSION: &str = "349d462ced25bb2b";

    /// Puts a sequencer on the session the request builders sign for.
    ///
    /// The session a fresh database mints is random, and every request below
    /// is signed for one fixed session, so a test that submits or drains has
    /// to bring the two together. Only the tests that submit or drain call
    /// this. Some tests are about sessions themselves: a database that is
    /// emptied gets a new session, and a reopened one keeps its session. Those
    /// tests read the session the database really minted, and this function
    /// would hide exactly what they check.
    fn on_test_session(mut state: FeedState) -> FeedState {
        state.session = TEST_SESSION.to_string();
        state
    }

    /// A nonce in the right form, and readable in a failure message.
    fn nonce(tag: u8) -> String {
        logchain::to_hex(&[tag; inbox::NONCE_BYTES])
    }

    fn order_submission(account: AccountId, price: f64, nonce: &str) -> Submission {
        Submission::Order {
            account,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price,
            quantity: 5.0,
            nonce: Some(nonce.to_string()),
            session: Some(TEST_SESSION.to_string()),
            order_type: OrderType::Limit,
            time_in_force: TimeInForce::GoodTillCancel,
            post_only: false,
        }
    }

    /// Publishes one order the way a live caller does. Takes the next id,
    /// builds the message with it, and publishes.
    fn publish_next(state: &mut FeedState, price: f64) -> Result<OrderId, String> {
        let id = state.next_id;
        state.next_id += 1;
        state.publish(order(id, price)).map(|()| id)
    }

    fn chain_of<'a>(messages: impl IntoIterator<Item = &'a OrderMessage>) -> Chain {
        messages
            .into_iter()
            .fold(EMPTY_CHAIN, |chain, msg| logchain::extend(&chain, msg))
    }

    /// The chain over what the sequencer holds in memory. It hashes the way
    /// the sequencer hashes: over the stored bytes, with no parse and no
    /// second serialization.
    fn window_chain(messages: &VecDeque<Published>) -> Chain {
        messages.iter().fold(EMPTY_CHAIN, |chain, msg| {
            logchain::extend_bytes(&chain, msg.json.as_bytes())
        })
    }

    /// One message of the window, read back as a message. The window holds
    /// bytes. A test that wants one field parses those bytes, exactly as the
    /// drain code does.
    fn parsed(msg: &Published) -> OrderMessage {
        serde_json::from_str(&msg.json).expect("this build published it")
    }

    /// The key and signature a caller puts on a submission.
    ///
    /// A submission with a price off the price step has no statement to sign,
    /// so it gets a placeholder signature. The handler refuses such a
    /// submission on its values before it looks at any signature, so the
    /// placeholder never reaches a signature check.
    fn proof(key: &SigningKey, submission: &Submission) -> (String, String) {
        match inbox::sign_submission(key, submission) {
            Some(signed) => (signed.public_key, signed.signature),
            None => (
                logchain::to_hex(key.verifying_key().as_bytes()),
                logchain::to_hex(&[0u8; 64]),
            ),
        }
    }

    /// A `POST /order` body, signed the way a real caller signs one, under a
    /// nonce of its own.
    fn order_request(
        key: &SigningKey,
        account: AccountId,
        price: f64,
        quantity: f64,
    ) -> SubmitOrderRequest {
        order_request_with_nonce(key, account, price, quantity, &inbox::new_nonce())
    }

    fn order_request_with_nonce(
        key: &SigningKey,
        account: AccountId,
        price: f64,
        quantity: f64,
        nonce: &str,
    ) -> SubmitOrderRequest {
        order_request_with_terms(
            key,
            account,
            price,
            quantity,
            nonce,
            OrderType::Limit,
            TimeInForce::GoodTillCancel,
            false,
        )
    }

    /// The same body, with the three order terms named. The submission that is
    /// signed and the body that is sent carry the same three, which is the
    /// property a signature over them is there to hold.
    #[allow(clippy::too_many_arguments)]
    fn order_request_with_terms(
        key: &SigningKey,
        account: AccountId,
        price: f64,
        quantity: f64,
        nonce: &str,
        order_type: OrderType,
        time_in_force: TimeInForce,
        post_only: bool,
    ) -> SubmitOrderRequest {
        let submission = Submission::Order {
            account,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price,
            quantity,
            nonce: Some(nonce.to_string()),
            session: Some(TEST_SESSION.to_string()),
            order_type,
            time_in_force,
            post_only,
        };
        let (public_key, signature) = proof(key, &submission);
        SubmitOrderRequest {
            account,
            symbol: "ETH-USDC".to_string(),
            side: Side::Buy,
            price,
            quantity,
            nonce: nonce.to_string(),
            session: TEST_SESSION.to_string(),
            order_type,
            time_in_force,
            post_only,
            public_key,
            signature,
        }
    }

    /// A `POST /cancel` body, signed the same way.
    fn cancel_request(
        key: &SigningKey,
        account: AccountId,
        target_id: OrderId,
    ) -> SubmitCancelRequest {
        cancel_request_with_nonce(key, account, target_id, &inbox::new_nonce())
    }

    fn cancel_request_with_nonce(
        key: &SigningKey,
        account: AccountId,
        target_id: OrderId,
        nonce: &str,
    ) -> SubmitCancelRequest {
        let submission = Submission::Cancel {
            account,
            target_id,
            nonce: Some(nonce.to_string()),
            session: Some(TEST_SESSION.to_string()),
        };
        let (public_key, signature) = proof(key, &submission);
        SubmitCancelRequest {
            account,
            target_id,
            nonce: nonce.to_string(),
            session: TEST_SESSION.to_string(),
            public_key,
            signature,
        }
    }

    /// The entry the separate service would have made from this `POST /order`
    /// body, if the body had gone there instead. Same signed bytes, same
    /// nonce.
    fn entry_from_order(req: &SubmitOrderRequest, inbox_id: i64) -> InboxEntry {
        InboxEntry {
            inbox_id,
            received_at: WALL,
            submission: Submission::Order {
                account: req.account,
                symbol: req.symbol.clone(),
                side: req.side,
                price: req.price,
                quantity: req.quantity,
                nonce: Some(req.nonce.clone()),
                session: Some(req.session.clone()),
                order_type: req.order_type,
                time_in_force: req.time_in_force,
                post_only: req.post_only,
            },
            public_key: req.public_key.clone(),
            signature: req.signature.clone(),
            feed_id: None,
            sequenced_at: None,
            content_checked: None,
        }
    }

    /// An entry of the separate service with its submitter's proof, as
    /// `GET /pending` serves one.
    fn inbox_entry(key: &SigningKey, inbox_id: i64, submission: Submission) -> InboxEntry {
        let (public_key, signature) = proof(key, &submission);
        InboxEntry {
            inbox_id,
            received_at: WALL,
            submission,
            public_key,
            signature,
            feed_id: None,
            sequenced_at: None,
            content_checked: None,
        }
    }

    /// The rule the whole log rests on. After a restart the sequencer serves
    /// what it published before, down to the chain hash and the signature over
    /// it.
    #[test]
    fn a_restart_reproduces_the_same_chain() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);

        let published = {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
            state
                .publish_batch(vec![order(2, 100.26), order(3, 100.27)])
                .expect("published");
            state.publish(order(4, 100.28)).expect("published");
            (state.chain, state.messages.clone(), state.session.clone())
        };

        let state = open(&path, &key).expect("the same database");
        assert_eq!(state.chain, published.0);
        assert_eq!(state.chain, window_chain(&state.messages));
        assert_eq!(state.messages.len(), published.1.len());
        assert_eq!(
            state.next_id, 5,
            "the ids continue where the history ended, so a consumer cannot tell it restarted"
        );
        // The common case, and the one the session change must not break. A
        // restart onto a checkpointed history reads the same history under the
        // same name, so nothing downstream resets.
        assert_eq!(
            state.session, published.2,
            "a restart with a checkpoint continues the history it published, under its own name"
        );
        assert_eq!(state.session, open(&path, &key).unwrap().session);

        // The head the sequencer signs after the reload verifies against its
        // own key.
        let head = state.signed_head();
        let chain = logchain::from_hex::<32>(&head.chain).unwrap();
        let signature = Signature::from_bytes(&logchain::from_hex::<64>(&head.signature).unwrap());
        assert!(logchain::verify_head(
            &key.verifying_key(),
            &head.session,
            head.last_id,
            &chain,
            &signature
        ));
        assert_eq!(head.last_id, 4);
    }

    /// Makes every insert into `feed_messages` fail, the way a full or broken
    /// disk would.
    fn break_writes(state: &FeedState) {
        state
            .storage
            .conn()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_writes BEFORE INSERT ON feed_messages
                 BEGIN SELECT RAISE(ABORT, 'disk'); END;",
            )
            .unwrap();
    }

    /// Finding 1. A message that could not be written is not published, not
    /// counted, and not visible anywhere.
    #[test]
    fn a_failed_write_publishes_nothing() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database");
        publish_next(&mut state, 100.25).expect("published");
        let good_chain = state.chain;
        assert_eq!(state.next_id, 2);
        break_writes(&state);

        let failed = publish_next(&mut state, 100.26);
        assert!(
            failed.is_err(),
            "the write failed, so the publish must fail"
        );
        assert_eq!(state.messages.len(), 1, "nothing was published");
        assert_eq!(state.chain, good_chain, "the chain did not move");
        assert_eq!(state.next_id, 2, "and id 2 is handed out again");
        assert!(state.message(2).is_none());
        // The head still describes the history that really exists.
        assert_eq!(state.signed_head().last_id, 1);

        // And the database itself never saw the message.
        drop(state);
        let state = open(&path, &key).expect("the database is intact");
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.chain, good_chain);
    }

    /// Finding 1, the half about the separate service. A failed write must
    /// leave nothing that could be marked. Otherwise the sequencer would tell
    /// the separate service that an entry is in a log that does not hold it.
    #[test]
    fn a_failed_write_leaves_no_inbox_pairing() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database");
        break_writes(&state);

        let failed = state.sequence(vec![(Some(("epoch1".to_string(), 1)), order(1, 100.25))]);
        assert!(failed.is_err());
        assert!(
            state.inbox_sequenced.is_empty(),
            "an unsequenced entry has no pairing"
        );
        assert!(
            state.message(1).is_none(),
            "and no message for a mark to carry"
        );
        assert_eq!(state.next_id, 1);
    }

    /// Findings 2 and 3. An edited message is refused, not repaired. The old
    /// code rewrote the stored chain links to match the edit and signed the
    /// result, so the edit was invisible from the next restart on.
    #[test]
    fn an_edited_message_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26), order(3, 100.27)])
                .expect("published");
        }

        let conn = Connection::open(&path).unwrap();
        let edited = serde_json::to_string(&order(2, 999.99)).unwrap();
        conn.execute(
            "UPDATE feed_messages SET json = ?1 WHERE id = 2",
            params![edited],
        )
        .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "the history was edited");
        assert!(
            refused.contains("does not hold the history this feed last published"),
            "unexpected error: {}",
            refused
        );
    }

    /// Finding 3. Cutting rows off the end used to keep the same session. The
    /// sequencer then handed out the freed ids again, with different content,
    /// and said nothing.
    #[test]
    fn a_truncated_history_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26), order(3, 100.27)])
                .expect("published");
        }

        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM feed_messages WHERE id = 3", [])
            .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "the history was truncated");
        assert!(
            refused.contains("does not hold the history this feed last published"),
            "unexpected error: {}",
            refused
        );
    }

    /// A row taken out of the middle moves every later row up one place, so
    /// the ids no longer run 1, 2, 3 without a gap. The id check catches that
    /// before the chain check does.
    #[test]
    fn a_hole_in_the_middle_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26), order(3, 100.27)])
                .expect("published");
        }

        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM feed_messages WHERE id = 2", [])
            .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "a row was removed from the middle");
        assert!(
            refused.contains("message ids in"),
            "unexpected error: {}",
            refused
        );
    }

    /// The checkpoint is the evidence a start checks against. Deleting it is
    /// refused for the same reason an edit is. This also covers an emptied
    /// `feed_meta`: the session comes back new, and the messages beside it
    /// have nothing to check against.
    #[test]
    fn a_history_without_a_checkpoint_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
        }

        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM feed_meta", []).unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "there is no checkpoint to check against");
        assert!(
            refused.contains("no signed checkpoint"),
            "unexpected error: {}",
            refused
        );
    }

    /// The same refusal when only the checkpoint row is deleted and the session
    /// row stays. This is what the wipe below looks like when the attacker does
    /// not also empty `feed_messages`.
    #[test]
    fn a_history_whose_checkpoint_alone_was_deleted_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let session = {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
            state.session.clone()
        };

        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM feed_meta WHERE key = 'checkpoint'", [])
            .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "there is no checkpoint to check against");
        assert!(
            refused.contains("no signed checkpoint"),
            "unexpected error: {}",
            refused
        );
        assert!(
            !refused.contains(&session),
            "and it does not start under the old name to say so: {}",
            refused
        );
    }

    /// A checkpoint with no session beside it is a signature over a name the
    /// file no longer holds. Nothing can check that signature, so the start
    /// refuses here. The other choice was to let the signature check fail
    /// under a new name, and that would report a key problem when the real
    /// problem is a missing row.
    #[test]
    fn a_checkpoint_without_its_session_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
        }

        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM feed_meta WHERE key = 'session'", [])
            .unwrap();
        drop(conn);

        let refused = refusal(
            open(&path, &key),
            "the session the checkpoint names is gone",
        );
        assert!(
            refused.contains("names no session"),
            "unexpected error: {}",
            refused
        );
    }

    /// The attack this change closes, exactly as it was reproduced by hand:
    /// delete every message and the checkpoint, leave the session row and
    /// `feed.key` where they are, then restart.
    ///
    /// Before this change, all three checks a start makes passed on an empty
    /// table. Each of those checks reads a row the attacker deletes. The
    /// sequencer came back up under the name consumers had already pinned, and
    /// signed a second, different history under that name. Nothing was
    /// refused, nothing was warned about, and one key signed two histories
    /// under one name.
    #[test]
    fn a_wiped_history_starts_under_a_new_session() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let published = {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26), order(3, 100.27)])
                .expect("published");
            state.session.clone()
        };

        wipe(&path);

        let state = open(&path, &key).expect("an emptied database is a database with no history");
        assert_eq!(state.last_id(), 0, "the wipe left nothing published");
        assert_ne!(
            state.session, published,
            "nothing was ever signed under the name left in the file, so continuing under it \
             would put two different histories under one name"
        );
    }

    /// The new name is how a consumer sees the wipe, so the new name has to
    /// reach the file. A second restart must not go back to the old name.
    #[test]
    fn a_wiped_history_keeps_the_name_it_publishes_its_first_message_under() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let published = {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
            state.session.clone()
        };

        wipe(&path);

        let after = {
            let mut state = open(&path, &key).expect("an empty database starts");
            state.publish(order(1, 100.26)).expect("published");
            state.session.clone()
        };
        assert_ne!(after, published);

        let state = open(&path, &key).expect("the new history restarts");
        assert_eq!(
            state.session, after,
            "the name the new history was signed under is the one on disk"
        );
        assert_eq!(state.last_id(), 1);
    }

    /// The replay half. The set of used nonces is rebuilt from the rows, so a
    /// wipe empties it, while `feed_accounts` survives in its own table. A
    /// submission that got a 409 before the wipe is accepted after it.
    ///
    /// That is safe only because the messages it produces belong to a different
    /// history. This test pins both halves of that. The nonce set belongs to
    /// the new history, and no receipt from the old history verifies against
    /// the new head.
    #[test]
    fn a_wiped_history_does_not_inherit_the_old_nonces_or_its_receipts() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let spent = nonce(0x5a);
        let (old_session, old_head) = {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish(order_with_nonce(1, 100.25, &spent))
                .expect("published");
            (state.session.clone(), state.signed_head())
        };

        wipe(&path);
        let mut state = open(&path, &key).expect("an empty database starts");
        assert!(
            state.nonces.is_empty(),
            "the nonces come out of the rows, and there are none"
        );

        state
            .publish(order_with_nonce(1, 100.25, &spent))
            .expect("the nonce is free in a history that has never seen it");
        let head = state.signed_head();
        assert_eq!(state.nonces.len(), 1);
        assert_ne!(
            head.session, old_session,
            "so the message it authorises is published under a name the old history never used"
        );

        // A receipt from the old history cannot be relabelled as part of the
        // new one. The signature covers the session, so the old head does not
        // verify under the new name.
        let old_chain = logchain::from_hex::<32>(&old_head.chain).unwrap();
        let old_signature =
            Signature::from_bytes(&logchain::from_hex::<64>(&old_head.signature).unwrap());
        assert!(
            logchain::verify_head(
                &key.verifying_key(),
                &old_session,
                old_head.last_id,
                &old_chain,
                &old_signature
            ),
            "the old receipt was a real one"
        );
        assert!(
            !logchain::verify_head(
                &key.verifying_key(),
                &head.session,
                old_head.last_id,
                &old_chain,
                &old_signature
            ),
            "and it is not a receipt for anything in the new history"
        );

        // The other direction too. A consumer that holds the old session
        // cannot verify the new head under it, so the change is visible from
        // both sides.
        let new_chain = logchain::from_hex::<32>(&head.chain).unwrap();
        let new_signature =
            Signature::from_bytes(&logchain::from_hex::<64>(&head.signature).unwrap());
        assert!(!logchain::verify_head(
            &key.verifying_key(),
            &old_session,
            head.last_id,
            &new_chain,
            &new_signature
        ));
    }

    /// A database that nothing was ever published into still starts, and still
    /// gets a name. The name it publishes its first message under is the name
    /// it keeps.
    #[test]
    fn a_fresh_database_gets_a_session_and_keeps_it() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database starts");
        assert_eq!(state.last_id(), 0);
        assert_eq!(state.session.len(), 16, "and it names its history");

        let minted = state.session.clone();
        state.publish(order(1, 100.25)).expect("published");
        drop(state);

        let state = open(&path, &key).expect("the same database");
        assert_eq!(
            state.session, minted,
            "the name the first publish signed under is the one a restart continues"
        );
    }

    /// The attack, as the one `sqlite3` command that performs it. Every message
    /// and the checkpoint are gone. The session row, `feed_accounts` and
    /// `feed.key` stay exactly where the sequencer put them.
    fn wipe(path: &Path) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "DELETE FROM feed_messages;
             DELETE FROM feed_meta WHERE key = 'checkpoint';",
        )
        .unwrap();
    }

    /// A chain link rewritten on its own still leaves the messages hashing to
    /// the signed head. Only the check of each message against its stored link
    /// catches this.
    #[test]
    fn a_rewritten_chain_link_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26)])
                .expect("published");
        }

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE feed_messages SET chain = ?1 WHERE id = 1",
            params![[7u8; 32].as_slice()],
        )
        .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "a stored chain link was rewritten");
        assert!(
            refused.contains("chain link stored with message 1"),
            "unexpected error: {}",
            refused
        );
    }

    /// A history signed by another key is not this sequencer's to continue.
    #[test]
    fn a_history_signed_by_another_key_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
        }

        let refused = refusal(
            open(&path, &logchain::ephemeral_key()),
            "another key cannot continue this history",
        );
        assert!(
            refused.contains("is not signed by this feed's key"),
            "unexpected error: {}",
            refused
        );
    }

    /// Finding 5. The submission handler accepts exactly what the matching
    /// engine can run.
    #[tokio::test]
    async fn off_grid_submissions_are_refused_at_intake() {
        let state = Arc::new(Mutex::new(on_test_session(FeedState::new(4, WALL))));
        let key = logchain::ephemeral_key();

        let off_grid = refused(
            submit_order(
                State(Arc::clone(&state)),
                peer(),
                Ok(Json(order_request(&key, 1, 100.253, 5.0))),
            )
            .await,
            "the matcher would drop this order without a trace",
        );
        assert_eq!(off_grid.0, StatusCode::BAD_REQUEST);

        let huge = refused(
            submit_order(
                State(Arc::clone(&state)),
                peer(),
                Ok(Json(order_request(&key, 1, 1e307, 5.0))),
            )
            .await,
            "no price this size can be represented",
        );
        assert_eq!(huge.0, StatusCode::BAD_REQUEST);

        let zero_target = refused(
            submit_cancel(
                State(Arc::clone(&state)),
                peer(),
                Ok(Json(cancel_request(&key, 1, 0))),
            )
            .await,
            "feed ids start at 1",
        );
        assert_eq!(zero_target.0, StatusCode::BAD_REQUEST);

        // None of the three published anything.
        assert!(lock(&state).messages.is_empty());

        // Correct submissions still work.
        let accepted = submit_order(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(order_request(&key, 1, 100.25, 5.0))),
        )
        .await
        .expect("an on-grid order");
        assert_eq!(accepted.0.id, 1);
        assert_eq!(accepted.0.receipt.last_id, 1);
        let cancel = submit_cancel(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(cancel_request(&key, 1, 1))),
        )
        .await
        .expect("a cancel naming a real id");
        assert_eq!(cancel.0.id, 2);
        assert_eq!(lock(&state).messages.len(), 2);
    }

    /// The defect this closes. Before submissions were signed, `account` was a
    /// number the caller wrote. The exchange's cancel check asks whether the
    /// order belongs to account 1. It compared one number the sender chose
    /// against another number the same sender had chosen earlier. A stranger
    /// cancelled anyone's resting order by writing their account number.
    #[tokio::test]
    async fn a_stranger_cannot_cancel_an_account_s_order() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let state = Arc::new(Mutex::new(on_test_session(
            open(&path, &key).expect("a new database"),
        )));
        let owner = logchain::ephemeral_key();
        let stranger = logchain::ephemeral_key();

        // Account 1 places an order, which pins account 1 to the owner's key.
        let placed = submit_order(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(order_request(&owner, 1, 100.25, 5.0))),
        )
        .await
        .expect("the owner's own order");
        assert_eq!(placed.0.id, 1);

        // The stranger tries to cancel the order as account 1. The signature
        // is valid. It is not the key account 1 is pinned to.
        let impersonation = refused(
            submit_cancel(
                State(Arc::clone(&state)),
                peer(),
                Ok(Json(cancel_request(&stranger, 1, 1))),
            )
            .await,
            "account 1 is not this key's to speak for",
        );
        assert_eq!(impersonation.0, StatusCode::FORBIDDEN);
        assert!(
            impersonation.1.contains("is pinned to public key"),
            "the refusal has to name the key on file: {}",
            impersonation.1
        );

        // A signature that does not cover what was sent. The caller signed one
        // price and sent another.
        let mut rewritten = order_request(&owner, 1, 100.25, 5.0);
        rewritten.price = 100.26;
        let rewritten = refused(
            submit_order(State(Arc::clone(&state)), peer(), Ok(Json(rewritten))).await,
            "the signature covers 100.25, not 100.26",
        );
        assert_eq!(rewritten.0, StatusCode::UNAUTHORIZED);

        // The owner's own cancel still works, and nothing else was published.
        let _ = submit_cancel(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(cancel_request(&owner, 1, 1))),
        )
        .await
        .expect("the owner may cancel the owner's order");
        let published = lock(&state).messages.clone();
        assert_eq!(published.len(), 2, "only the owner's two messages");
        assert!(matches!(
            parsed(&published[1]),
            OrderMessage::Cancel {
                account: 1,
                target_id: 1,
                ..
            }
        ));
    }

    /// A pin is worth something only if it survives a restart. A sequencer that
    /// forgot which key an account had would let the next submission for that
    /// account come from anyone.
    #[test]
    fn an_account_keeps_its_key_across_a_restart() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let owner = logchain::ephemeral_key();
        let stranger = logchain::ephemeral_key();
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .pin_or_check_account(1, &owner.verifying_key())
                .expect("account 1 is unclaimed");
        }

        let mut state = open(&path, &key).expect("the database reopens");
        state
            .pin_or_check_account(1, &owner.verifying_key())
            .expect("the same key is still account 1's");
        let refused = state
            .pin_or_check_account(1, &stranger.verifying_key())
            .expect_err("a restart must not release the account");
        assert_eq!(refused.0, StatusCode::FORBIDDEN);
    }

    /// The sequencer checks the account signature again on what it drains, and
    /// it has to. `--inbox-url` is a flag that can point anywhere, and the
    /// sequencer is the party that signs the history it puts in order.
    #[test]
    fn the_drain_path_refuses_a_submission_the_account_did_not_sign() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = on_test_session(open(&path, &key).expect("a new database"));
        let owner = logchain::ephemeral_key();
        let stranger = logchain::ephemeral_key();

        let order_for = |account: AccountId| order_submission(account, 100.25, &inbox::new_nonce());

        // Entry 1 pins account 1 to the owner's key.
        let (marks, refused) = sequence_drained(
            &mut state,
            "epoch1",
            vec![inbox_entry(&owner, 1, order_for(1))],
        );
        assert!(refused.is_empty());
        assert_eq!(marks.len(), 1);

        // Entry 2 is signed by a stranger for account 1. The sequencer refuses
        // it. The entry stays pending in the separate service and is reported
        // overdue there. It does not go into the log under an account that did
        // not ask for it.
        let (marks, refused) = sequence_drained(
            &mut state,
            "epoch1",
            vec![inbox_entry(&stranger, 2, order_for(1))],
        );
        assert!(marks.is_empty(), "nothing to mark: nothing was sequenced");
        assert_eq!(refused.len(), 1);
        assert!(
            refused[0].1.contains("is pinned to public key"),
            "the reason has to survive to the log: {}",
            refused[0].1
        );

        // Entry 3 carries a signature that covers different terms.
        let mut forged = inbox_entry(&owner, 3, order_for(1));
        forged.submission = order_for(2);
        let (marks, refused) = sequence_drained(&mut state, "epoch1", vec![forged]);
        assert!(marks.is_empty());
        assert_eq!(refused.len(), 1);
        assert!(
            refused[0].1.contains("does not verify"),
            "unexpected reason: {}",
            refused[0].1
        );

        assert_eq!(
            state.messages.len(),
            1,
            "only the entry that proved itself reached the history"
        );
    }

    /// A restart reads its own orders back out of the database, so the
    /// generator can still cancel them.
    ///
    /// Without this the generator forgets every order it placed, on every
    /// restart. A forgotten order stays in the book until something trades with
    /// it. That is the defect `feed/generate.rs` exists to remove, and a
    /// restart is the one route that could bring it back.
    ///
    /// The lives start again, because a life is a count of milliseconds on this
    /// clock and the log holds none. What must survive is which orders are
    /// open.
    #[test]
    fn a_restart_reads_back_the_orders_the_generator_can_still_cancel() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let open_before: Vec<(OrderId, i64)> = {
            let mut state = open(&path, &key).expect("a new database");
            let mut timestamp = state.clock.now_ms();
            for _ in 0..2_000 {
                let message = generate::generate_message_at(&mut state, timestamp);
                timestamp += 167;
                state.publish(message).expect("published");
            }
            assert!(
                state.open_orders.len() > 10,
                "2,000 messages leave orders open: {}",
                state.open_orders.len()
            );
            let mut open: Vec<(OrderId, i64)> = state
                .open_orders
                .iter()
                .map(|order| (order.id, order.price_cents))
                .collect();
            open.sort();
            open
        };

        let state = open(&path, &key).expect("the database starts again");
        let mut open_after: Vec<(OrderId, i64)> = state
            .open_orders
            .iter()
            .map(|order| (order.id, order.price_cents))
            .collect();
        open_after.sort();
        assert_eq!(
            open_after, open_before,
            "the restart holds a different set of open orders than the run that wrote the log"
        );
        let now = state.clock.now_ms();
        for order in &state.open_orders {
            assert!(
                order.expires_at_ms > now,
                "order {} came back already past the end of its life",
                order.id
            );
        }
    }

    /// Finding 6. A database can already hold an impossible price, written
    /// before the submission handler checked prices. The sequencer must not
    /// load that price back into the generator. The next drift step from it
    /// reaches infinity, serde writes `null`, and nothing can read `null` back,
    /// including this sequencer.
    #[test]
    fn a_poisoned_mid_is_not_reloaded() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            // Straight to `sequence`. Before the drain code was checked, that
            // is where such a message could have come from.
            state.publish(order(1, 1e307)).expect("published");
        }

        let mut state = open(&path, &key).expect("the database still starts");
        assert_eq!(
            state.mids.get("ETH-USDC"),
            Some(&100.0),
            "the symbol restarts from its initial mid, not from the poisoned price"
        );
        for _ in 0..200 {
            let msg = generate_message(&mut state);
            if let OrderMessage::New { price, .. } = &msg {
                assert!(price.is_finite(), "a generated price is always a number");
                assert!(
                    to_grid(*price, PRICE_SCALE).is_some(),
                    "and always one the engine can take: {}",
                    price
                );
            }
            // Every generated message survives the round trip serde does.
            let json = serde_json::to_string(&msg).unwrap();
            serde_json::from_str::<OrderMessage>(&json).expect("a message reads back");
        }
    }

    /// Finding 8, and the reason finding 15 had to be fixed and not written
    /// down as known. A page has a size limit, and the head on the page stands
    /// exactly at the last message in it. A consumer that hashes the chain
    /// across pages then checks every page against a signature.
    #[tokio::test]
    async fn orders_are_paged_and_the_head_covers_exactly_what_is_served() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        let total = PAGE_LIMIT + 50;
        {
            let mut guard = lock(&state);
            // `round2`, because this test hashes the chain over the messages
            // as they came back off the wire, not over the ones still in
            // memory. `100.0 + 804.0 / 100.0` is not the nearest f64 to
            // 108.04, so serde writes it as `108.03999999999999`. serde_json's
            // parser reads a 17-digit decimal back to within one ULP, one
            // step between two neighbouring f64 values, and not exactly,
            // because the `float_roundtrip` feature is off and nothing here
            // turns it on. Serializing that value again gives `108.04` and a
            // different SHA-256. Every message this sequencer really publishes
            // is a whole number of cents: `generate_message` rounds, and
            // `validate_submission` refuses anything else. Those values do
            // survive the round trip exactly, so `round2` keeps the test on
            // the values the sequencer can produce.
            let batch: Vec<OrderMessage> = (1..=total as u64)
                .map(|id| order(id, round2(100.0 + id as f64 / 100.0)))
                .collect();
            guard.publish_batch(batch).expect("published");
        }

        let (head, body) = orders(&state, Some(0), None).await.expect("a page");
        assert_eq!(body.len(), PAGE_LIMIT, "the response is bounded");

        assert_eq!(
            head[HEAD_LAST_ID_HEADER],
            body.last().unwrap().id().to_string(),
            "the head stands at the last message served"
        );
        assert_eq!(
            head[HEAD_CHAIN_HEADER],
            logchain::to_hex(&chain_of(&body)),
            "and its chain is the one those messages produce"
        );
        let key = logchain::from_hex::<32>(&head[HEAD_PUBKEY_HEADER]).unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
        let signature =
            Signature::from_bytes(&logchain::from_hex::<64>(&head[HEAD_SIGNATURE_HEADER]).unwrap());
        assert!(logchain::verify_head(
            &key,
            &head[SESSION_HEADER],
            head[HEAD_LAST_ID_HEADER].parse().unwrap(),
            &logchain::from_hex::<32>(&head[HEAD_CHAIN_HEADER]).unwrap(),
            &signature
        ));

        // The next page continues, and the last one carries the full head.
        let (head, rest) = orders(&state, Some(PAGE_LIMIT as OrderId), None)
            .await
            .expect("the rest");
        assert_eq!(rest.len(), 50);
        assert_eq!(rest[0].id(), PAGE_LIMIT as OrderId + 1);
        assert_eq!(head[HEAD_LAST_ID_HEADER], total.to_string());

        // `?n=` is capped too.
        let (_, capped) = orders(&state, None, Some(usize::MAX))
            .await
            .expect("a capped tail");
        assert_eq!(capped.len(), PAGE_LIMIT);
    }

    /// The round trip `/messages.ndjson` exists for. A caller hashes the lines
    /// exactly as they arrived and reaches the chain in the head beside them.
    /// The caller parses no message and serializes no message.
    ///
    /// The 100.0 check is the defect this endpoint prevents. Serde writes that
    /// price as `100.0`, and those are the bytes in the chain. A browser that
    /// parsed the JSON and serialized it again would write `100`. It would hash
    /// different bytes, and report this sequencer as having rewritten its
    /// history.
    #[tokio::test]
    async fn ndjson_lines_are_the_bytes_the_chain_was_folded_over() {
        use sha2::{Digest, Sha256};

        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        {
            let mut guard = lock(&state);
            // A whole-number price, a price with cents, and a message with a
            // submitter's nonce. Those are the three forms a line can have.
            guard.publish(order(1, 100.0)).expect("published");
            guard.publish(order(2, 100.25)).expect("published");
            guard
                .publish(order_with_nonce(3, 100.0, &nonce(7)))
                .expect("published");
        }

        let response = feed_router(Arc::clone(&state), default_origins(), None)
            .oneshot(local_request("/messages.ndjson?since=0"))
            .await
            .expect("the router answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/x-ndjson"
        );
        let head: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap().to_string(),
                )
            })
            .collect();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");

        // The body is exactly three lines, each ending in one 0x0A, so the
        // split leaves one trailing empty piece and nothing else.
        let mut lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').collect();
        assert_eq!(lines.pop(), Some(&b""[..]), "the body ends in a newline");
        assert_eq!(lines.len(), 3);
        assert!(
            String::from_utf8_lossy(lines[0]).contains("\"price\":100.0"),
            "a whole-number price stays 100.0, not 100: {}",
            String::from_utf8_lossy(lines[0])
        );
        assert!(
            !String::from_utf8_lossy(lines[0]).contains("\"price\":100,"),
            "and never the shape JSON.stringify would write"
        );
        assert!(
            String::from_utf8_lossy(lines[2]).contains(&nonce(7)),
            "a submitter's nonce is on the line that was hashed"
        );

        // What a browser does: hash the raw lines, then compare with the head.
        let chain = lines.iter().fold(EMPTY_CHAIN, |chain, line| {
            let mut hasher = Sha256::new();
            hasher.update(chain);
            hasher.update(line);
            hasher.finalize().into()
        });
        assert_eq!(
            head[HEAD_CHAIN_HEADER],
            logchain::to_hex(&chain),
            "the head's chain is the fold over the lines as served"
        );
        assert_eq!(head[HEAD_LAST_ID_HEADER], "3");
        assert_eq!(head[SESSION_HEADER], lock(&state).session.clone());
        let key = logchain::from_hex::<32>(&head[HEAD_PUBKEY_HEADER]).unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
        let signature =
            Signature::from_bytes(&logchain::from_hex::<64>(&head[HEAD_SIGNATURE_HEADER]).unwrap());
        assert!(
            logchain::verify_head(
                &key,
                &head[SESSION_HEADER],
                head[HEAD_LAST_ID_HEADER].parse().unwrap(),
                &chain,
                &signature
            ),
            "and the feed signed that chain"
        );

        // `?since=` and `?limit=` cut the pages exactly as `page()` does.
        let response = feed_router(Arc::clone(&state), default_origins(), None)
            .oneshot(local_request("/messages.ndjson?since=1&limit=1"))
            .await
            .expect("the router answers");
        let last_id = response
            .headers()
            .get(HEAD_LAST_ID_HEADER)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let page = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        assert_eq!(
            page.as_ref(),
            [logchain::canonical_bytes(&order(2, 100.25)), vec![b'\n']].concat(),
            "one message, verbatim"
        );
        assert_eq!(last_id, "2", "and the head stands at it");
    }

    /// An empty page still carries the head of the whole history. That is how
    /// a consumer that is up to date confirms it is up to date.
    #[tokio::test]
    async fn an_empty_page_carries_the_full_head() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        lock(&state).publish(order(1, 100.25)).expect("published");

        let (head, body) = orders(&state, Some(1), None).await.expect("an empty page");
        assert!(body.is_empty());
        assert_eq!(head[HEAD_LAST_ID_HEADER], "1");
        // That head is the current one, which is why this response must never
        // be cached. See `Freshness`.
        assert_eq!(head[header::CACHE_CONTROL.as_str()], OPEN_CACHE_CONTROL);
    }

    /// Finding 7. The drain code used to copy whatever the separate service
    /// served straight into a signed message: no symbol check, no price step
    /// check, nothing. `--inbox-url` is a flag that can point anywhere, so the
    /// drain was the last way to get a price into the history that no f64 can
    /// hold. That price is where finding 6's infinity started.
    #[test]
    fn the_drain_path_refuses_what_the_front_door_refuses() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = on_test_session(open(&path, &key).expect("a new database"));

        let account_key = logchain::ephemeral_key();
        let entry =
            |inbox_id: i64, submission: Submission| inbox_entry(&account_key, inbox_id, submission);
        let due = vec![
            entry(1, order_submission(1, 1e307, &inbox::new_nonce())),
            entry(2, order_submission(1, 100.253, &inbox::new_nonce())),
            // Lower case, which the symbol name rule refuses. A symbol that is
            // not listed is not refused here. Whether a symbol is listed is a
            // fact about the log, and the drain code checks only what the
            // submission handler checks.
            entry(
                3,
                Submission::Order {
                    account: 1,
                    symbol: "not-a-symbol".to_string(),
                    side: Side::Buy,
                    price: 100.25,
                    quantity: 5.0,
                    nonce: Some(inbox::new_nonce()),
                    session: Some(TEST_SESSION.to_string()),
                    order_type: OrderType::Limit,
                    time_in_force: TimeInForce::GoodTillCancel,
                    post_only: false,
                },
            ),
            entry(
                4,
                Submission::Cancel {
                    account: 1,
                    target_id: 0,
                    nonce: Some(inbox::new_nonce()),
                    session: Some(TEST_SESSION.to_string()),
                },
            ),
            // A nonce in the wrong spelling. This system accepts one spelling
            // only. The same 128 bits in upper case would otherwise be a
            // second key in the sequencer's map, and the same submission twice.
            entry(5, order_submission(1, 100.25, &nonce(0xAB).to_uppercase())),
            entry(6, order_submission(1, 100.25, &inbox::new_nonce())),
        ];

        let (marks, refused) = sequence_drained(&mut state, "epoch1", due);
        assert_eq!(
            refused.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5],
            "everything the engine could not execute is refused"
        );
        assert!(
            refused[4].1.contains("32 lowercase hex"),
            "the nonce refusal says what is wrong with it: {}",
            refused[4].1
        );
        assert_eq!(marks.len(), 1, "only the good entry is marked");
        assert_eq!(marks[0].0, 6);
        assert_eq!(state.messages.len(), 1, "and only it reaches the history");
        assert_eq!(state.messages[0].id, 1, "using the first free id");

        // No price that an f64 cannot hold reached the signed history, so a
        // restart still works. That is the point of the check.
        drop(state);
        let state = on_test_session(open(&path, &key).expect("the history still starts"));
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.mids["ETH-USDC"], 100.25);
    }

    /// Finding 14. A separate service that lost its database starts its entry
    /// ids again at 1. When the key was the id alone, the new entry 1 hit the
    /// record of the old entry 1 and could never go into the log.
    #[test]
    fn a_new_inbox_epoch_does_not_collide_with_the_old_one() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database");

        state
            .sequence(vec![(Some(("epoch1".to_string(), 1)), order(1, 100.25))])
            .expect("sequenced");
        state
            .sequence(vec![(Some(("epoch2".to_string(), 1)), order(2, 100.26))])
            .expect("the same entry id in a new inbox database");

        assert_eq!(state.inbox_sequenced[&("epoch1".to_string(), 1)], 1);
        assert_eq!(state.inbox_sequenced[&("epoch2".to_string(), 1)], 2);

        // Both pairings survive a restart.
        drop(state);
        let state = open(&path, &key).expect("reopened");
        assert_eq!(state.inbox_sequenced.len(), 2);
        assert_eq!(state.inbox_sequenced[&("epoch2".to_string(), 1)], 2);
    }

    /// Finding 4. A write over a published message is a constraint error. The
    /// old row stays as it was.
    #[test]
    fn an_id_that_is_already_published_cannot_be_written_again() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database");
        state.publish(order(1, 100.25)).expect("published");

        // Force the id backwards, the way a restored or shared database
        // would.
        state.next_id = 1;
        let refused = state.publish(order(1, 999.99));
        assert!(refused.is_err(), "id 1 is already published");
        assert_eq!(state.messages.len(), 1);
        match parsed(&state.messages[0]) {
            OrderMessage::New { price, .. } => assert_eq!(price, 100.25),
            other => panic!("unexpected message {:?}", other),
        }
    }

    /// The defect this closes. A captured submission stays valid bytes forever.
    /// Anyone who saw one could send it again and get a second order under that
    /// account.
    #[tokio::test]
    async fn a_replay_at_the_front_door_is_refused_and_names_the_message_it_already_made() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let state = Arc::new(Mutex::new(on_test_session(
            open(&path, &key).expect("a new database"),
        )));
        let owner = logchain::ephemeral_key();

        let request = order_request(&owner, 1000, 100.25, 5.0);
        let accepted = submit_order(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(order_request_with_nonce(
                &owner,
                1000,
                100.25,
                5.0,
                &request.nonce,
            ))),
        )
        .await
        .expect("the first submission");
        assert_eq!(accepted.0.id, 1);

        // The same bytes again. The answer is not a new 200, and not a second
        // copy of the old receipt. The answer says which message these bytes
        // already became. Without that, a client cannot tell a duplicate from
        // a lost order.
        let replay = refused(
            submit_order(State(Arc::clone(&state)), peer(), Ok(Json(request))).await,
            "these exact bytes already produced message 1",
        );
        assert_eq!(replay.0, StatusCode::CONFLICT);
        assert!(
            replay.1.contains("feed message 1"),
            "the refusal has to name the message: {}",
            replay.1
        );
        assert_eq!(lock(&state).messages.len(), 1, "no duplicate order");

        // A cancel replays the same way. A different nonce for the same terms
        // is a new submission, and that is what lets the bot send a cancel
        // again until it takes effect.
        let cancel = cancel_request(&owner, 1000, 1);
        let first = submit_cancel(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(cancel_request_with_nonce(
                &owner,
                1000,
                1,
                &cancel.nonce,
            ))),
        )
        .await
        .expect("the first cancel");
        assert_eq!(first.0.id, 2);
        let replayed_cancel = refused(
            submit_cancel(State(Arc::clone(&state)), peer(), Ok(Json(cancel))).await,
            "the same signed cancel cannot be sequenced twice",
        );
        assert_eq!(replayed_cancel.0, StatusCode::CONFLICT);
        let resent = submit_cancel(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(cancel_request(&owner, 1000, 1))),
        )
        .await
        .expect("a fresh nonce for the same target is a new cancel");
        assert_eq!(resent.0.id, 3);
        assert_eq!(lock(&state).messages.len(), 3);

        // The refusal survives a restart, because the nonces come back from
        // the messages themselves.
        let published = lock(&state).messages.clone();
        let request = order_request_with_nonce(
            &owner,
            1000,
            100.25,
            5.0,
            parsed(&published[0])
                .nonce()
                .expect("message 1 carries its nonce"),
        );
        drop(state);
        let state = Arc::new(Mutex::new(open(&path, &key).expect("reopened")));
        let after_restart = refused(
            submit_order(State(Arc::clone(&state)), peer(), Ok(Json(request))).await,
            "a restart must not free a nonce",
        );
        assert_eq!(after_restart.0, StatusCode::CONFLICT);
        assert_eq!(lock(&state).messages.len(), 3);
    }

    /// The case a plain "have I seen this signature" check gets wrong. It is
    /// the reason this design resolves a duplicate instead of refusing it.
    ///
    /// `GET /pending` serves the submitter's signature. Anyone who watches the
    /// separate service can copy a submission from it and post it to the
    /// sequencer directly. The sequencer publishes it once. The entry in the
    /// separate service is then a request that was already granted. Refusing
    /// that entry would leave it pending until it went overdue, and the service
    /// would report censorship over an order that is live in the market.
    #[test]
    fn an_entry_whose_submission_was_already_published_resolves_instead_of_alarming() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = on_test_session(open(&path, &key).expect("a new database"));
        let owner = logchain::ephemeral_key();

        // The user submits through the separate service. The entry is waiting.
        let request = order_request(&owner, 1000, 100.25, 5.0);
        let entry = entry_from_order(&request, 1);

        // An observer copies the signature from `/pending` and posts it to the
        // sequencer directly. Same bytes, so it is a valid submission and the
        // sequencer publishes it.
        let published = {
            let signed = SignedSubmission {
                submission: entry.submission.clone(),
                public_key: entry.public_key.clone(),
                signature: entry.signature.clone(),
            };
            let key = inbox::verify_account_signature(&signed).expect("valid");
            state.pin_or_check_account(1000, &key).expect("unclaimed");
            let id = state.next_id;
            state.next_id += 1;
            // The one conversion `POST /order` uses. The test calls it instead
            // of copying what the submission handler does.
            let msg = inbox::message_from(id, WALL, &signed.submission);
            state.publish(msg).expect("published");
            id
        };
        assert_eq!(published, 1);

        // Now the sequencer drains the separate service and meets the original
        // entry.
        let (marks, refused) = sequence_drained(&mut state, "epoch1", vec![entry.clone()]);
        assert!(
            refused.is_empty(),
            "the entry is not refused: its order exists, {:?}",
            refused
        );
        assert_eq!(marks.len(), 1, "it is marked, so it stops being pending");
        assert_eq!(marks[0].0, 1, "entry 1");
        assert_eq!(
            marks[0].2.feed_id, published,
            "against the message its submission already became"
        );
        assert_eq!(
            state.messages.len(),
            1,
            "one order, not two: the entry was resolved, not sequenced again"
        );

        // The mark the separate service will receive really does describe this
        // entry, so the entry closes and is not refused as a content mismatch.
        // The mark carries the message's stored bytes, which is where the
        // service reads the terms from.
        let marked: OrderMessage =
            serde_json::from_str(&marks[0].2.message).expect("the stored bytes of the message");
        assert!(
            inbox::message_matches(&entry.submission, &marked),
            "the resolved message has to match what the entry submitted"
        );
    }

    /// The bytes of a message, with the two fields the sequencer picks removed.
    ///
    /// A message is an object with one key. The key names the kind, and its
    /// body holds the fields. See `wire.rs`. The id and the timestamp are
    /// removed from that body by name. Every other field stays, whatever it is
    /// called and whenever it was added. That is the point: the caller compares
    /// whole messages and never holds a list of the fields to compare.
    fn terms_of(message: &OrderMessage) -> String {
        let mut value = serde_json::to_value(message).expect("a message serialises");
        let body = value
            .as_object_mut()
            .and_then(|kinds| kinds.values_mut().next())
            .and_then(|body| body.as_object_mut())
            .expect("a message is a kind with a body");
        body.remove("id");
        body.remove("timestamp");
        serde_json::to_string(&value).expect("a message serialises")
    }

    /// One signed submission, sent by both routes, becomes one message.
    ///
    /// Before this change, `POST /order` on the sequencer and the drain of the
    /// separate service each built the message themselves, field by field. They
    /// agreed only because both filled every order term with the default. The
    /// first term a submitter is allowed to pick would have turned the same
    /// signed bytes into a market order by one route and a limit order by the
    /// other, and `message_matches` would have accepted both.
    ///
    /// The test compares bytes and not fields on purpose. A field-by-field
    /// compare needs an edit for every field added, and the field whose edit is
    /// forgotten is the field that then differs between the routes. Only the id
    /// and the timestamp are removed. The sequencer picks both, no submission
    /// names either, and the two routes here run on two new sequencers.
    #[tokio::test]
    async fn one_submission_becomes_the_same_message_at_both_doors() {
        for (order_type, time_in_force, post_only) in TERM_SHAPES {
            one_submission_at_both_doors(order_type, time_in_force, post_only).await;
        }
    }

    /// The six kinds of order the Trade panel offers, as the three fields each
    /// one sets. The two shapes the exchange always refuses are not here,
    /// because no page and no flag can ask for them. Those two shapes are
    /// post-only on a market order, and post-only on an order that may not
    /// rest.
    const TERM_SHAPES: [(OrderType, TimeInForce, bool); 6] = [
        (OrderType::Limit, TimeInForce::GoodTillCancel, false),
        (OrderType::Limit, TimeInForce::GoodTillCancel, true),
        (OrderType::Limit, TimeInForce::ImmediateOrCancel, false),
        (OrderType::Limit, TimeInForce::FillOrKill, false),
        (OrderType::Market, TimeInForce::GoodTillCancel, false),
        (OrderType::Market, TimeInForce::FillOrKill, false),
    ];

    /// One signed submission through both routes, with the terms named.
    ///
    /// The message each route stored is read back and its terms are compared
    /// with the terms that were signed. A route that published the default
    /// terms for an order signed as a market order would pass a comparison of
    /// the two routes against each other, because both would be wrong the same
    /// way. So the signed terms are the third thing in the comparison.
    async fn one_submission_at_both_doors(
        order_type: OrderType,
        time_in_force: TimeInForce,
        post_only: bool,
    ) {
        let dir = TempDir::new().unwrap();
        let owner = logchain::ephemeral_key();
        let request = order_request_with_terms(
            &owner,
            1000,
            100.25,
            5.0,
            &inbox::new_nonce(),
            order_type,
            time_in_force,
            post_only,
        );
        let entry = entry_from_order(&request, 1);

        // The first route: POST /order on the sequencer.
        let front_key = logchain::ephemeral_key();
        let front = Arc::new(Mutex::new(on_test_session(
            open(&dir.path().join("front.db"), &front_key).expect("a new database"),
        )));
        let receipt = submit_order(State(Arc::clone(&front)), peer(), Ok(Json(request)))
            .await
            .expect("the front door takes it");
        assert_eq!(receipt.id, 1, "the first message of a new log");
        let at_front = lock(&front).messages[0].json.clone();

        // The second route: the same signed submission, drained from the
        // separate service.
        let drain_key = logchain::ephemeral_key();
        let mut drained = on_test_session(
            open(&dir.path().join("drain.db"), &drain_key).expect("a new database"),
        );
        let (marks, refused) = sequence_drained(&mut drained, "epoch1", vec![entry]);
        assert!(
            refused.is_empty(),
            "the entry is not refused: {:?}",
            refused
        );
        assert_eq!(marks.len(), 1, "it is sequenced");
        let at_drain = drained.messages[0].json.clone();

        let front_message: OrderMessage =
            serde_json::from_str(&at_front).expect("the stored bytes of the message");
        let drain_message: OrderMessage =
            serde_json::from_str(&at_drain).expect("the stored bytes of the message");
        assert_eq!(
            terms_of(&front_message),
            terms_of(&drain_message),
            "one signed submission, two doors, one message"
        );

        // And the message both routes built is the order that was signed.
        for (route, message) in [
            ("the front door", &front_message),
            ("the drain", &drain_message),
        ] {
            match message {
                OrderMessage::New {
                    order_type: published_type,
                    time_in_force: published_life,
                    post_only: published_post_only,
                    ..
                } => assert_eq!(
                    (*published_type, *published_life, *published_post_only),
                    (order_type, time_in_force, post_only),
                    "{} published terms the account did not sign",
                    route
                ),
                other => panic!("{} published {:?}, which is not an order", route, other),
            }
        }
    }

    /// A submission signed for a log that is not this one is refused, on both
    /// routes, and nothing is published.
    ///
    /// The session is the second line of the statement, so this signature is
    /// good: it covers a different log. That is what makes the refusal worth
    /// having: without it the same signed bytes would still become a message
    /// after the sequencer's database was emptied and started again under a new
    /// session, which is a replay across the reset.
    ///
    /// The separate service does not make this check, and `inbox::checked_session`
    /// says why: it would have to ask this sequencer which log is current, and
    /// that is the party it exists to distrust. So both places that do check are
    /// here, and this test drives both.
    #[tokio::test]
    async fn a_submission_signed_for_another_log_is_refused_on_both_routes() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let owner = logchain::ephemeral_key();
        let request = order_request(&owner, 1000, 100.25, 5.0);
        let entry = entry_from_order(&request, 1);

        // A sequencer on some other session. `open` mints a fresh random one,
        // and `on_test_session` is deliberately not called.
        let state = Arc::new(Mutex::new(open(&path, &key).expect("a new database")));
        let elsewhere = lock(&state).session.clone();
        assert_ne!(
            elsewhere, TEST_SESSION,
            "this test needs a sequencer on another session"
        );

        let (status, why) = refused(
            submit_order(State(Arc::clone(&state)), peer(), Ok(Json(request))).await,
            "it is signed for another log",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            why.contains(TEST_SESSION) && why.contains(&elsewhere),
            "the refusal has to name both sessions, or the caller cannot act on it: {}",
            why
        );
        assert_eq!(
            lock(&state).last_id(),
            0,
            "nothing was published, and no id was spent"
        );

        // The same signed submission, arriving through the separate service.
        let mut drained = open(&path, &key).expect("the same database");
        drained.session = elsewhere.clone();
        let (marks, refused_at_intake) = sequence_drained(&mut drained, "epoch1", vec![entry]);
        assert!(marks.is_empty(), "nothing was sequenced");
        assert_eq!(refused_at_intake.len(), 1, "the entry was refused by name");
        assert!(
            refused_at_intake[0].1.contains(TEST_SESSION),
            "the drain gives the same reason: {}",
            refused_at_intake[0].1
        );

        // And the same submission on a sequencer that is on its session is
        // taken. Only the session separates the two.
        let on_session = Arc::new(Mutex::new(on_test_session(
            open(&dir.path().join("same.db"), &key).expect("a new database"),
        )));
        let accepted = order_request(&owner, 1000, 100.25, 5.0);
        let _ = submit_order(State(Arc::clone(&on_session)), peer(), Ok(Json(accepted)))
            .await
            .expect("the same submission, for the log it names");
    }

    /// Two copies of one submission inside a single page of `/pending`. The map
    /// on disk is updated only after the batch commits. Without a record kept
    /// for the batch itself, the replay would go into the log beside its
    /// original.
    #[test]
    fn a_replay_beside_its_original_in_one_drain_tick_is_resolved_not_duplicated() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = on_test_session(open(&path, &key).expect("a new database"));
        let owner = logchain::ephemeral_key();

        let request = order_request(&owner, 1000, 100.25, 5.0);
        let original = entry_from_order(&request, 1);
        let mut replay = entry_from_order(&request, 2);
        replay.inbox_id = 2;

        let (marks, refused) = sequence_drained(&mut state, "epoch1", vec![original, replay]);
        assert!(
            refused.is_empty(),
            "neither entry is refused: {:?}",
            refused
        );
        assert_eq!(marks.len(), 2, "both entries are answered");
        assert_eq!(
            marks[0].2.feed_id, marks[1].2.feed_id,
            "with the same message, because they are the same submission"
        );
        assert_eq!(state.messages.len(), 1, "which was published once");
    }

    /// A nonce names one submission. The submitter picks the nonce, so an
    /// account can sign two different submissions under one nonce. The second
    /// one cannot go into the log.
    ///
    /// How the second one is refused matters. Marking the entry against the
    /// message the nonce already produced would write a `content_mismatch` into
    /// the rejection log of the separate service. That log holds the marks the
    /// sequencer signed and the service refused, so it is evidence about the
    /// sequencer. A submitter that reuses its own nonce is not evidence about
    /// the sequencer, and must not be recorded beside the cases that are.
    #[test]
    fn one_nonce_over_two_different_submissions_is_refused_by_name() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = on_test_session(open(&path, &key).expect("a new database"));
        let owner = logchain::ephemeral_key();

        let shared = nonce(0x5a);
        let first = entry_from_order(
            &order_request_with_nonce(&owner, 1000, 100.25, 5.0, &shared),
            1,
        );
        // Same account, same nonce, a different price. The signature is valid,
        // and it covers different terms.
        let second = entry_from_order(
            &order_request_with_nonce(&owner, 1000, 100.26, 5.0, &shared),
            2,
        );

        let (marks, refused) = sequence_drained(&mut state, "epoch1", vec![first, second.clone()]);
        assert_eq!(marks.len(), 1, "only the first submission is sequenced");
        assert_eq!(marks[0].0, 1);
        assert_eq!(refused.len(), 1, "and the second is refused, not marked");
        assert_eq!(refused[0].0, 2);
        assert!(
            refused[0].1.contains("already used this nonce"),
            "the reason has to name what happened: {}",
            refused[0].1
        );
        assert_eq!(state.messages.len(), 1);

        // The same across two drain rounds, once the first entry is committed
        // and in the map on disk rather than in the batch.
        let (marks, refused) = sequence_drained(&mut state, "epoch1", vec![second]);
        assert!(marks.is_empty());
        assert_eq!(refused.len(), 1);
        assert!(refused[0].1.contains("already used this nonce"));
        assert_eq!(state.messages.len(), 1);
    }

    /// A nonce is spent only by a message that was really published. The other
    /// choice would tell a submitter that retries after a disk error that their
    /// order already exists, when no order exists.
    #[tokio::test]
    async fn a_failed_write_leaves_the_nonce_free() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let state = Arc::new(Mutex::new(on_test_session(
            open(&path, &key).expect("a new database"),
        )));
        let owner = logchain::ephemeral_key();
        break_writes(&lock(&state));

        let request = order_request(&owner, 1000, 100.25, 5.0);
        let retry = order_request_with_nonce(&owner, 1000, 100.25, 5.0, &request.nonce);
        let failed = refused(
            submit_order(State(Arc::clone(&state)), peer(), Ok(Json(request))).await,
            "the write failed",
        );
        assert_eq!(failed.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            lock(&state).nonces.is_empty(),
            "nothing was published, so nothing was spent"
        );

        // The same submission, sent again once the disk works, is the order it
        // always was. It is not a replay.
        lock(&state)
            .storage
            .conn()
            .unwrap()
            .execute_batch("DROP TRIGGER no_writes;")
            .unwrap();
        let accepted = submit_order(State(Arc::clone(&state)), peer(), Ok(Json(retry)))
            .await
            .expect("a retry after a failed write is accepted");
        assert_eq!(accepted.0.id, 1);
    }

    /// The rule that makes every deployed `feed.db` still start. A message that
    /// never had a nonce serializes to exactly the bytes it did before the
    /// field existed, so the chain over old history does not change.
    #[test]
    fn a_message_without_a_nonce_serializes_as_it_always_did() {
        let generated = order(1, 100.25);
        let json = serde_json::to_string(&generated).expect("serializes");
        assert_eq!(
            json,
            "{\"New\":{\"id\":1,\"timestamp\":1700000000001,\"account\":1,\"symbol\":\"ETH-USDC\",\
             \"side\":\"Buy\",\"price\":100.25,\"quantity\":5.0}}",
            "no `nonce` key at all, or every existing feed.db fails its checkpoint"
        );
        // Read back, and written out again, unchanged. Every consumer that
        // hashes the chain again does this round trip.
        let read_back: OrderMessage = serde_json::from_str(&json).expect("reads back");
        assert_eq!(serde_json::to_string(&read_back).unwrap(), json);
        assert!(read_back.nonce().is_none());

        // A message that has a nonce carries it, so the nonce is inside the
        // hash chain and not beside it.
        let signed = order_with_nonce(1, 100.25, &nonce(0x11));
        let signed_json = serde_json::to_string(&signed).expect("serializes");
        assert!(signed_json.contains("\"nonce\":\"11111111111111111111111111111111\""));
        assert_ne!(
            logchain::extend(&EMPTY_CHAIN, &generated),
            logchain::extend(&EMPTY_CHAIN, &signed),
            "the nonce is committed to by the chain, so removing one is tampering"
        );
    }

    /// A database written before nonces existed opens, passes its checkpoint,
    /// and keeps signing the same history.
    #[test]
    fn a_feed_db_from_before_nonces_still_starts() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let before = {
            let mut state = open(&path, &key).expect("a new database");
            // None of these has a nonce, which is exactly what a database
            // written by the previous build holds.
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26), order(3, 100.27)])
                .expect("published");
            state.chain
        };

        let state = open(&path, &key).expect("an old database still starts");
        assert_eq!(state.chain, before, "and reaches the same chain");
        assert!(state.nonces.is_empty(), "no nonces to remember");
        assert_eq!(state.next_id, 4);
    }

    /// A history longer than the window, published the way the generator
    /// publishes: one transaction, ids handed out in order.
    fn long_history(path: &Path, key: &SigningKey, total: u64) -> Chain {
        let mut state = open(path, key).expect("a new database");
        let batch: Vec<OrderMessage> = (1..=total)
            .map(|id| order(id, 100.0 + (id % 100) as f64 / 100.0))
            .collect();
        state.next_id = total + 1;
        state.publish_batch(batch).expect("published");
        state.chain
    }

    /// The size every test below needs: past the window, so the oldest messages
    /// are on disk only.
    const PAST_WINDOW: u64 = MESSAGE_WINDOW as u64 + 500;

    /// The start loads the window and not the whole history. This used to be
    /// impossible. The check loaded every message before it checked anything,
    /// so a history larger than RAM could never start again, and the sequencer
    /// could only grow.
    #[test]
    fn a_history_longer_than_the_window_starts_with_only_the_window_in_memory() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let published = long_history(&path, &key, PAST_WINDOW);

        let state = open(&path, &key).expect("the same database");
        assert_eq!(state.chain, published, "the chain covers the whole history");
        assert_eq!(state.next_id, PAST_WINDOW + 1);
        assert_eq!(state.last_id(), PAST_WINDOW);
        assert_eq!(
            state.messages.len(),
            MESSAGE_WINDOW,
            "the window is bounded, whatever the history is"
        );
        assert_eq!(
            state.window_start(),
            PAST_WINDOW - MESSAGE_WINDOW as OrderId + 1,
            "and holds the newest messages"
        );
        assert_eq!(state.chains.len(), state.messages.len());
        // The head the sequencer signs covers the whole history, not the
        // window.
        assert_eq!(state.signed_head().last_id, PAST_WINDOW);
    }

    /// `?since=0` walks the whole history from disk, page by page, with a head
    /// over each page that verifies. This is what `--verify`, `--audit`, and a
    /// bot replaying after a session change all do.
    #[tokio::test]
    async fn orders_below_the_window_are_served_from_the_database() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let published = long_history(&path, &key, PAST_WINDOW);
        let state = Arc::new(Mutex::new(open(&path, &key).expect("the same database")));

        let mut chain = EMPTY_CHAIN;
        let mut seen: u64 = 0;
        let mut pages = 0;
        loop {
            let (head, body) = orders(&state, Some(seen), None).await.expect("a page");
            if body.is_empty() {
                break;
            }
            pages += 1;
            for msg in &body {
                seen += 1;
                assert_eq!(msg.id(), seen, "the pages are the history, in order");
                chain = logchain::extend(&chain, msg);
            }
            assert_eq!(
                head[HEAD_LAST_ID_HEADER],
                seen.to_string(),
                "the head stands at the last message served"
            );
            assert_eq!(
                head[HEAD_CHAIN_HEADER],
                logchain::to_hex(&chain),
                "and its chain is the one the messages so far produce"
            );
            let signature = Signature::from_bytes(
                &logchain::from_hex::<64>(&head[HEAD_SIGNATURE_HEADER]).unwrap(),
            );
            assert!(
                logchain::verify_head(
                    &key.verifying_key(),
                    &head[SESSION_HEADER],
                    seen,
                    &chain,
                    &signature
                ),
                "a disk-served page carries a head this feed really signed"
            );
        }
        assert_eq!(seen, PAST_WINDOW, "every message was served");
        assert_eq!(chain, published, "and they fold to the published chain");
        assert!(pages > 1, "the walk really was paged");
    }

    /// Without a database there is nowhere to read an old message back from. A
    /// consumer that asks for a message which has left memory is told exactly
    /// that. It is not handed a page that starts somewhere else. A page that
    /// started wherever memory happens to begin would look to every consumer
    /// like the sequencer had rewritten its history.
    #[tokio::test]
    async fn a_memory_only_feed_refuses_what_it_no_longer_has() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        {
            let mut guard = lock(&state);
            let batch: Vec<OrderMessage> = (1..=PAST_WINDOW)
                .map(|id| order(id, 100.0 + (id % 100) as f64 / 100.0))
                .collect();
            guard.publish_batch(batch).expect("published");
        }

        let (status, why) = refused(
            orders_from(&state, peer(), Some(0), None, &[]).await,
            "these messages are not in memory and there is no database",
        );
        assert_eq!(status, StatusCode::GONE);
        assert!(why.contains("no longer in this feed's memory"), "{}", why);

        // The messages the sequencer still holds are served as usual.
        let (_, body) = orders(&state, Some(PAST_WINDOW - 10), None)
            .await
            .expect("the tail is still in memory");
        assert_eq!(body.len(), 10);
    }

    /// Every check for an edited history, against a history longer than the
    /// window, with the damage below the window. These checks used to run with
    /// every message in memory at once. The row checked here is one the
    /// sequencer never holds in memory.
    #[test]
    fn tampering_below_the_window_still_refuses_to_start() {
        let cases: [(&str, &str, &str); 4] = [
            (
                "an edited message",
                "UPDATE feed_messages SET json = replace(json, '\"price\":100.05', '\"price\":999.99') WHERE id = 5",
                "does not hold the history this feed last published",
            ),
            (
                "a truncated tail",
                "DELETE FROM feed_messages WHERE id > 10200",
                "does not hold the history this feed last published",
            ),
            (
                "a hole in the middle",
                "DELETE FROM feed_messages WHERE id = 7",
                "message ids in",
            ),
            (
                "a rewritten chain link",
                "UPDATE feed_messages SET chain = zeroblob(32) WHERE id = 3",
                "chain link stored with message 3",
            ),
        ];
        for (what, sql, expected) in cases {
            let dir = TempDir::new().unwrap();
            let (path, key) = feed_at(&dir);
            long_history(&path, &key, PAST_WINDOW);

            let conn = Connection::open(&path).unwrap();
            let changed = conn.execute(sql, []).unwrap();
            assert!(changed > 0, "{}: the edit changed nothing", what);
            drop(conn);

            let refused = refusal(open(&path, &key), what);
            assert!(
                refused.contains(expected),
                "{}: unexpected error: {}",
                what,
                refused
            );
        }
    }

    /// The replay check covers the whole history, not only what is in memory.
    /// A nonce spent by the first message of a long history is still spent
    /// after a restart that holds only the last ten thousand messages.
    #[tokio::test]
    async fn a_nonce_below_the_window_is_still_spent_after_a_restart() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let account_key = logchain::ephemeral_key();
        let spent = nonce(9);
        let again = order_request_with_nonce(&account_key, 1000, 100.25, 5.0, &spent);
        {
            let state = Arc::new(Mutex::new(on_test_session(
                open(&path, &key).expect("a new database"),
            )));
            // The response holds the message that went into the log. This test
            // needs only that the submission was accepted, so it drops the id
            // on purpose instead of leaving an unused `#[must_use]` value.
            let _accepted = submit_order(
                State(Arc::clone(&state)),
                peer(),
                Ok(Json(order_request_with_nonce(
                    &account_key,
                    1000,
                    100.25,
                    5.0,
                    &spent,
                ))),
            )
            .await
            .expect("the first submission");
            // Message 1 carries a nonce. Everything after it is generated
            // traffic, which carries no nonce, and pushes message 1 out of the
            // window.
            let mut guard = lock(&state);
            let first_generated = guard.next_id;
            let batch: Vec<OrderMessage> = (first_generated..=PAST_WINDOW)
                .map(|id| order(id, 100.0 + (id % 100) as f64 / 100.0))
                .collect();
            guard.next_id = PAST_WINDOW + 1;
            guard.publish_batch(batch).expect("published");
        }

        let state = Arc::new(Mutex::new(on_test_session(
            open(&path, &key).expect("the same database"),
        )));
        assert!(
            lock(&state).message(1).is_some(),
            "message 1 is below the window and read back from the database"
        );
        let (status, why) = refused(
            submit_order(State(Arc::clone(&state)), peer(), Ok(Json(again))).await,
            "the nonce on message 1 was already spent",
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(why.contains("feed message 1"), "{}", why);
    }

    // -----------------------------------------------------------------------
    // Caching closed ranges
    // -----------------------------------------------------------------------

    /// A sequencer holding `total` messages, every price a whole number of
    /// price steps, so the bytes served survive a JSON round trip. See the note
    /// in `orders_are_paged_and_the_head_covers_exactly_what_is_served`.
    fn feed_holding(total: u64) -> Arc<Mutex<FeedState>> {
        let state = Arc::new(Mutex::new(on_test_session(FeedState::new(4, WALL))));
        {
            let mut guard = lock(&state);
            let batch: Vec<OrderMessage> = (1..=total)
                .map(|id| order(id, round2(100.0 + (id % 500) as f64 / 100.0)))
                .collect();
            guard.publish_batch(batch).expect("published");
        }
        state
    }

    /// A page whose whole range lies below the head can never change. It is
    /// cached forever, and it carries an ETag a client can check against.
    #[tokio::test]
    async fn a_closed_page_is_immutable_and_carries_an_etag() {
        let state = feed_holding(2_500);
        let response = ndjson_from(&state, peer(), Some(0), Some(1000), &[])
            .await
            .expect("a page");
        assert_eq!(response.status(), StatusCode::OK);
        let head = headers_of(&response);
        assert_eq!(
            head[header::CACHE_CONTROL.as_str()],
            "public, max-age=31536000, immutable"
        );
        let etag = head[header::ETAG.as_str()].clone();
        assert!(
            etag.starts_with('"') && etag.ends_with('"'),
            "a strong ETag is a quoted string, not {}",
            etag
        );
        assert!(
            !etag.starts_with("W/"),
            "these bytes are exact, so the validator is strong: {}",
            etag
        );
        // The ETag holds the chain the sequencer signed at the page's last
        // message. The ETag therefore names the content without hashing it.
        assert!(
            etag.contains(&head[HEAD_CHAIN_HEADER]),
            "the ETag names the chain at the last message: {} / {}",
            etag,
            head[HEAD_CHAIN_HEADER]
        );

        // The same URL again gives the same bytes and the same ETag. Nothing in
        // the answer depends on when the client asked.
        let again = ndjson_from(&state, peer(), Some(0), Some(1000), &[])
            .await
            .expect("the same page");
        assert_eq!(headers_of(&again)[header::ETAG.as_str()], etag);
        assert_eq!(
            body_of(again).await,
            body_of(response).await,
            "a closed page is the same bytes every time"
        );
    }

    /// A shared cache may store a `public` answer only under the origin that
    /// asked for it. Without `Vary: origin`, the copy `curl` fetched would go
    /// to a browser. That copy has no `Origin` on the request and no
    /// `Access-Control-Allow-Origin` on the answer, so the browser would refuse
    /// to read a correct answer. The cross-origin layer adds `Vary` only for a
    /// request that carried an `Origin`, so a cacheable response has to add
    /// `Vary` itself.
    #[tokio::test]
    async fn a_cacheable_answer_says_it_varies_on_the_origin_that_asked() {
        let state = feed_holding(2_500);
        for request_headers in [&[][..], &[("origin", "http://127.0.0.1:3001")][..]] {
            let response = feed_router(Arc::clone(&state), default_origins(), None)
                .oneshot({
                    let mut request = local_request("/messages.ndjson?since=0&limit=1000");
                    for (name, value) in request_headers {
                        request.headers_mut().insert(
                            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                            HeaderValue::from_str(value).unwrap(),
                        );
                    }
                    request
                })
                .await
                .expect("the router answers");
            assert!(
                headers_of(&response)[header::CACHE_CONTROL.as_str()].contains("public"),
                "this page is shared-cacheable"
            );
            assert!(
                response
                    .headers()
                    .get_all(header::VARY)
                    .iter()
                    .any(|value| value.to_str().unwrap_or_default().contains("origin")),
                "a shared-cacheable answer with no Vary can be replayed to the wrong origin \
                 (request headers: {:?})",
                request_headers
            );
        }
    }

    /// Every page that is not a closed range. Each one looks cacheable by at
    /// least one of the tests above, and is not.
    #[tokio::test]
    async fn a_page_that_touches_the_head_is_never_cached() {
        let state = feed_holding(1_500);
        let cases: [(&str, Option<OrderId>, Option<usize>); 3] = [
            // Short. The next message makes this URL answer with more lines.
            ("a page that runs into the head", Some(1_000), Some(1000)),
            // Empty. This page carries the head of the whole history.
            ("an empty page", Some(1_500), Some(1000)),
            // Zero length, which is full and empty at the same time.
            ("a page of no messages", Some(0), Some(0)),
        ];
        for (why, since, limit) in cases {
            let response = ndjson_from(&state, peer(), since, limit, &[])
                .await
                .unwrap_or_else(|e| panic!("{}: {:?}", why, e));
            let head = headers_of(&response);
            assert_eq!(head[header::CACHE_CONTROL.as_str()], "no-store", "{}", why);
            assert!(
                !head.contains_key(header::ETAG.as_str()),
                "{} must not offer a validator either",
                why
            );
        }

        // `?n=` has to be refused on the form of the request, not on the body.
        // It comes back full, 1000 of 1500 messages, and answers with a
        // different 1000 every time the sequencer publishes.
        let response = orders_from(&state, peer(), None, Some(PAGE_LIMIT), &[])
            .await
            .expect("a tail");
        let head = headers_of(&response);
        assert_eq!(
            head[header::CACHE_CONTROL.as_str()],
            "no-store",
            "?n= names a range relative to the head and can never be cached"
        );
        assert!(!head.contains_key(header::ETAG.as_str()));
    }

    /// The rule behind option (c) in the note above `Freshness`. The head
    /// headers may travel on a cached response only because they stand at the
    /// last message in the body. This test fails if anyone marks a response
    /// immutable while its head describes anything else. The
    /// `unwrap_or((last_id, chain))` fallback puts exactly that on an empty
    /// page.
    #[tokio::test]
    async fn an_immutable_response_never_carries_a_head_past_its_body() {
        let state = feed_holding(3_000);
        // Every form of page this sequencer can answer with, cacheable or not.
        let ranges: [(Option<OrderId>, Option<usize>); 6] = [
            (Some(0), Some(1000)),
            (Some(1_000), Some(1000)),
            (Some(2_500), Some(500)),
            (Some(2_500), Some(1000)),
            (Some(3_000), Some(1000)),
            (Some(2_999), Some(1)),
        ];
        for (since, limit) in ranges {
            let response = ndjson_from(&state, peer(), since, limit, &[])
                .await
                .expect("a page");
            let head = headers_of(&response);
            let immutable = head[header::CACHE_CONTROL.as_str()].contains("immutable");
            let body = body_of(response).await;
            let last_line = body
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .next_back()
                .map(|line| {
                    serde_json::from_slice::<OrderMessage>(line)
                        .expect("a message")
                        .id()
                });
            if immutable {
                assert_eq!(
                    Some(head[HEAD_LAST_ID_HEADER].parse::<OrderId>().unwrap()),
                    last_line,
                    "an immutable response whose head stands past its body would let a cache \
                     hand out a head that is no longer current (since={:?} limit={:?})",
                    since,
                    limit
                );
            }
            // The other half of the same rule. A response that really does
            // carry the current head is never immutable.
            if last_line.is_none() {
                assert!(
                    !immutable,
                    "an empty page carries the head of the whole history and must not be cached"
                );
            }
        }
    }

    /// What a client that kept the ETag saves: a few bytes, and no page read.
    /// The 304 repeats the cache headers, so the stored entry stays cacheable.
    #[tokio::test]
    async fn a_matching_if_none_match_gets_a_304_with_no_body() {
        let state = feed_holding(2_500);
        let first = ndjson_from(&state, peer(), Some(0), Some(1000), &[])
            .await
            .expect("a page");
        let etag = headers_of(&first)[header::ETAG.as_str()].clone();
        assert!(!body_of(first).await.is_empty());

        let again = ndjson_from(
            &state,
            peer(),
            Some(0),
            Some(1000),
            &[(header::IF_NONE_MATCH.as_str(), &etag)],
        )
        .await
        .expect("a revalidation");
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
        let head = headers_of(&again);
        assert_eq!(head[header::ETAG.as_str()], etag);
        assert_eq!(
            head[header::CACHE_CONTROL.as_str()],
            "public, max-age=31536000, immutable",
            "a 304 that dropped these would tell the cache to stop caching"
        );
        assert!(body_of(again).await.is_empty(), "a 304 carries no body");

        // An ETag for a different range does not match this range.
        let wrong = ndjson_from(
            &state,
            peer(),
            Some(1_000),
            Some(1000),
            &[(header::IF_NONE_MATCH.as_str(), &etag)],
        )
        .await
        .expect("a page");
        assert_eq!(wrong.status(), StatusCode::OK);
        assert!(!body_of(wrong).await.is_empty());

        // A page that is not closed has no ETag. A client that sends one gets
        // the page, and is not told that nothing changed.
        let open = ndjson_from(
            &state,
            peer(),
            Some(2_400),
            Some(1000),
            &[(header::IF_NONE_MATCH.as_str(), &etag)],
        )
        .await
        .expect("a page");
        assert_eq!(open.status(), StatusCode::OK);
    }

    // -----------------------------------------------------------------------
    // The read budget
    // -----------------------------------------------------------------------

    /// The work this endpoint exists for must never be the work the budget
    /// refuses: 14 pages, 13,774 messages, in one burst from one visitor.
    ///
    /// The test runs on a real database, because that is where those messages
    /// are. The first anchor's range of ids is far below `MESSAGE_WINDOW`, so
    /// every page of it is a SQLite read. That read is the cost the cache
    /// headers and this budget are both about.
    #[tokio::test]
    async fn a_first_anchor_verification_is_never_refused() {
        const ANCHOR_LAST_ID: u64 = 13_774;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, ANCHOR_LAST_ID + 200);
        let state = Arc::new(Mutex::new(open(&path, &key).expect("the same database")));
        let visitor = reader("203.0.113.9");

        let mut folded = 0u64;
        let mut pages = 0;
        while folded < ANCHOR_LAST_ID {
            let want = PAGE_LIMIT.min((ANCHOR_LAST_ID - folded) as usize);
            let response = ndjson_from(&state, visitor.clone(), Some(folded), Some(want), &[])
                .await
                .expect("a page");
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "page {} of verifying the first anchor was refused",
                pages + 1
            );
            assert!(
                headers_of(&response)[header::CACHE_CONTROL.as_str()].contains("immutable"),
                "every page of a settled anchor is a closed range"
            );
            folded += want as u64;
            pages += 1;
        }
        assert_eq!(pages, 14, "this is the shape the browser really asks in");

        // There is room to do the same walk twice more, because a visitor who
        // reloads the page must not be told to come back later.
        for round in 0..2 {
            let mut folded = 0u64;
            while folded < ANCHOR_LAST_ID {
                let want = PAGE_LIMIT.min((ANCHOR_LAST_ID - folded) as usize);
                let response = ndjson_from(&state, visitor.clone(), Some(folded), Some(want), &[])
                    .await
                    .expect("a page");
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "verification {} was refused after {} messages",
                    round + 2,
                    folded
                );
                folded += want as u64;
            }
        }
    }

    /// The loop the limiter did not catch before. `?since=0&limit=1000` sent as
    /// fast as sockets open is refused, and the refusal says when to come back.
    #[tokio::test]
    async fn an_abusive_read_burst_is_refused_with_a_retry_after() {
        let state = feed_holding(5_000);
        let flood = reader("198.51.100.7");

        let mut refusal = None;
        for attempt in 0..200 {
            let response = ndjson_from(&state, flood.clone(), Some(0), Some(1000), &[])
                .await
                .expect("an answer");
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                refusal = Some((attempt, response));
                break;
            }
        }
        let (attempt, response) = refusal.expect("a whole-history loop is refused");
        assert!(
            attempt >= 40,
            "the burst has to cover an honest verification first, not stop at {}",
            attempt
        );
        let head = headers_of(&response);
        let retry: u64 = head[header::RETRY_AFTER.as_str()]
            .parse()
            .expect("Retry-After is a whole number of seconds");
        assert!(retry >= 1, "Retry-After: 0 invites an immediate retry");
        let body = String::from_utf8(body_of(response).await).expect("a readable refusal");
        assert!(body.contains("198.51.100.7"), "{}", body);
        assert!(body.contains("read budget"), "{}", body);
        assert!(
            body.contains(&READ_BURST.to_string()),
            "the refusal says what the budget is: {}",
            body
        );
        assert!(
            body.contains("anchor"),
            "and that an honest verification fits inside it: {}",
            body
        );
    }

    /// The same bug the submission limiter had, now on reads. Behind a proxy
    /// every visitor arrives from the proxy's address. Without `TrustedProxies`
    /// one reader would spend everyone's budget.
    #[tokio::test]
    async fn two_clients_behind_one_proxy_do_not_share_a_read_budget() {
        let state = feed_holding(5_000);
        {
            lock(&state).trusted_proxies = trusted(&["172.17.0.0/16"]);
        }
        let first = Caller::with_forwarded("172.17.0.3:41000", &["203.0.113.9"]);
        let second = Caller::with_forwarded("172.17.0.3:41000", &["198.51.100.7"]);

        let mut spent = 0;
        loop {
            let response = ndjson_from(&state, first.clone(), Some(0), Some(1000), &[])
                .await
                .expect("an answer");
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                break;
            }
            spent += 1;
            assert!(spent < 500, "the first reader's budget never ran out");
        }

        let response = ndjson_from(&state, second, Some(0), Some(1000), &[])
            .await
            .expect("an answer");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a second visitor behind the same proxy must have their own budget"
        );
    }

    /// The default has to be safe for the deployment that exists. Every
    /// consumer this exchange runs reads the sequencer at
    /// `http://127.0.0.1:3000`, in `demo.sh` and inside the container. Those
    /// consumers are the exchange, three validators, the bot and the anchor
    /// sender. A budget that could refuse them would stall a validator after
    /// twenty refused polls, and that validator would drop out of the set that
    /// has to agree. The loopback address is exempt for that reason, and this
    /// test pins it.
    #[tokio::test]
    async fn this_exchange_s_own_consumers_are_never_read_limited() {
        let state = feed_holding(5_000);
        for round in 0..300 {
            let response = ndjson_from(&state, peer(), Some(0), Some(1000), &[])
                .await
                .expect("an answer");
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "a local consumer was refused on read {}",
                round
            );
        }
    }

    // -----------------------------------------------------------------------
    // /metrics
    // -----------------------------------------------------------------------

    /// `/metrics` has to parse as Prometheus text: every series declared, every
    /// value a number. The counters also have to move when a caller reads the
    /// sequencer.
    #[tokio::test]
    async fn metrics_are_prometheus_text_and_the_counters_move() {
        let state = feed_holding(2_500);
        let router = || feed_router(Arc::clone(&state), default_origins(), None);

        let scrape = |router: Router| async move {
            let response = router
                .oneshot(local_request("/metrics"))
                .await
                .expect("the router answers");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                headers_of(&response)[header::CONTENT_TYPE.as_str()],
                METRICS_CONTENT_TYPE
            );
            String::from_utf8(body_of(response).await).expect("metrics are text")
        };

        let before = scrape(router()).await;
        // Enough of the format that a scraper would accept it. Every sample
        // line names a declared metric and ends in a number. Every metric that
        // has samples has a HELP line and a TYPE line.
        let mut declared: Vec<&str> = Vec::new();
        for line in before.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').expect("# TYPE <name> <kind>");
                assert!(
                    kind == "counter" || kind == "gauge",
                    "unknown metric type {}",
                    kind
                );
                declared.push(name);
                continue;
            }
            if line.starts_with("# HELP ") {
                continue;
            }
            assert!(!line.is_empty(), "no blank lines in the exposition");
            let (series, value) = line.rsplit_once(' ').expect("<series> <value>");
            value
                .parse::<f64>()
                .unwrap_or_else(|_| panic!("{} is not a number, in: {}", value, line));
            let name = series.split('{').next().expect("a metric name");
            assert!(
                declared.contains(&name),
                "{} has samples but no # TYPE line",
                name
            );
        }
        assert!(before.ends_with('\n'), "the exposition ends with a newline");
        for expected in [
            "feed_requests_total",
            "feed_response_bytes_total",
            "feed_messages_served_total",
            "feed_db_page_seconds_total",
            "feed_db_pages_total",
            "feed_cache_responses_total",
            "feed_reads_refused_total",
            "feed_head_id",
            "feed_window_messages",
            "feed_uptime_seconds",
        ] {
            assert!(before.contains(expected), "{} is missing", expected);
        }
        assert!(
            before.contains("feed_head_id 2500"),
            "the head id is the newest message published"
        );

        // One closed page, and the counters that page moves.
        let sample = |text: &str, series: &str| -> u64 {
            text.lines()
                .find_map(|line| line.strip_prefix(series))
                .and_then(|rest| rest.trim().parse().ok())
                .unwrap_or_else(|| panic!("{} is not in the exposition", series))
        };
        let read = router()
            .oneshot(local_request("/messages.ndjson?since=0&limit=1000"))
            .await
            .expect("the router answers");
        let served = body_of(read).await.len() as u64;
        assert!(served > 0);

        let after = scrape(router()).await;
        assert_eq!(
            sample(&after, "feed_messages_served_total{source=\"window\"}")
                - sample(&before, "feed_messages_served_total{source=\"window\"}"),
            1000,
            "a thousand messages came out of the in-memory window"
        );
        assert_eq!(
            sample(
                &after,
                "feed_response_bytes_total{endpoint=\"messages_ndjson\"}"
            ),
            served,
            "the bytes counted are the bytes that left"
        );
        assert_eq!(
            sample(
                &after,
                "feed_requests_total{endpoint=\"messages_ndjson\",status=\"2xx\"}"
            ),
            1
        );
        assert_eq!(
            sample(&after, "feed_cache_responses_total{outcome=\"immutable\"}")
                - sample(&before, "feed_cache_responses_total{outcome=\"immutable\"}"),
            1,
            "and that page was a closed range"
        );
        assert!(
            sample(
                &after,
                "feed_requests_total{endpoint=\"metrics\",status=\"2xx\"}"
            ) >= 1,
            "the scrape counts itself"
        );
    }

    // -----------------------------------------------------------------------
    // Serving the bytes that were hashed
    // -----------------------------------------------------------------------
    //
    // The sequencer stores each message's JSON and hashes those bytes into the
    // chain. Everything below pins the one rule that follows. What the
    // sequencer serves, from memory or from disk, is that same byte string. It
    // is never a second serialization of the message. If that stops being
    // true, the sequencer serves a page that does not hash to the chain stored
    // beside it, and every consumer reads that as a rewritten history.

    /// A message kind added to the sequencer after this build was compiled.
    ///
    /// Bytes are the only form of it that exists here. No struct in this binary
    /// can produce one. That is exactly where a sequencer stands against its
    /// own database after a release is rolled back.
    fn market_order(id: OrderId, nonce: Option<&str>) -> String {
        let nonce = match nonce {
            Some(nonce) => format!(r#","nonce":"{}""#, nonce),
            None => String::new(),
        };
        format!(
            r#"{{"Market":{{"id":{},"timestamp":{},"account":1,"symbol":"ETH-USDC","side":"Buy","quantity":3.0,"max_slippage_bps":50{}}}}}"#,
            id,
            WALL + id,
            nonce
        )
    }

    /// Appends one message to a `feed.db` exactly as the sequencer binary that
    /// created it would have: the bytes, the chain link over them, its Merkle
    /// leaf and the nodes above it, and a checkpoint signed for the history and
    /// the tree they end.
    ///
    /// This is the only way to build a database that holds a kind this build
    /// cannot read, because this build cannot create such a message.
    fn append_stored(path: &Path, key: &SigningKey, id: OrderId, json: &str) {
        let conn = Connection::open(path).unwrap();
        let session: String = conn
            .query_row(
                "SELECT value FROM feed_meta WHERE key = 'session'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let previous: Chain = if id == 1 {
            EMPTY_CHAIN
        } else {
            let bytes: Vec<u8> = conn
                .query_row(
                    "SELECT chain FROM feed_messages WHERE id = ?1",
                    params![id as i64 - 1],
                    |row| row.get(0),
                )
                .unwrap();
            bytes.try_into().unwrap()
        };
        let chain = logchain::extend_bytes(&previous, json.as_bytes());
        conn.execute(
            "INSERT INTO feed_messages (id, json, chain) VALUES (?1, ?2, ?3)",
            params![id as i64, json, chain.as_slice()],
        )
        .unwrap();
        tree::append(&conn, id - 1, &[merkle::leaf_hash(json.as_bytes())]).unwrap();
        let root = tree::root(
            &Nodes::Disk {
                conn: &conn,
                leaves: id,
            },
            id,
        )
        .unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
            params![Checkpoint::row(key, &session, id, &chain, &root)],
        )
        .unwrap();
    }

    /// Every stored row, as it sits on disk.
    fn stored_rows(path: &Path) -> Vec<(i64, String, Vec<u8>)> {
        let conn = Connection::open(path).unwrap();
        let mut statement = conn
            .prepare("SELECT id, json, chain FROM feed_messages ORDER BY id")
            .unwrap();
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap();
        rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    /// The rule the whole change exists for. A sequencer binary older than its
    /// own database starts, hashes its way to the chain the newer binary
    /// signed, and does not report its own undamaged history as edited.
    #[test]
    fn a_database_holding_a_kind_this_build_cannot_read_still_starts() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let market = market_order(3, None);
        assert!(
            serde_json::from_str::<OrderMessage>(&market).is_err(),
            "this build must genuinely not know this kind, or the test proves nothing"
        );

        let expected = {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26)])
                .expect("published");
            let after_two = state.chain;
            drop(state);
            append_stored(&path, &key, 3, &market);
            logchain::extend_bytes(&after_two, market.as_bytes())
        };

        let state = open(&path, &key).expect("a feed older than its own database still starts");
        assert_eq!(
            state.chain, expected,
            "and reaches the chain the newer binary signed, over the same bytes"
        );
        assert_eq!(state.last_id(), 3);
        assert_eq!(
            state.next_id, 4,
            "so it keeps publishing where the history ends"
        );
        assert_eq!(state.unreadable, 1, "and counts what it could not read");

        // What the sequencer loses is the generator's own state for that
        // message. That is the only part of the reload that needs to understand
        // the message.
        assert_eq!(state.mids["ETH-USDC"], 100.26);
        // The sequencer says so. Anything that needs to understand message 3
        // gets no message back.
        assert!(state.message(3).is_none());
        assert!(state.message(2).is_some());
    }

    /// The sequencer's half of a bug seen in production, and the reason a
    /// confirmation carries the stored bytes and not a message serialized
    /// again.
    ///
    /// Take an entry this sequencer had already put in the log, whose message
    /// is a kind the sequencer cannot read after a rollback. That entry used to
    /// produce no mark at all. `state.message` answered `None`, nothing was
    /// sent, and the separate service reported a working sequencer as late. The
    /// mark now carries the bytes and an inclusion proof, and neither needs the
    /// kind.
    #[test]
    fn an_entry_whose_message_this_build_cannot_read_is_still_marked() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let owner = logchain::ephemeral_key();
        let spent = nonce(0x33);
        {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
        }
        // A newer binary put entry 5 of the separate service into the log as
        // message 2, of a kind this build does not know, and recorded the
        // pairing before the rollback. The mark for it was never delivered.
        let stored = market_order(2, Some(&spent));
        append_stored(&path, &key, 2, &stored);
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO inbox_sequenced (epoch, inbox_id, feed_id) VALUES ('epoch1', 5, 2)",
                [],
            )
            .unwrap();

        let mut state = open(&path, &key).expect("an older binary still starts");
        assert!(
            state.message(2).is_none(),
            "the premise: this build cannot read message 2"
        );

        let entry = inbox_entry(&owner, 5, order_submission(1, 100.25, &spent));
        let (marks, refused) = sequence_drained(&mut state, "epoch1", vec![entry]);
        assert!(
            refused.is_empty(),
            "a kind this build cannot read is not a refusal: {:?}",
            refused
        );
        assert_eq!(
            marks.len(),
            1,
            "the entry is confirmed rather than left to go overdue"
        );
        let request = &marks[0].2;
        assert_eq!(request.feed_id, 2);
        assert_eq!(
            request.message, stored,
            "the bytes as stored, not a message this build serialized again"
        );
        assert_eq!(
            (state.last_id(), state.next_id),
            (2, 3),
            "and the entry was not sequenced a second time"
        );

        // The confirmation has to hold on the other side. This is the one check
        // that the two services agree about the leaf index, the bytes and the
        // head. Each half can be correct on its own and still disagree with the
        // other.
        let public = key.verifying_key();
        assert!(
            inbox::verify_mark(&public, request),
            "the separate service has to accept this mark's signature"
        );
        assert_eq!(
            inbox::verify_inclusion(&public, request),
            Ok(()),
            "and the proof has to land on the root this feed signed"
        );
    }

    /// Every mark this sequencer builds carries a proof the separate service
    /// accepts. The entry's route into the history does not matter: it went
    /// into the log in this pass, or it was resolved against a message that was
    /// already published.
    #[test]
    fn every_mark_carries_a_proof_the_inbox_accepts() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let owner = logchain::ephemeral_key();
        let mut state = on_test_session(open(&path, &key).expect("a new database"));

        // Some traffic first, so the leaves under test are not leaf 0.
        state
            .publish_batch(vec![order(1, 100.25), order(2, 100.26), order(3, 100.27)])
            .expect("published");
        state.next_id = 4;

        let due: Vec<InboxEntry> = (0..5)
            .map(|i| {
                inbox_entry(
                    &owner,
                    10 + i,
                    order_submission(1, 100.25, &nonce(0x40 + i as u8)),
                )
            })
            .collect();
        let (marks, refused) = sequence_drained(&mut state, "epoch1", due);
        assert!(refused.is_empty(), "{:?}", refused);
        assert_eq!(marks.len(), 5);

        let public = key.verifying_key();
        for (inbox_id, _, request) in &marks {
            assert!(
                inbox::verify_mark(&public, request),
                "entry {}'s mark is not one the inbox would accept",
                inbox_id
            );
            assert_eq!(
                inbox::verify_inclusion(&public, request),
                Ok(()),
                "entry {}'s proof does not land on the root this feed signed",
                inbox_id
            );
            assert_eq!(
                request.message,
                state.stored_json(request.feed_id).expect("stored"),
                "entry {}'s mark carries bytes that are not the stored ones",
                inbox_id
            );
        }
    }

    /// A nonce spent by a message this build cannot read is still spent.
    ///
    /// Without this, a sequencer that was rolled back would accept that
    /// submission a second time. The next binary that can read both messages
    /// would then find two messages under one nonce and refuse to start. A
    /// downgrade would leave a database that cannot be started again.
    #[test]
    fn a_nonce_on_a_message_this_build_cannot_read_is_still_spent() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let spent = nonce(0x33);
        {
            let mut state = on_test_session(open(&path, &key).expect("a new database"));
            state.publish(order(1, 100.25)).expect("published");
        }
        append_stored(&path, &key, 2, &market_order(2, Some(&spent)));

        let state = on_test_session(open(&path, &key).expect("it still starts"));
        let key = (
            1u32,
            inbox::canonical_nonce(&spent).expect("a canonical nonce"),
        );
        assert_eq!(
            state.nonces.get(&key),
            Some(&2),
            "the nonce is read out of the bytes, so a kind this build cannot interpret still \
             spends one"
        );
    }

    /// Hashing the stored bytes must not have paid for new message kinds by
    /// losing a check. An edit to a message this build cannot read is caught by
    /// exactly the same checkpoint check as an edit to one it can read.
    #[test]
    fn tampering_with_a_message_this_build_cannot_read_still_refuses_to_start() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state.publish(order(1, 100.25)).expect("published");
        }
        append_stored(&path, &key, 2, &market_order(2, None));
        open(&path, &key).expect("it starts before the edit");

        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE feed_messages SET json = replace(json, '\"quantity\":3.0', '\"quantity\":9.0') \
             WHERE id = 2",
            [],
        )
        .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "message 2 was edited");
        assert!(
            refused.contains("does not hold the history this feed last published"),
            "unexpected error: {}",
            refused
        );
    }

    /// Opening a database must not rewrite one stored byte.
    ///
    /// The chain is a hash over those bytes. Anything that reformatted a row,
    /// or serialized it again through this build's structs on the way past,
    /// would change the history the sequencer signed. It would also change it
    /// without a warning, because the same pass would compute the chain again
    /// to match.
    #[test]
    fn opening_a_database_never_rewrites_a_stored_row() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![
                    order(1, 100.0),
                    order_with_nonce(2, 100.25, &nonce(0x77)),
                ])
                .expect("published");
        }
        append_stored(&path, &key, 3, &market_order(3, None));

        let before = stored_rows(&path);
        for _ in 0..3 {
            open(&path, &key).expect("it reopens");
        }
        assert_eq!(
            before,
            stored_rows(&path),
            "every row is byte for byte as it was"
        );
    }

    /// A history longer than the window, with a message this build cannot read
    /// below the window. This is where a long-running sequencer stands after a
    /// release was rolled back and the sequencer kept publishing.
    ///
    /// Returns the chain over the whole history and the id of the message this
    /// build cannot read.
    fn history_with_unreadable(path: &Path, key: &SigningKey, total: u64) -> (Chain, OrderId) {
        const UNREADABLE: OrderId = 6;
        {
            let mut state = open(path, key).expect("a new database");
            let batch: Vec<OrderMessage> = (1..UNREADABLE)
                .map(|id| order(id, round2(100.0 + id as f64 / 100.0)))
                .collect();
            state.next_id = UNREADABLE;
            state.publish_batch(batch).expect("published");
        }
        append_stored(path, key, UNREADABLE, &market_order(UNREADABLE, None));
        let chain = {
            let mut state = open(path, key).expect("the feed reopens over it");
            let batch: Vec<OrderMessage> = (UNREADABLE + 1..=total)
                .map(|id| order(id, round2(100.0 + (id % 500) as f64 / 100.0)))
                .collect();
            state.next_id = total + 1;
            state.publish_batch(batch).expect("published");
            state.chain
        };
        (chain, UNREADABLE)
    }

    /// The lines of one `/messages.ndjson` page, exactly as served.
    async fn ndjson_lines(
        state: &Arc<Mutex<FeedState>>,
        since: OrderId,
        limit: usize,
    ) -> (HashMap<String, String>, Vec<Vec<u8>>) {
        let response = ndjson_from(state, peer(), Some(since), Some(limit), &[])
            .await
            .expect("a page");
        let headers = headers_of(&response);
        let body = body_of(response).await;
        let mut lines: Vec<Vec<u8>> = body
            .split(|byte| *byte == b'\n')
            .map(|line| line.to_vec())
            .collect();
        assert_eq!(lines.pop(), Some(Vec::new()), "the body ends in a newline");
        (headers, lines)
    }

    /// The raw body of one `/orders` page, not parsed.
    ///
    /// The media type is checked here, and not in one test, because the body is
    /// no longer built by `Json`. Every JSON client on this endpoint needs the
    /// header to have stayed the same.
    async fn orders_body(state: &Arc<Mutex<FeedState>>, since: OrderId) -> Vec<u8> {
        let response = orders_from(state, peer(), Some(since), None, &[])
            .await
            .expect("a page");
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .expect("/orders says what it serves"),
            "application/json"
        );
        body_of(response).await
    }

    /// A page read back off the disk is the bytes that were hashed. That holds
    /// for a message this build cannot parse too.
    ///
    /// This half had to ship with the hashing done at start. Fixing only the
    /// hashing at start would let the sequencer start, and then serve, out of
    /// the same rows, bytes that do not hash to the `chain` column beside them.
    #[tokio::test]
    async fn a_disk_page_serves_the_bytes_that_were_hashed() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let (published, unreadable) = history_with_unreadable(&path, &key, PAST_WINDOW);
        let state = Arc::new(Mutex::new(open(&path, &key).expect("the same database")));
        assert!(
            lock(&state).window_start() > unreadable,
            "the unreadable message has to be below the window, or this reads from memory"
        );

        let (head, lines) = ndjson_lines(&state, 0, PAGE_LIMIT).await;
        assert_eq!(lines.len(), PAGE_LIMIT);
        assert_eq!(
            String::from_utf8(lines[unreadable as usize - 1].clone()).unwrap(),
            market_order(unreadable, None),
            "the message this build cannot read is served exactly as it was stored"
        );

        // Every line, hashed as it arrived, gives the chain the sequencer
        // signed.
        let mut chain = EMPTY_CHAIN;
        for line in &lines {
            chain = logchain::extend_bytes(&chain, line);
        }
        assert_eq!(head[HEAD_CHAIN_HEADER], logchain::to_hex(&chain));
        assert_eq!(head[HEAD_LAST_ID_HEADER], PAGE_LIMIT.to_string());
        let signature =
            Signature::from_bytes(&logchain::from_hex::<64>(&head[HEAD_SIGNATURE_HEADER]).unwrap());
        assert!(
            logchain::verify_head(
                &key.verifying_key(),
                &head[SESSION_HEADER],
                PAGE_LIMIT as OrderId,
                &chain,
                &signature
            ),
            "and the feed signed that chain"
        );

        // The whole history, page by page off the disk, hashes to what was
        // published, with a kind this binary does not know inside it.
        let mut chain = EMPTY_CHAIN;
        let mut since = 0;
        while since < PAST_WINDOW {
            let (_, lines) = ndjson_lines(&state, since, PAGE_LIMIT).await;
            assert!(!lines.is_empty());
            since += lines.len() as OrderId;
            for line in &lines {
                chain = logchain::extend_bytes(&chain, line);
            }
        }
        assert_eq!(chain, published, "the served history is the published one");
    }

    /// The place the two halves are most likely to disagree: a page that starts
    /// below the window and runs into it.
    ///
    /// The same message is served from the database in one request and from
    /// memory in the other, and the two have to be the same bytes. They are the
    /// same bytes only because the window holds what the rows hold. After a
    /// restart the window is rows read back off the disk. A window of messages
    /// serialized again would differ from the rows for exactly the kinds this
    /// build cannot read.
    #[tokio::test]
    async fn a_page_across_the_window_boundary_is_the_same_bytes_either_way() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        history_with_unreadable(&path, &key, PAST_WINDOW);
        let state = Arc::new(Mutex::new(open(&path, &key).expect("the same database")));

        let start = lock(&state).window_start();
        assert!(
            start > 1,
            "the window has to have moved, or nothing is on disk"
        );

        // One page that begins five messages below the window and runs twenty
        // into it, and one that begins exactly at the window.
        let (_, crossing) = ndjson_lines(&state, start - 6, 25).await;
        let (_, in_memory) = ndjson_lines(&state, start - 1, 20).await;
        assert_eq!(crossing.len(), 25);
        assert_eq!(in_memory.len(), 20);
        assert_eq!(
            &crossing[5..],
            &in_memory[..],
            "the same messages, served from the database and from memory"
        );

        // The messages below the window come from the disk, and the ones above
        // it from memory, so the assert above really did compare the two.
        let (_, disk_only) = ndjson_lines(&state, start - 6, 5).await;
        assert_eq!(&crossing[..5], &disk_only[..]);
    }

    /// The two endpoints serve one history, and have to serve it as one set of
    /// bytes. `/orders` puts those bytes in a JSON array. `/messages.ndjson`
    /// puts the same bytes one per line.
    ///
    /// Both the memory branch and the disk branch are checked, because the
    /// array used to be built by serializing parsed messages again while the
    /// lines were not.
    #[tokio::test]
    async fn orders_and_messages_ndjson_serve_the_same_bytes() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        history_with_unreadable(&path, &key, PAST_WINDOW);
        let state = Arc::new(Mutex::new(open(&path, &key).expect("the same database")));
        let start = lock(&state).window_start();

        // `0` is served from the database, `start - 1` from the window.
        for since in [0, start - 1] {
            let (_, lines) = ndjson_lines(&state, since, PAGE_LIMIT).await;
            let mut expected = vec![b'['];
            for (index, line) in lines.iter().enumerate() {
                if index > 0 {
                    expected.push(b',');
                }
                expected.extend_from_slice(line);
            }
            expected.push(b']');
            assert_eq!(
                orders_body(&state, since).await,
                expected,
                "/orders?since={} is the same messages as /messages.ndjson, in the same bytes",
                since
            );
        }
    }

    /// The float protection, on every route that can serve a message.
    ///
    /// serde writes an f64 price of 100.0 as `100.0`, and those are the bytes
    /// in the chain. A different serializer writes `100`: a browser's
    /// `JSON.stringify` does. Anything that parsed a stored message and wrote
    /// it out through such a serializer hashes different bytes, and reports a
    /// working sequencer as one that rewrote its history. The endpoints must
    /// never be that different serializer.
    #[tokio::test]
    async fn a_whole_number_price_stays_a_float_from_memory_and_from_disk() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.0), order(2, 100.25)])
                .expect("published");
        }
        let state = Arc::new(Mutex::new(open(&path, &key).expect("reopened")));

        // From the window, on both endpoints.
        let (from_window, lines) = ndjson_lines(&state, 0, PAGE_LIMIT).await;
        let line = String::from_utf8(lines[0].clone()).unwrap();
        assert!(line.contains("\"price\":100.0"), "{}", line);
        assert!(!line.contains("\"price\":100,"), "{}", line);
        let array = String::from_utf8(orders_body(&state, 0).await).unwrap();
        assert!(array.contains("\"price\":100.0"), "{}", array);

        // Now from the disk. The test moves the window past message 1 instead
        // of publishing 10,000 more messages, which would prove the same thing
        // far more slowly. What matters is which branch of `page` answers, and
        // a message below the window takes the branch that reads rows.
        {
            let mut guard = lock(&state);
            guard.messages.pop_front();
            guard.chains.pop_front();
            assert_eq!(guard.window_start(), 2);
        }
        let (from_disk, disk_lines) = ndjson_lines(&state, 0, PAGE_LIMIT).await;
        assert_eq!(
            disk_lines, lines,
            "the rows and the window hold the same bytes, message for message"
        );
        assert_eq!(
            from_disk[HEAD_CHAIN_HEADER], from_window[HEAD_CHAIN_HEADER],
            "so the head over the page is the same chain from either branch"
        );
        assert_eq!(
            from_disk[HEAD_CHAIN_HEADER],
            logchain::to_hex(&disk_lines.iter().fold(EMPTY_CHAIN, |chain, line| {
                logchain::extend_bytes(&chain, line)
            })),
            "and it is the fold over the bytes that were served"
        );
        assert_eq!(
            String::from_utf8(orders_body(&state, 0).await).unwrap(),
            array,
            "on both endpoints"
        );
    }

    // -----------------------------------------------------------------------
    // The operator's endpoint
    //
    // `POST /operator` is the one route a trader can never use. These tests
    // check who it answers, in which words, and that a message it published is
    // in the history like any other, with the signature inside the bytes and a
    // proof that lands on the root this sequencer signed.
    // -----------------------------------------------------------------------

    /// A sequencer that names an operator, on an in-memory history.
    fn feed_for(operator: &SigningKey) -> Arc<Mutex<FeedState>> {
        let mut state = FeedState::new(4, WALL);
        state.operator_key = Some(operator.verifying_key());
        Arc::new(Mutex::new(state))
    }

    /// The session a sequencer's operator signs for.
    fn session_of(state: &Arc<Mutex<FeedState>>) -> String {
        lock(state).session.clone()
    }

    /// The signature the operator puts on a message.
    ///
    /// A message the rules refuse has no statement to sign, so it gets a
    /// placeholder signature. The handler refuses such a message on its values
    /// before it looks at any signature, so the placeholder never reaches a
    /// signature check. This works like `proof`, for the same reason.
    fn operator_signature(key: &SigningKey, session: &str, message: &OrderMessage) -> String {
        match operator::kind_and_fields(message) {
            Ok((kind, fields)) => operator::sign(key, kind, session, &fields),
            Err(_) => logchain::to_hex(&[0u8; 64]),
        }
    }

    /// A `POST /operator` body for a listing, signed the way the command line
    /// signs one.
    fn listing_request(
        key: &SigningKey,
        session: &str,
        symbol: &str,
        price_step: f64,
        quantity_step: f64,
        nonce: &str,
    ) -> SubmitOperatorRequest {
        let message = OrderMessage::ListSymbol {
            id: 0,
            timestamp: 0,
            account: OPERATOR_ACCOUNT,
            symbol: symbol.to_string(),
            price_step,
            quantity_step,
            nonce: Some(nonce.to_string()),
            public_key: String::new(),
            signature: String::new(),
        };
        SubmitOperatorRequest::ListSymbol {
            symbol: symbol.to_string(),
            price_step,
            quantity_step,
            nonce: nonce.to_string(),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: operator_signature(key, session, &message),
        }
    }

    /// One `POST /operator`, from a caller on this machine.
    async fn post_operator(
        state: &Arc<Mutex<FeedState>>,
        req: SubmitOperatorRequest,
    ) -> Result<Json<SubmitResponse>, (StatusCode, String)> {
        submit_operator(
            State(Arc::clone(state)),
            Caller::from_socket("127.0.0.1:40000"),
            Ok(Json(req)),
        )
        .await
    }

    /// A key that is not the operator's is refused, and the answer names the
    /// key this sequencer does publish for. The status is 403 and not 401,
    /// because the signature is valid and the signer is the wrong one.
    #[tokio::test]
    async fn a_key_that_is_not_the_operators_is_refused() {
        let operator = logchain::ephemeral_key();
        let stranger = logchain::ephemeral_key();
        let state = feed_for(&operator);
        let session = session_of(&state);

        let (status, message) = refused(
            post_operator(
                &state,
                listing_request(&stranger, &session, "ALFA-USD", 0.01, 0.1, &nonce(0x11)),
            )
            .await,
            "a stranger cannot open a market",
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            message.contains(&logchain::to_hex(operator.verifying_key().as_bytes())),
            "the refusal names the key this feed publishes for: {}",
            message
        );
        assert_eq!(lock(&state).last_id(), 0, "and nothing was published");
    }

    /// A signature made for another history does not verify here. This is what
    /// stops a message signed against one log being replayed into another, or
    /// into this one after its database was emptied and it took a new session.
    #[tokio::test]
    async fn a_signature_made_for_another_history_is_refused() {
        let operator = logchain::ephemeral_key();
        let state = feed_for(&operator);

        let (status, _) = refused(
            post_operator(
                &state,
                listing_request(
                    &operator,
                    "0000000000000000",
                    "ALFA-USD",
                    0.01,
                    0.1,
                    &nonce(0x12),
                ),
            )
            .await,
            "a signature for another session cannot be published here",
        );
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(lock(&state).last_id(), 0, "and nothing was published");
    }

    /// A sequencer that names no operator has no such route, so the answer is
    /// 404 and not 403. The test goes through the router, because the missing
    /// route is the point.
    #[tokio::test]
    async fn a_sequencer_that_names_no_operator_serves_no_route() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        let operator = logchain::ephemeral_key();
        let session = session_of(&state);
        let body = serde_json::to_string(&serde_json::json!({
            "kind": "ListSymbol",
            "symbol": "ALFA-USD",
            "price_step": 0.01,
            "quantity_step": 0.1,
            "nonce": nonce(0x13),
            "public_key": logchain::to_hex(operator.verifying_key().as_bytes()),
            "signature": operator_signature(
                &operator,
                &session,
                &OrderMessage::ListSymbol {
                    id: 0,
                    timestamp: 0,
                    account: OPERATOR_ACCOUNT,
                    symbol: "ALFA-USD".to_string(),
                    price_step: 0.01,
                    quantity_step: 0.1,
                    nonce: Some(nonce(0x13)),
                    public_key: String::new(),
                    signature: String::new(),
                },
            ),
        }))
        .expect("a body");
        let post = |router: Router| {
            let mut request = Request::builder()
                .method(Method::POST)
                .uri("/operator")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .expect("a request");
            request
                .extensions_mut()
                .insert(axum::extract::ConnectInfo::<SocketAddr>(
                    "127.0.0.1:40000".parse().expect("a socket address"),
                ));
            router.oneshot(request)
        };

        let missing = post(feed_router(Arc::clone(&state), default_origins(), None))
            .await
            .expect("the router answers");
        assert_eq!(
            missing.status(),
            StatusCode::NOT_FOUND,
            "a sequencer with no operator key must not have this endpoint"
        );

        // The same body, on a sequencer that does name that operator.
        lock(&state).operator_key = Some(operator.verifying_key());
        let published = post(feed_router(
            Arc::clone(&state),
            default_origins(),
            Some(operator.verifying_key()),
        ))
        .await
        .expect("the router answers");
        assert_eq!(published.status(), StatusCode::OK);
    }

    /// The same signed message twice is one message, and the answer names it.
    #[tokio::test]
    async fn the_same_operator_message_cannot_become_two() {
        let operator = logchain::ephemeral_key();
        let state = feed_for(&operator);
        let session = session_of(&state);
        let spent = nonce(0x14);

        let first = post_operator(
            &state,
            listing_request(&operator, &session, "ALFA-USD", 0.01, 0.1, &spent),
        )
        .await
        .expect("the operator opens a market");
        assert_eq!(first.id, 1, "the operator writes message 1");

        let (status, message) = refused(
            post_operator(
                &state,
                listing_request(&operator, &session, "ALFA-USD", 0.01, 0.1, &spent),
            )
            .await,
            "one signed statement is one message",
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            message.contains(&spent) && message.contains("feed message 1"),
            "the refusal names the nonce and the message it already became: {}",
            message
        );
        // One guard, not two. `lock` is not reentrant, so two guards in one
        // expression would hold the first while asking for the second.
        let state = lock(&state);
        assert_eq!(
            (state.last_id(), state.next_id),
            (1, 2),
            "and the replay took no sequence number"
        );
    }

    /// What was published is the message that was signed. The bytes in the
    /// history carry the signature, and the proof for them lands on the root
    /// this sequencer signed.
    #[tokio::test]
    async fn a_published_operator_message_carries_its_signature_and_proves_into_the_root() {
        let operator = logchain::ephemeral_key();
        let state = feed_for(&operator);
        let session = session_of(&state);
        let req = listing_request(&operator, &session, "ALFA-USD", 0.01, 0.1, &nonce(0x15));
        let SubmitOperatorRequest::ListSymbol { ref signature, .. } = req else {
            panic!("it is a listing");
        };
        let signature = signature.clone();

        let published = post_operator(&state, req).await.expect("published");
        let mut state = lock(&state);
        let stored = state
            .stored_json(published.id)
            .expect("a published message");
        assert!(
            stored.contains(&signature),
            "the published bytes do not carry the operator's signature: {}",
            stored
        );
        // Those bytes read back as the kind they were published as.
        assert!(matches!(
            serde_json::from_str::<OrderMessage>(&stored).expect("this build published it"),
            OrderMessage::ListSymbol { account, .. } if account == OPERATOR_ACCOUNT
        ));

        let sth = state.signed_tree_head().expect("a head");
        let root = checked_root(&state, &sth);
        let leaf = published.id - 1;
        let path = path_of(&state.inclusion_proof(leaf, sth.tree_size).expect("a proof"));
        assert!(
            merkle::verify_entry_inclusion(leaf, sth.tree_size, stored.as_bytes(), &path, &root),
            "the operator's message does not prove into the signed root"
        );
    }

    /// A price step the matching engine cannot hold, and a symbol the rule
    /// refuses. Both answer 400, because the message is wrong whoever signed
    /// it.
    #[tokio::test]
    async fn a_message_the_rules_refuse_is_refused_before_the_key_is_looked_at() {
        let operator = logchain::ephemeral_key();
        let state = feed_for(&operator);
        let session = session_of(&state);

        // 0.001 is a tenth of a cent, which the matching engine cannot hold.
        let (status, message) = refused(
            post_operator(
                &state,
                listing_request(&operator, &session, "ALFA-USD", 0.001, 0.1, &nonce(0x16)),
            )
            .await,
            "a step off the grid cannot be listed",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("price_step"), "{}", message);

        let (status, message) = refused(
            post_operator(
                &state,
                listing_request(&operator, &session, "alfa-usd", 0.01, 0.1, &nonce(0x17)),
            )
            .await,
            "a lower-case symbol is not a symbol",
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("alfa-usd"), "{}", message);

        assert_eq!(lock(&state).last_id(), 0, "and nothing was published");
    }

    /// An operator message pins no account.
    ///
    /// `pin_or_check_account` ties an account number to a trader's key, and
    /// ties that key back to the account number. The operator publishes under
    /// `OPERATOR_ACCOUNT`, which names nobody. The operator key is not a
    /// trading account, and pinning it would turn the two into one thing.
    #[tokio::test]
    async fn publishing_an_operator_message_pins_no_account() {
        let operator = logchain::ephemeral_key();
        let state = feed_for(&operator);
        let session = session_of(&state);

        let _ = post_operator(
            &state,
            listing_request(&operator, &session, "ALFA-USD", 0.01, 0.1, &nonce(0x18)),
        )
        .await
        .expect("published");

        let state = lock(&state);
        assert!(
            state.accounts.is_empty(),
            "the operator's key was written into the account pins: {:?}",
            state.accounts.keys().collect::<Vec<_>>()
        );
    }

    /// A sequencer that names an operator generates nothing until the operator
    /// has written the complete opening, and starts after its last message.
    // Virtual time, not the clock on the wall. These two tests give the
    // generator a period of time and then say what it must have done in that
    // time. Measured against the real clock, that is a race with the machine.
    // Under a full `cargo test` the runtime may not schedule the generator
    // inside 250ms, and the test then reports that the check held the
    // generator back when nothing ran at all. It failed that way in two of
    // three runs on a loaded host.
    //
    // `start_paused` makes `tokio::time` advance only when every task is idle.
    // The period then holds exactly the ticks that fit in it, on every machine,
    // and the test finishes at once instead of sleeping.
    #[tokio::test(start_paused = true)]
    async fn a_sequencer_that_names_an_operator_publishes_nothing_until_the_log_is_opened() {
        let operator = logchain::ephemeral_key();
        let state = feed_for(&operator);

        // Three ticks at the highest rate the generator accepts: 300 messages
        // if the check were not there.
        let held = tokio::time::timeout(
            Duration::from_millis(350),
            produce_orders(Arc::clone(&state), 1000.0, None),
        );
        assert!(
            held.await.is_err(),
            "the generator runs until it is stopped"
        );
        assert_eq!(
            lock(&state).last_id(),
            0,
            "a sequencer waiting for its operator published something of its own"
        );

        // Three operator messages do not complete a four-message opening.
        let session = session_of(&state);
        for (index, symbol) in ["ALFA-USD", "BRAVO-USD", "CHARLIE-USD"]
            .into_iter()
            .enumerate()
        {
            let _ = post_operator(
                &state,
                listing_request(
                    &operator,
                    &session,
                    symbol,
                    0.01,
                    0.1,
                    &nonce(0x19 + index as u8),
                ),
            )
            .await
            .expect("the operator publishes part of the opening");
        }
        assert_eq!(lock(&state).last_id(), OPENING_MESSAGES - 1);
        let still_held = tokio::time::timeout(
            Duration::from_millis(250),
            produce_orders(Arc::clone(&state), 1000.0, None),
        );
        assert!(
            still_held.await.is_err(),
            "the generator runs until stopped"
        );
        assert_eq!(
            lock(&state).last_id(),
            OPENING_MESSAGES - 1,
            "generated traffic entered before the opening was complete"
        );

        // The fourth operator message completes the opening.
        let _ = post_operator(
            &state,
            listing_request(&operator, &session, "DELTA-USD", 0.01, 0.1, &nonce(0x1c)),
        )
        .await
        .expect("the operator completes the opening");
        let running = tokio::time::timeout(
            Duration::from_millis(250),
            produce_orders(Arc::clone(&state), 1000.0, None),
        );
        assert!(running.await.is_err(), "the generator runs until stopped");
        assert!(
            lock(&state).last_id() > OPENING_MESSAGES,
            "the generator did not start after the opening completed"
        );
    }

    /// A trader cannot occupy one of the positions reserved for the operator's
    /// opening. The signed request can be retried unchanged after the opening.
    #[tokio::test]
    async fn a_trader_waits_while_the_operator_opens_the_log() {
        let operator = logchain::ephemeral_key();
        let trader = logchain::ephemeral_key();
        let state = feed_for(&operator);

        let refused = match submit_order(
            State(Arc::clone(&state)),
            peer(),
            Ok(Json(order_request(&trader, 7, 100.25, 5.0))),
        )
        .await
        {
            Ok(_) => panic!("a trader entered the opening"),
            Err(refused) => refused,
        };
        assert_eq!(refused.0, StatusCode::SERVICE_UNAVAILABLE);
        assert!(refused.1.contains("opening"));
        assert_eq!(lock(&state).last_id(), 0);
        assert!(lock(&state).accounts.is_empty());
    }

    /// A sequencer that names no operator generates from its first tick, which
    /// is what it has always done. A check that always held would stop every
    /// sequencer started with `--rate`, including the ones
    /// `tests/crash_restart.rs` and `tests/fault_injection.rs` start.
    #[tokio::test(start_paused = true)]
    async fn a_sequencer_with_no_operator_key_generates_as_it_always_did() {
        let state = Arc::new(Mutex::new(FeedState::new(4, WALL)));
        let running = tokio::time::timeout(
            Duration::from_millis(250),
            produce_orders(Arc::clone(&state), 1000.0, None),
        );
        assert!(running.await.is_err(), "the generator runs until stopped");
        assert!(
            lock(&state).last_id() > 0,
            "a sequencer with no operator key published nothing"
        );
    }

    // -----------------------------------------------------------------------
    // The Merkle log
    //
    // The tree stands beside the chain for one commit. Both are kept up to
    // date, and every consumer still checks by the chain. These tests check
    // that the tree covers exactly the bytes the chain covers, that a client
    // can check a proof against a head this sequencer signed at any size the
    // tree has been, and that the head obeys RFC 9162's rule about its own
    // timestamp.
    // -----------------------------------------------------------------------

    /// A hash served as hex, back as bytes.
    fn hash_of(hex: &str) -> merkle::Hash {
        logchain::from_hex::<32>(hex).unwrap_or_else(|| panic!("{} is not 32 hex bytes", hex))
    }

    /// The node hashes of a proof this sequencer produced.
    fn path_of(path: &[String]) -> Vec<merkle::Hash> {
        path.iter().map(|node| hash_of(node)).collect()
    }

    /// Checks a signed tree head the way an outside reader would, from the key
    /// and the hex in the head itself. Returns the root the head covers.
    fn checked_root(state: &FeedState, sth: &SignedTreeHead) -> merkle::Hash {
        let public = VerifyingKey::from_bytes(&hash_of(&sth.public_key)).expect("a public key");
        let signature =
            Signature::from_bytes(&logchain::from_hex::<64>(&sth.signature).expect("64 hex bytes"));
        let root = hash_of(&sth.root_hash);
        assert_eq!(sth.session, state.session);
        assert!(
            logchain::verify_tree_head(
                &public,
                &sth.session,
                sth.timestamp,
                sth.tree_size,
                &root,
                &signature
            ),
            "the feed's own tree head does not verify under its own key"
        );
        root
    }

    /// A sequencer with messages `1..=total` in memory, published in one burst.
    fn published_through(total: u64) -> FeedState {
        let mut state = FeedState::new(4, WALL);
        grow_state(&mut state, 1, total);
        state
    }

    /// Publishes messages `from..=to`.
    fn grow_state(state: &mut FeedState, from: OrderId, to: OrderId) {
        let batch: Vec<OrderMessage> = (from..=to)
            .map(|id| order(id, round2(100.0 + (id % 500) as f64 / 100.0)))
            .collect();
        state.next_id = to + 1;
        state.publish_batch(batch).expect("published");
    }

    /// The same, on a sequencer behind a lock.
    fn grow(state: &Arc<Mutex<FeedState>>, from: OrderId, to: OrderId) {
        grow_state(&mut lock(state), from, to);
    }

    /// The tree a restart rebuilds from the rows is the tree the run that
    /// published them built by appending. The history here holds a message kind
    /// this build cannot parse.
    ///
    /// This is the tree's half of
    /// `a_database_holding_a_kind_this_build_cannot_read_still_starts`. A leaf
    /// is stored bytes, so the rebuild does not need to understand a message. A
    /// sequencer rolled back past a message kind still reaches the root the
    /// newer binary was signing.
    #[test]
    fn a_restart_rebuilds_the_tree_the_appends_built() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let market = market_order(3, None);
        assert!(
            serde_json::from_str::<OrderMessage>(&market).is_err(),
            "this build must genuinely not know this kind, or the test proves nothing"
        );

        let appended = {
            let mut state = open(&path, &key).expect("a new database");
            state
                .publish_batch(vec![order(1, 100.25), order(2, 100.26)])
                .expect("published");
            drop(state);
            append_stored(&path, &key, 3, &market);
            let mut state = open(&path, &key).expect("it reopens over a kind it cannot read");
            publish_next(&mut state, 100.27).expect("published");
            (
                state.tree_size(),
                state.tree_root().expect("a readable tree"),
            )
        };

        let state = open(&path, &key).expect("the same database again");
        assert_eq!(state.unreadable, 1, "one message was never parsed");
        assert_eq!(
            (
                state.tree_size(),
                state.tree_root().expect("a readable tree")
            ),
            appended,
            "and the rebuild still reaches the tree the appends built"
        );
        assert_eq!(state.tree_size(), 4);

        // The leaves really are the stored bytes. The same root comes out when
        // it is built outside the sequencer, from the rows on disk and nothing
        // else.
        let rows = stored_rows(&path);
        let bytes: Vec<&[u8]> = rows.iter().map(|(_, json, _)| json.as_bytes()).collect();
        assert_eq!(
            state.tree_root().expect("a readable tree"),
            MerkleTree::from_entries(&bytes).root(),
            "a reader with the rows and merkle.rs computes the same root"
        );
    }

    /// A history on disk, and the same messages in a `MerkleTree` built by
    /// `merkle.rs` alone.
    ///
    /// The tree in the database is the thing under test. The tree in memory is
    /// the expected answer, because the RFC 9162 tests in `merkle.rs` run
    /// against that tree.
    fn disk_and_memory(total: u64) -> (TempDir, FeedState, MerkleTree) {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, total);
        let state = open(&path, &key).expect("the same database");
        let rows = stored_rows(&path);
        let bytes: Vec<&[u8]> = rows.iter().map(|(_, json, _)| json.as_bytes()).collect();
        (dir, state, MerkleTree::from_entries(&bytes))
    }

    /// The sizes worth asking about: the small ones the RFC gives separate
    /// equations for, one below and one above two powers of two, and the ends.
    fn interesting_sizes(total: u64) -> Vec<u64> {
        let mut sizes: Vec<u64> = vec![0, 1, 2, 3, 7, 8, 9, 63, 64, 65, 127, 128, 129];
        sizes.extend([total / 2, total.saturating_sub(1), total]);
        sizes.retain(|size| *size <= total);
        sizes.sort_unstable();
        sizes.dedup();
        sizes
    }

    /// **The rule the whole change rests on.** A proof read out of
    /// `merkle_nodes` is the proof the in-memory tree gives for the same leaf
    /// and the same tree size, hash for hash, at every size and every leaf.
    ///
    /// The test does not check that both proofs verify. It checks that both are
    /// the same bytes. A disk tree that produced some other proof that looks
    /// valid would still be a different log.
    #[test]
    fn a_proof_from_disk_is_the_proof_the_in_memory_tree_gives() {
        const TOTAL: u64 = 200;
        let (_dir, state, memory) = disk_and_memory(TOTAL);
        assert!(
            matches!(state.storage, Storage::Disk { .. }),
            "this test is about the disk tree"
        );
        assert_eq!(state.tree_size(), memory.len());

        for size in interesting_sizes(TOTAL) {
            assert_eq!(
                merkle::mth(&state.storage.nodes(), size).expect("a root"),
                memory.root_at(size).expect("a root"),
                "the root at size {size}"
            );
            for leaf in 0..size {
                assert_eq!(
                    path_of(&state.inclusion_proof(leaf, size).expect("a proof")),
                    memory.inclusion_proof(leaf, size).expect("a proof"),
                    "the inclusion proof for leaf {leaf} of size {size}"
                );
            }
            for first in interesting_sizes(size) {
                assert_eq!(
                    path_of(&state.consistency_proof(first, size).expect("a proof")),
                    memory.consistency_proof(first, size).expect("a proof"),
                    "the consistency proof {first} -> {size}"
                );
            }
        }
    }

    /// A tree that cannot be written stops the message being published, because
    /// the two are one write.
    ///
    /// This asks what happens if the process stops between the two writes. There
    /// is no point between them to stop at, so the test makes the failure happen
    /// inside the transaction itself. A node insert that fails rolls back the
    /// message, the chain link, the checkpoint and the pairing with the separate
    /// service. The sequencer is left exactly where it was.
    #[test]
    fn a_node_that_cannot_be_written_publishes_nothing() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database");
        publish_next(&mut state, 100.25).expect("published");
        let (chain, root, size) = (
            state.chain,
            state.tree_root().expect("a readable tree"),
            state.tree_size(),
        );

        state
            .storage
            .conn()
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_nodes BEFORE INSERT ON merkle_nodes
                 BEGIN SELECT RAISE(ABORT, 'disk'); END;",
            )
            .unwrap();
        let refused = publish_next(&mut state, 100.26).expect_err("the node write fails");
        assert!(refused.contains("not written"), "{}", refused);

        assert_eq!(state.tree_size(), size, "no leaf without a message");
        assert_eq!(state.tree_root().expect("a readable tree"), root);
        assert_eq!(state.chain, chain, "and no message without a leaf");
        assert_eq!(state.last_id(), 1);
        assert_eq!(stored_rows(&path).len(), 1, "the row went back with it");

        // The database is not left half written. It reopens, and the tree it
        // comes back with is the one the messages make.
        drop(state);
        let state = open(&path, &key).expect("the database is intact");
        assert_eq!(state.tree_size(), 1);
        assert_eq!(state.tree_root().expect("a readable tree"), root);
    }

    /// A database written by a build that kept the tree in memory holds every
    /// message and no nodes. It opens, builds the tree from its own messages
    /// once, and serves proofs that match the in-memory tree.
    #[test]
    fn a_database_from_before_the_tree_was_stored_opens_and_proves() {
        const TOTAL: u64 = 100;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let rows = stored_rows(&path);
        let bytes: Vec<&[u8]> = rows.iter().map(|(_, json, _)| json.as_bytes()).collect();
        let memory = MerkleTree::from_entries(&bytes);

        // Such a database holds the messages and nothing else. The old build
        // had no `merkle_nodes` table at all. This build creates an empty one
        // for it on open.
        Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM merkle_nodes", [])
            .unwrap();
        assert_eq!(stored_node_count(&path), 0);

        let mut state = open(&path, &key).expect("an old database still starts");
        assert_eq!(
            stored_node_count(&path),
            tree::expected_nodes(TOTAL),
            "the nodes were built from the messages and stored"
        );
        assert_eq!(state.tree_root().expect("a readable tree"), memory.root());
        for leaf in 0..TOTAL {
            assert_eq!(
                path_of(&state.inclusion_proof(leaf, TOTAL).expect("a proof")),
                memory.inclusion_proof(leaf, TOTAL).expect("a proof"),
                "leaf {leaf} after the rebuild"
            );
        }

        // The sequencer keeps publishing on top of the tree the start built.
        publish_next(&mut state, 100.25).expect("published");
        assert_eq!(state.tree_size(), TOTAL + 1);
        assert_eq!(stored_node_count(&path), tree::expected_nodes(TOTAL + 1));
        drop(state);

        // The second start builds nothing. The count is the same, and the tree
        // is the same tree.
        let state = open(&path, &key).expect("the same database");
        assert_eq!(stored_node_count(&path), tree::expected_nodes(TOTAL + 1));
        assert_eq!(state.tree_size(), TOTAL + 1);
    }

    /// A tree the messages do not make is thrown away and built again. It is
    /// not served. A tree that is the first part of the right tree only has its
    /// missing end added.
    #[test]
    fn a_tree_that_does_not_match_its_messages_is_rebuilt_from_them() {
        const TOTAL: u64 = 40;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let root = open(&path, &key)
            .expect("the database")
            .tree_root()
            .expect("a readable tree");

        // Rows that are not the first part of any tree: the tree of 40 leaves
        // with one node missing from the middle.
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM merkle_nodes WHERE level = 0 AND idx = 5", [])
            .unwrap();
        assert_ne!(stored_node_count(&path), tree::expected_nodes(TOTAL));
        drop(conn);

        let state = open(&path, &key).expect("it starts anyway");
        assert_eq!(
            stored_node_count(&path),
            tree::expected_nodes(TOTAL),
            "the whole tree was built again from the messages"
        );
        assert_eq!(
            state.tree_root().expect("a readable tree"),
            root,
            "and it is the same tree it was"
        );
    }

    /// Writes `tree`'s nodes over the rows of `merkle_nodes`, row for row.
    ///
    /// A tree of `leaves` leaves stores one row per full subtree. Which
    /// `(level, idx)` pairs those are does not depend on the hashes under them.
    /// So this replaces every row and adds none. The row count and the highest
    /// leaf index are the two numbers the start check reads, and both come out
    /// exactly as they went in.
    fn overwrite_nodes(path: &Path, tree: &MerkleTree, leaves: u64) {
        let conn = Connection::open(path).unwrap();
        let mut level = 0u32;
        while leaves >> level > 0 {
            for idx in 0..(leaves >> level) {
                let hash = tree.node(level, idx).unwrap_or_else(|never| match never {});
                conn.execute(
                    "INSERT OR REPLACE INTO merkle_nodes (level, idx, hash) VALUES (?1, ?2, ?3)",
                    params![level, idx, hash.as_slice()],
                )
                .unwrap();
            }
            level += 1;
        }
    }

    /// **The defect the signed root exists for, written as the attack.**
    ///
    /// Nothing checked `merkle_nodes`. The start check counted rows and read the
    /// highest leaf index, and never read a hash back. The comment above it said
    /// an edited node produces a proof that does not verify. That is backwards.
    /// The root the sequencer signs is computed from those rows, so rewriting
    /// one moves the root, and every proof over the rewritten tree verifies
    /// against the root it moved to.
    ///
    /// Nothing else in the file is touched. `feed_messages`, every chain column,
    /// the session and the signed checkpoint are exactly as the sequencer left
    /// them, and every one of their own checks passes. Run against the code from
    /// before the root went into the checkpoint, this database started. `/sth`
    /// was signed over `52fc004c09ae…` where the correct root is
    /// `c180a0f44f55…`. An inclusion proof for bytes in no message verified
    /// against that signed root, and the message really published at that id did
    /// not.
    #[test]
    fn a_rewritten_leaf_cannot_move_the_root_this_feed_signs() {
        const TOTAL: u64 = 8;
        const FORGED_LEAF: u64 = 2;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);

        let before = stored_rows(&path);
        let published: Vec<&[u8]> = before.iter().map(|(_, json, _)| json.as_bytes()).collect();
        let honest = MerkleTree::from_entries(&published).root();

        // Bytes that are in no row of `feed_messages`: the same message id at a
        // price this sequencer never published.
        let forged_json = serde_json::to_string(&order(FORGED_LEAF + 1, 999.99)).unwrap();
        assert!(
            before.iter().all(|(_, json, _)| *json != forged_json),
            "the forged message must not be one the feed really published"
        );
        let mut leaves = published.clone();
        leaves[FORGED_LEAF as usize] = forged_json.as_bytes();
        let forged = MerkleTree::from_entries(&leaves);
        overwrite_nodes(&path, &forged, TOTAL);

        // That is the whole edit, and it leaves every other check with nothing
        // to report.
        assert_eq!(stored_node_count(&path), tree::expected_nodes(TOTAL));
        assert_eq!(stored_rows(&path), before, "the messages are untouched");

        let refused = refusal(
            open(&path, &key),
            "its tree is not the one its messages make",
        );
        assert!(
            refused.contains(&logchain::to_hex(&forged.root()))
                && refused.contains(&logchain::to_hex(&honest)),
            "the refusal names the root that is there and the root that was signed: {}",
            refused
        );

        // The operator's way back, and the proof that the forged tree gained
        // nothing. The tree is built again from the messages, and bytes that
        // are in no message have no proof against anything this sequencer
        // signs.
        Connection::open(&path)
            .unwrap()
            .execute("DELETE FROM merkle_nodes", [])
            .unwrap();
        let mut state = open(&path, &key).expect("the tree is built from the messages again");
        let sth = state.signed_tree_head().expect("a tree head");
        let signed = checked_root(&state, &sth);
        assert_eq!(signed, honest, "and it is the tree the messages make");
        assert_ne!(signed, forged.root());

        let proof = state.inclusion_proof(FORGED_LEAF, TOTAL).expect("a proof");
        assert!(
            !merkle::verify_entry_inclusion(
                FORGED_LEAF,
                TOTAL,
                forged_json.as_bytes(),
                &path_of(&proof),
                &signed,
            ),
            "bytes in no message must not verify against a root this feed signed"
        );
        assert!(
            merkle::verify_entry_inclusion(
                FORGED_LEAF,
                TOTAL,
                published[FORGED_LEAF as usize],
                &path_of(&proof),
                &signed,
            ),
            "and the message it really published must"
        );
        assert_eq!(state.last_id(), TOTAL);
    }

    /// The same attack one level up, on a node no leaf hash is stored under.
    ///
    /// Eleven leaves and not eight, because the root of a tree of eight is one
    /// stored node and reading it reads nothing else. At eleven the root is
    /// built from `node(3,0)` over leaves 0-7, `node(1,4)` over leaves 8-9, and
    /// leaf 10 beside them. `node(1,4)` is then an inner node the root is
    /// computed through, and this test rewrites that node. Every leaf row is
    /// left alone, so only the signed root can catch the edit.
    #[test]
    fn a_rewritten_internal_node_cannot_move_the_root_this_feed_signs() {
        const TOTAL: u64 = 11;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let honest = open(&path, &key)
            .expect("the database")
            .tree_root()
            .expect("a readable tree");
        let leaves = leaf_rows(&path);

        let conn = Connection::open(&path).unwrap();
        let replaced = conn
            .execute(
                "UPDATE merkle_nodes SET hash = ?1 WHERE level = 1 AND idx = 4",
                params![merkle::leaf_hash(b"not a node of this tree").as_slice()],
            )
            .unwrap();
        drop(conn);
        assert_eq!(replaced, 1, "one row, in place");
        assert_eq!(stored_node_count(&path), tree::expected_nodes(TOTAL));

        let refused = refusal(
            open(&path, &key),
            "its tree is not the one its messages make",
        );
        assert!(
            refused.contains(&logchain::to_hex(&honest)),
            "the refusal names the root the feed signed: {}",
            refused
        );
        assert_eq!(
            leaf_rows(&path),
            leaves,
            "every leaf still hashes its own message, so nothing but the signed root caught this"
        );
    }

    /// **What the signed root does not catch.**
    ///
    /// Reading the root reads one node for each set bit of the tree size. A node
    /// below one of those is not read at a start, and a rewrite of it is not
    /// refused. `node(1,0)` here is such a node: `node(3,0)` was built from it
    /// long ago.
    ///
    /// An attacker gains nothing from that, and this test says so. The root does
    /// not move, so the sequencer goes on signing the root its messages make. A
    /// proof that reads the rewritten node then fails against that signed root,
    /// in the hands of whoever asked for it. To make other bytes verify, the
    /// root has to move with them, and moving the root is what the checkpoint
    /// now refuses.
    ///
    /// Catching this at a start means reading every node and hashing the whole
    /// tree again. That is the pass over the history that moving the tree to
    /// disk removed. It would find an edit that can forge nothing, and it would
    /// cost a start that grows with the history.
    #[test]
    fn a_rewritten_node_the_root_is_not_read_through_cannot_forge_a_proof() {
        const TOTAL: u64 = 11;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let honest = open(&path, &key)
            .expect("the database")
            .tree_root()
            .expect("a readable tree");

        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE merkle_nodes SET hash = ?1 WHERE level = 1 AND idx = 0",
                params![merkle::leaf_hash(b"not a node of this tree").as_slice()],
            )
            .unwrap();

        let mut state = open(&path, &key).expect("the root did not move, so this start is allowed");
        let sth = state.signed_tree_head().expect("a tree head");
        let signed = checked_root(&state, &sth);
        assert_eq!(signed, honest, "and it signs the root its messages make");

        // Leaf 2's path runs through the rewritten node. The proof this
        // sequencer serves for leaf 2 does not verify against the head the
        // sequencer signed itself.
        let published = stored_rows(&path);
        let proof = state.inclusion_proof(2, TOTAL).expect("a proof");
        assert!(
            !merkle::verify_entry_inclusion(
                2,
                TOTAL,
                published[2].1.as_bytes(),
                &path_of(&proof),
                &signed,
            ),
            "a proof through a rewritten node must not verify"
        );
        // No other bytes verify against that root either. Forging needs the
        // root to move, and the root did not move.
        let forged_json = serde_json::to_string(&order(3, 999.99)).unwrap();
        assert!(!merkle::verify_entry_inclusion(
            2,
            TOTAL,
            forged_json.as_bytes(),
            &path_of(&proof),
            &signed,
        ));
    }

    /// The leaf hashes on disk, in leaf order.
    fn leaf_rows(path: &Path) -> Vec<Vec<u8>> {
        Connection::open(path)
            .unwrap()
            .prepare("SELECT hash FROM merkle_nodes WHERE level = 0 ORDER BY idx")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    /// A change to the tree's structure is a different event from a rewritten
    /// hash, and it keeps the answer it always had. Rows that form no tree these
    /// messages could make have an ordinary cause: a build with no
    /// `merkle_nodes` table at all, or an operator's `DELETE`. Those rows are
    /// built again, not refused.
    ///
    /// The rows the edit added are gone afterwards, and the root is the one the
    /// messages make. Nothing an attacker added survives this route.
    #[test]
    fn a_leaf_past_the_message_count_is_still_rebuilt_rather_than_refused() {
        const TOTAL: u64 = 8;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let honest = open(&path, &key)
            .expect("the database")
            .tree_root()
            .expect("a readable tree");

        // A ninth leaf under eight messages.
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "INSERT INTO merkle_nodes (level, idx, hash) VALUES (0, ?1, ?2)",
            params![
                TOTAL as i64,
                merkle::leaf_hash(b"a message this feed never published").as_slice()
            ],
        )
        .unwrap();
        drop(conn);
        assert_eq!(stored_node_count(&path), tree::expected_nodes(TOTAL) + 1);

        let state = open(&path, &key).expect("it starts anyway");
        assert_eq!(state.tree_size(), TOTAL, "the extra leaf is not a message");
        assert_eq!(state.tree_root().expect("a readable tree"), honest);
        assert_eq!(
            stored_node_count(&path),
            tree::expected_nodes(TOTAL),
            "and the row it added is gone"
        );
    }

    /// A database whose checkpoint was written before checkpoints carried a
    /// root. It has to start, because every deployment has one. It must not
    /// trust the tree beside it, because nothing signed says what that tree is.
    ///
    /// The second half is the downgrade attack. Remove the two fields from a
    /// checkpoint that had them, and the head signature still verifies, so a
    /// rewritten tree could come in behind an old-format row. It does not,
    /// because a tree that nothing signed for is thrown away and built again.
    #[test]
    fn a_checkpoint_from_before_the_root_still_opens_and_is_not_believed_about_the_tree() {
        const TOTAL: u64 = 8;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let rows = stored_rows(&path);
        let published: Vec<&[u8]> = rows.iter().map(|(_, json, _)| json.as_bytes()).collect();
        let honest = MerkleTree::from_entries(&published).root();

        let mut leaves = published.clone();
        let forged_json = serde_json::to_string(&order(3, 999.99)).unwrap();
        leaves[2] = forged_json.as_bytes();
        overwrite_nodes(&path, &MerkleTree::from_entries(&leaves), TOTAL);
        strip_root(&path);

        let mut state = open(&path, &key).expect("an old checkpoint still opens");
        assert_eq!(
            state.tree_root().expect("a readable tree"),
            honest,
            "the tree was built from the messages, not read off the disk"
        );
        assert_eq!(stored_node_count(&path), tree::expected_nodes(TOTAL));
        let sth = state.signed_tree_head().expect("a tree head");
        assert_eq!(checked_root(&state, &sth), honest);

        // The next publish writes a checkpoint that carries the root, so the
        // start after it reads the tree instead of building it again.
        publish_next(&mut state, 100.25).expect("published");
        drop(state);
        no_node_writes(&path);
        let state = open(&path, &key).expect("the tree is vouched for now");
        assert_eq!(state.tree_size(), TOTAL + 1);
    }

    /// The ordinary restart, which is every restart. The session, the chain and
    /// the tree come back, and not one node is written to get them.
    ///
    /// The SQLite trigger makes that last part a test and not a claim. A start
    /// that built the tree again would abort on its first insert, and the open
    /// below would fail.
    #[test]
    fn an_ordinary_restart_reads_its_tree_and_writes_no_node() {
        const TOTAL: u64 = 40;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);
        let before = open(&path, &key).expect("the database");
        let (session, chain, root) = (
            before.session.clone(),
            before.chain,
            before.tree_root().expect("a readable tree"),
        );
        drop(before);

        no_node_writes(&path);
        let state = open(&path, &key).expect("a restart writes no node");
        assert_eq!(state.session, session, "the same history");
        assert_eq!(state.chain, chain);
        assert_eq!(state.tree_size(), TOTAL);
        assert_eq!(state.tree_root().expect("a readable tree"), root);
    }

    /// Refuses every insert into `merkle_nodes` from now on. A start that builds
    /// any part of the tree then fails, instead of costing a pass over the
    /// history with no sign of it.
    fn no_node_writes(path: &Path) {
        Connection::open(path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER no_nodes BEFORE INSERT ON merkle_nodes
                 BEGIN SELECT RAISE(ABORT, 'a start that reads its tree writes no node'); END;",
            )
            .unwrap();
    }

    /// Rewrites the checkpoint the way a build from before the signed root wrote
    /// it: the head, the chain and the signature over them, and nothing about
    /// the tree.
    ///
    /// The head signature is not touched and still verifies. That is the point.
    /// This is the row an operator upgrading from that build really has, and it
    /// is also the row an attacker would leave behind to get their tree trusted.
    fn strip_root(path: &Path) {
        let conn = Connection::open(path).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT value FROM feed_meta WHERE key = 'checkpoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut checkpoint: serde_json::Value = serde_json::from_str(&stored).unwrap();
        let fields = checkpoint.as_object_mut().unwrap();
        assert!(fields.remove("root").is_some(), "there was a root to strip");
        assert!(fields.remove("root_signature").is_some());
        conn.execute(
            "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
            params![checkpoint.to_string()],
        )
        .unwrap();
    }

    /// Half a statement is not a statement. A checkpoint that holds a root with
    /// no signature over it, or a signature with no root, is a row no publish
    /// wrote.
    #[test]
    fn a_checkpoint_holding_half_the_root_statement_is_refused() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, 4);

        for field in ["root", "root_signature"] {
            let conn = Connection::open(&path).unwrap();
            let stored: String = conn
                .query_row(
                    "SELECT value FROM feed_meta WHERE key = 'checkpoint'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let mut checkpoint: serde_json::Value = serde_json::from_str(&stored).unwrap();
            let kept = checkpoint.clone();
            checkpoint.as_object_mut().unwrap().remove(field).unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
                params![checkpoint.to_string()],
            )
            .unwrap();
            drop(conn);

            let refused = refusal(open(&path, &key), "half a checkpoint is not one");
            assert!(
                refused.contains("written to by something other than the feed"),
                "removing {}: {}",
                field,
                refused
            );

            // Put it back for the next half.
            Connection::open(&path)
                .unwrap()
                .execute(
                    "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
                    params![kept.to_string()],
                )
                .unwrap();
        }
        open(&path, &key).expect("and the whole checkpoint still opens");
    }

    /// The root is signed, not only stored. An edit to the root in the
    /// checkpoint is refused by the signature over it. It is not refused by the
    /// comparison against the tree, because an attacker can make that
    /// comparison pass.
    #[test]
    fn an_edited_root_in_the_checkpoint_is_refused_by_its_own_signature() {
        const TOTAL: u64 = 8;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, TOTAL);

        // The root of the tree the attacker wants served, written into the
        // checkpoint beside the tree that makes it. Both halves agree. Only the
        // signature disagrees.
        let rows = stored_rows(&path);
        let mut leaves: Vec<&[u8]> = rows.iter().map(|(_, json, _)| json.as_bytes()).collect();
        let forged_json = serde_json::to_string(&order(3, 999.99)).unwrap();
        leaves[2] = forged_json.as_bytes();
        let forged = MerkleTree::from_entries(&leaves);
        overwrite_nodes(&path, &forged, TOTAL);

        let conn = Connection::open(&path).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT value FROM feed_meta WHERE key = 'checkpoint'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut checkpoint: serde_json::Value = serde_json::from_str(&stored).unwrap();
        checkpoint["root"] = logchain::to_hex(&forged.root()).into();
        conn.execute(
            "INSERT OR REPLACE INTO feed_meta (key, value) VALUES ('checkpoint', ?1)",
            params![checkpoint.to_string()],
        )
        .unwrap();
        drop(conn);

        let refused = refusal(open(&path, &key), "the root was edited after it was signed");
        assert!(
            refused.contains("is not signed by this feed's key"),
            "{}",
            refused
        );
    }

    /// How many rows the tree takes on disk.
    fn stored_node_count(path: &Path) -> u64 {
        tree::stored_nodes(&Connection::open(path).unwrap()).unwrap()
    }

    /// The memory the tree costs a running sequencer, whatever the history is:
    /// one number, and no `MerkleTree` anywhere.
    ///
    /// A history's tree in RAM used to be `2n` hashes: 12.8 MB at 134,500
    /// messages, built again at every start. A sequencer now holds the leaf
    /// count. This test checks that by looking at the type, not at a
    /// measurement. The numbers are in the note on `with_db`.
    #[test]
    fn the_tree_a_running_feed_holds_is_one_number() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        long_history(&path, &key, PAST_WINDOW);
        let state = open(&path, &key).expect("the same database");
        match &state.storage {
            Storage::Disk { leaves, .. } => assert_eq!(*leaves, PAST_WINDOW),
            Storage::Memory(_) => panic!("a feed with a database must not hold its tree in RAM"),
        }
        assert_eq!(
            stored_node_count(&path),
            tree::expected_nodes(PAST_WINDOW),
            "every node is on disk"
        );
        // Two rows for each message, and never more. That is the disk cost paid
        // for the memory saved.
        assert!(stored_node_count(&path) < 2 * PAST_WINDOW);
    }

    /// What an append and a proof cost on a history of 100,000 messages,
    /// measured and not estimated.
    ///
    /// ```text
    /// cargo test --release -- --ignored --nocapture measures_
    /// ```
    ///
    /// Ignored because it writes 100,000 messages and takes a few seconds, and
    /// because a number from a debug build would only describe `debug`. It is
    /// here and not in a benchmark harness so that it uses the same `sequence`
    /// and the same `inclusion_proof` the sequencer serves from, with nothing
    /// replaced by a stub and the real transaction and its fsync included.
    ///
    /// The two append figures answer different questions. A message published on
    /// its own pays a whole transaction, so one fsync, and that fsync is most of
    /// the cost. A message published inside a burst of 100 shares one fsync with
    /// 99 others. The generator publishes in bursts at any rate above ten a
    /// second, and that is where the cost of writing the tree's rows shows.
    #[test]
    #[ignore = "writes 100,000 messages; run it with --release"]
    fn measures_an_append_and_a_proof_on_a_hundred_thousand_messages() {
        const TOTAL: u64 = 100_000;
        const BURST: u64 = 100;
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let mut state = open(&path, &key).expect("a new database");

        let building = Instant::now();
        let mut bursts = Vec::new();
        let mut next = 1;
        while next <= TOTAL {
            let batch: Vec<OrderMessage> = (next..next + BURST)
                .map(|id| order(id, round2(100.0 + (id % 500) as f64 / 100.0)))
                .collect();
            state.next_id = next + BURST;
            let started = Instant::now();
            state.publish_batch(batch).expect("published");
            bursts.push(started.elapsed().as_micros());
            next += BURST;
        }
        let built = building.elapsed();

        let mut appends = Vec::new();
        for _ in 0..200 {
            let started = Instant::now();
            publish_next(&mut state, 100.25).expect("published");
            appends.push(started.elapsed().as_micros());
        }
        let size = state.last_id();

        let mut proofs = Vec::new();
        let mut lengths = Vec::new();
        for step in 0..1000u64 {
            let leaf = (step * 97 + step * step) % size;
            let started = Instant::now();
            let path = state.inclusion_proof(leaf, size).expect("a proof");
            proofs.push(started.elapsed().as_micros());
            lengths.push(path.len());
        }
        let mut consistency = Vec::new();
        for step in 0..1000u64 {
            let first = 1 + (step * 89) % (size - 1);
            let started = Instant::now();
            state.consistency_proof(first, size).expect("a proof");
            consistency.push(started.elapsed().as_micros());
        }

        drop(state);
        let opening = Instant::now();
        let state = open(&path, &key).expect("the same database");
        let reopened = opening.elapsed();
        assert_eq!(state.last_id(), size);
        drop(state);

        let bytes = std::fs::metadata(&path).unwrap().len();
        let messages: u64 = Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM feed_messages", [], |row| row.get(0))
            .unwrap();
        println!(
            "\n{messages} messages, built in {:?}, reopened in {:?}\n\
             one append alone (its own transaction and fsync): {} us median, {} us p95\n\
             one append inside a burst of {BURST}: {} us median\n\
             one inclusion proof: {} us median, {} us p95, {} nodes at most\n\
             one consistency proof: {} us median, {} us p95\n\
             {bytes} bytes on disk, {} bytes a message\n",
            built,
            reopened,
            median(&mut appends),
            p95(&mut appends),
            median(&mut bursts) / BURST as u128,
            median(&mut proofs),
            p95(&mut proofs),
            lengths.iter().max().unwrap(),
            median(&mut consistency),
            p95(&mut consistency),
            bytes / messages,
        );
    }

    fn median(samples: &mut [u128]) -> u128 {
        samples.sort_unstable();
        samples[samples.len() / 2]
    }

    fn p95(samples: &mut [u128]) -> u128 {
        samples.sort_unstable();
        samples[samples.len() * 95 / 100]
    }

    /// Every message in a real history has an inclusion proof that verifies
    /// against the root the sequencer signed, from the bytes the sequencer
    /// serves.
    #[test]
    fn an_inclusion_proof_verifies_for_every_message_in_a_history() {
        const TOTAL: u64 = 300;
        let mut state = published_through(TOTAL);
        let sth = state.signed_tree_head().expect("a head");
        let root = checked_root(&state, &sth);
        assert_eq!(sth.tree_size, TOTAL, "one leaf per published message");

        for leaf in 0..sth.tree_size {
            let path = path_of(&state.inclusion_proof(leaf, sth.tree_size).expect("a proof"));
            // The entry is the byte string `/messages.ndjson` serves for this
            // message, which is the only form a client has of it.
            let entry = state.stored_json(leaf + 1).expect("a published message");
            assert!(
                merkle::verify_entry_inclusion(leaf, sth.tree_size, entry.as_bytes(), &path, &root),
                "message {} does not prove into the signed root",
                leaf + 1
            );

            // Change one byte and the same proof is refused. That is what makes
            // the proof a statement about this message, and not about the
            // tree's structure.
            let edited = entry.replace("\"quantity\":5.0", "\"quantity\":6.0");
            assert_ne!(edited, entry);
            assert!(
                !merkle::verify_entry_inclusion(
                    leaf,
                    sth.tree_size,
                    edited.as_bytes(),
                    &path,
                    &root
                ),
                "an edited message {} still proved into the root",
                leaf + 1
            );
        }
    }

    /// A consistency proof between two heads this sequencer really signed.
    ///
    /// This proof will replace the chain. It says the older tree is the first
    /// part of the newer one: messages were added, and none was changed,
    /// removed or moved. It says that in `log2(n)` hashes, where hashing the
    /// chain again says it in `n` messages.
    #[test]
    fn a_consistency_proof_between_two_signed_tree_heads_verifies() {
        let mut state = published_through(137);
        let old = state.signed_tree_head().expect("a head");
        let old_root = checked_root(&state, &old);
        grow_state(&mut state, 138, 400);
        let new = state.signed_tree_head().expect("a head");
        let new_root = checked_root(&state, &new);
        assert_eq!((old.tree_size, new.tree_size), (137, 400));
        assert_ne!(old_root, new_root);

        let path = path_of(
            &state
                .consistency_proof(old.tree_size, new.tree_size)
                .expect("a proof"),
        );
        assert!(merkle::verify_consistency(
            old.tree_size,
            new.tree_size,
            &old_root,
            &new_root,
            &path
        ));
        // A proof means something only against the two roots it was made for.
        assert!(!merkle::verify_consistency(
            old.tree_size,
            new.tree_size,
            &merkle::empty_root(),
            &new_root,
            &path
        ));
        assert!(!merkle::verify_consistency(
            old.tree_size,
            new.tree_size,
            &old_root,
            &old_root,
            &path
        ));

        // The two sizes RFC 9162 leaves undefined. A running sequencer meets
        // both: the state before the first message, and a poll that found
        // nothing new.
        assert!(
            state
                .consistency_proof(0, new.tree_size)
                .expect("a proof")
                .is_empty()
        );
        assert!(merkle::verify_consistency(
            0,
            new.tree_size,
            &merkle::empty_root(),
            &new_root,
            &[]
        ));
        assert!(
            state
                .consistency_proof(new.tree_size, new.tree_size)
                .expect("a proof")
                .is_empty()
        );
        assert!(merkle::verify_consistency(
            new.tree_size,
            new.tree_size,
            &new_root,
            &new_root,
            &[]
        ));
    }

    /// A proof for a tree size the sequencer has grown past verifies against the
    /// root the sequencer signed at that size, and not against the newest root.
    ///
    /// This is why `tree_size` is a required parameter and never falls back to
    /// the current tree. A client that holds a head from an hour ago has that
    /// head's root and nothing else to check against. This sequencer publishes
    /// several messages a second, so the current tree would already be a
    /// different tree by the time the answer arrived.
    #[test]
    fn a_proof_for_a_historical_tree_size_verifies_against_the_root_signed_then() {
        const LEAF: u64 = 7;
        let mut state = published_through(100);
        let old = state.signed_tree_head().expect("a head");
        let old_root = checked_root(&state, &old);
        grow_state(&mut state, 101, 250);
        let new = state.signed_tree_head().expect("a head");
        let new_root = checked_root(&state, &new);

        let entry = state.stored_json(LEAF + 1).expect("a published message");
        let old_path = path_of(&state.inclusion_proof(LEAF, old.tree_size).expect("a proof"));
        let new_path = path_of(&state.inclusion_proof(LEAF, new.tree_size).expect("a proof"));
        assert_ne!(old_path, new_path, "two trees, two proofs");

        assert!(
            merkle::verify_entry_inclusion(
                LEAF,
                old.tree_size,
                entry.as_bytes(),
                &old_path,
                &old_root
            ),
            "the head this client kept is still checkable an hour later"
        );
        assert!(
            !merkle::verify_entry_inclusion(
                LEAF,
                old.tree_size,
                entry.as_bytes(),
                &old_path,
                &new_root
            ),
            "and it is the root signed at that size, not the newest root"
        );
        assert!(merkle::verify_entry_inclusion(
            LEAF,
            new.tree_size,
            entry.as_bytes(),
            &new_path,
            &new_root
        ));

        // A size this sequencer has not reached is refused. It is not answered
        // against whatever size the sequencer does hold.
        assert!(
            matches!(
                state.inclusion_proof(LEAF, new.tree_size + 1),
                Err(TreeError::Proof(merkle::ProofError::UnknownTreeSize { tree_size, have }))
                    if tree_size == new.tree_size + 1 && have == new.tree_size
            ),
            "a size this feed has not reached is the caller's error, not the tree's"
        );
    }

    /// RFC 9162 requires each tree head's timestamp to be later than the one
    /// before it, so that an old tree cannot be served as the current one.
    ///
    /// The clock counts milliseconds, and this sequencer publishes faster than
    /// that. The rule therefore has to hold for a burst inside one millisecond.
    /// It does, because two heads with the same time make the second one take
    /// the next millisecond.
    #[test]
    fn each_signed_tree_head_is_later_than_the_one_before_it() {
        let mut state = FeedState::new(4, WALL);
        let mut heads = Vec::new();
        for _ in 0..256 {
            publish_next(&mut state, 100.25).expect("published");
            heads.push(state.signed_tree_head().expect("a head"));
        }
        for pair in heads.windows(2) {
            assert!(pair[1].tree_size > pair[0].tree_size, "the tree only grows");
            assert!(
                pair[1].timestamp > pair[0].timestamp,
                "the head at size {} is dated {} and the one before it {}",
                pair[1].tree_size,
                pair[1].timestamp,
                pair[0].timestamp
            );
        }
        assert!(
            heads[255].timestamp >= WALL + 255,
            "256 publishes take far less than 256 milliseconds, so most of these \
             timestamps came from the tie break rather than from the clock"
        );
    }

    /// A head that nothing has changed under is served again, not signed again.
    ///
    /// Without this, a sequencer that answers a thousand reads in one
    /// millisecond would have to date a thousand heads one millisecond apart to
    /// keep the rule above. Its own timestamps would then run days into the
    /// future. This also saves one Ed25519 signature for each read, taken under
    /// the state lock the generator publishes under.
    #[test]
    fn a_tree_head_is_not_signed_again_while_nothing_has_changed() {
        let mut state = published_through(40);
        let heads: Vec<SignedTreeHead> = (0..1_000)
            .map(|_| state.signed_tree_head().expect("a head"))
            .collect();
        let mut stamps: Vec<u64> = heads.iter().map(|head| head.timestamp).collect();
        stamps.dedup();
        assert!(
            stamps.len() < 10,
            "a thousand reads with nothing published between them produced {} different heads",
            stamps.len()
        );
        for head in &heads {
            assert_eq!(head.tree_size, 40);
            checked_root(&state, head);
        }
    }

    /// The float rule, at the leaf.
    ///
    /// A price of 100.0 is `100.0` in the bytes the sequencer stored, so it is
    /// `100.0` in the leaf. A browser that parsed the message and serialized it
    /// again before hashing would write `100`. It would compute a different
    /// leaf, and report a working sequencer as one that rewrote its history. See
    /// the note on `get_messages_ndjson`, the endpoint that exists for this.
    #[test]
    fn a_price_of_100_is_still_100_in_the_leaf_bytes() {
        let mut state = FeedState::new(4, WALL);
        publish_next(&mut state, 100.0).expect("published");
        let stored = state.stored_json(1).expect("a published message");
        assert!(stored.contains("\"price\":100.0"), "{}", stored);
        assert_eq!(
            merkle::NodeSource::node(&state.storage.nodes(), 0, 0).expect("leaf 0"),
            merkle::leaf_hash(stored.as_bytes()),
            "the leaf is the stored bytes with RFC 9162's 0x00 in front, and nothing else"
        );

        // What `JSON.stringify` writes for the same number.
        let restringified = stored.replace("\"price\":100.0", "\"price\":100");
        assert_ne!(restringified, stored);
        assert_ne!(
            merkle::leaf_hash(restringified.as_bytes()),
            merkle::leaf_hash(stored.as_bytes()),
            "same number, different bytes, different leaf"
        );

        let sth = state.signed_tree_head().expect("a head");
        let root = checked_root(&state, &sth);
        assert!(merkle::verify_entry_inclusion(
            0,
            1,
            stored.as_bytes(),
            &[],
            &root
        ));
        assert!(
            !merkle::verify_entry_inclusion(0, 1, restringified.as_bytes(), &[], &root),
            "so a page that re-serialized before hashing would fail against an honest feed"
        );
    }

    /// One GET the router answers, from a caller on this machine.
    async fn served(state: &Arc<Mutex<FeedState>>, uri: &str) -> Response {
        feed_router(Arc::clone(state), default_origins(), None)
            .oneshot(local_request(uri))
            .await
            .expect("the router answers")
    }

    /// The JSON body of an answer that must have been a 200.
    async fn json_body(response: Response) -> serde_json::Value {
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&body_of(response).await).expect("a JSON body")
    }

    /// The node hashes of a proof served as JSON.
    fn hashes_in(path: &serde_json::Value) -> Vec<merkle::Hash> {
        path.as_array()
            .expect("a proof is an array")
            .iter()
            .map(|node| hash_of(node.as_str().expect("a node hash is hex")))
            .collect()
    }

    /// `GET /sth` serves a head an outside reader can check with nothing but the
    /// response. No cache may keep that answer.
    #[tokio::test]
    async fn the_sth_endpoint_serves_a_head_that_verifies_and_is_never_cached() {
        let state = feed_holding(2_500);
        let response = served(&state, "/sth").await;
        let headers = headers_of(&response);
        assert_eq!(
            headers[header::CACHE_CONTROL.as_str()],
            OPEN_CACHE_CONTROL,
            "this is where a caller asks where the feed stands, so a cached answer is a wrong one"
        );
        let body = json_body(response).await;

        let (session, public, root) = {
            let guard = lock(&state);
            (
                guard.session.clone(),
                guard.signing_key.verifying_key(),
                guard.tree_root().expect("a readable tree"),
            )
        };
        assert_eq!(body["session"], session);
        assert_eq!(body["tree_size"], 2_500);
        assert_eq!(body["root_hash"], logchain::to_hex(&root));
        assert_eq!(body["public_key"], logchain::to_hex(public.as_bytes()));

        let timestamp = body["timestamp"]
            .as_u64()
            .expect("milliseconds, as a number");
        assert!(timestamp >= WALL, "milliseconds since the Unix epoch");
        let signature = Signature::from_bytes(
            &logchain::from_hex::<64>(body["signature"].as_str().expect("hex"))
                .expect("64 hex bytes"),
        );
        assert!(logchain::verify_tree_head(
            &public, &session, timestamp, 2_500, &root, &signature
        ));
    }

    /// The two proof endpoints, end to end, checked the way a browser would.
    /// Read a head, ask for the proof it names, then verify against that head's
    /// root and the bytes `/messages.ndjson` serves.
    #[tokio::test]
    async fn the_proof_endpoints_answer_what_the_signed_heads_name() {
        let state = feed_holding(1_000);
        let old = json_body(served(&state, "/sth").await).await;
        grow(&state, 1_001, 2_500);
        let new = json_body(served(&state, "/sth").await).await;
        assert_eq!(old["tree_size"], 1_000);
        assert_eq!(new["tree_size"], 2_500);
        let old_root = hash_of(old["root_hash"].as_str().expect("hex"));
        let new_root = hash_of(new["root_hash"].as_str().expect("hex"));

        let proof =
            json_body(served(&state, "/proof/inclusion?leaf=1233&tree_size=2500").await).await;
        assert_eq!(proof["session"], new["session"]);
        assert_eq!(proof["leaf_index"], 1233);
        assert_eq!(proof["message_id"], 1234, "leaf n is message n + 1");
        assert_eq!(proof["tree_size"], 2_500);
        let entry = lock(&state).stored_json(1234).expect("a published message");
        assert!(merkle::verify_entry_inclusion(
            1233,
            2_500,
            entry.as_bytes(),
            &hashes_in(&proof["inclusion_path"]),
            &new_root
        ));

        // A message the older head already covered, against that older head.
        let older_entry = lock(&state).stored_json(234).expect("a published message");
        let earlier =
            json_body(served(&state, "/proof/inclusion?leaf=233&tree_size=1000").await).await;
        assert_eq!(earlier["message_id"], 234);
        assert!(merkle::verify_entry_inclusion(
            233,
            1_000,
            older_entry.as_bytes(),
            &hashes_in(&earlier["inclusion_path"]),
            &old_root
        ));

        // A message published after that head cannot prove into it. The tree
        // the request names does not hold that leaf.
        let response = served(&state, "/proof/inclusion?leaf=1233&tree_size=1000").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            String::from_utf8(body_of(response).await)
                .expect("text")
                .contains("leaf 1233 is outside a tree of size 1000")
        );

        // The two heads are one history. The older tree is the first part of
        // the newer one.
        let between =
            json_body(served(&state, "/proof/consistency?first=1000&second=2500").await).await;
        assert_eq!(between["first"], 1_000);
        assert_eq!(between["second"], 2_500);
        assert!(merkle::verify_consistency(
            1_000,
            2_500,
            &old_root,
            &new_root,
            &hashes_in(&between["consistency_path"])
        ));
    }

    /// A proof for a tree size below the head can never change. It is cached
    /// forever and carries an ETag, exactly as a closed page is. A proof for
    /// the size the tree has right now names the head, and this sequencer
    /// caches nothing that names the head.
    #[tokio::test]
    async fn a_proof_below_the_head_is_immutable_and_one_at_the_head_is_not() {
        let state = feed_holding(2_500);

        for uri in [
            "/proof/inclusion?leaf=0&tree_size=2500",
            "/proof/consistency?first=10&second=2500",
        ] {
            let headers = headers_of(&served(&state, uri).await);
            assert_eq!(headers[header::CACHE_CONTROL.as_str()], OPEN_CACHE_CONTROL);
            assert!(
                !headers.contains_key(header::ETAG.as_str()),
                "{} is not a stored answer, so it has no validator",
                uri
            );
        }

        let response = served(&state, "/proof/inclusion?leaf=0&tree_size=2499").await;
        let headers = headers_of(&response);
        assert_eq!(
            headers[header::CACHE_CONTROL.as_str()],
            "public, max-age=31536000, immutable"
        );
        let etag = headers[header::ETAG.as_str()].clone();
        assert!(etag.contains("inclusion"), "{}", etag);
        assert_ne!(
            etag,
            headers_of(&served(&state, "/proof/inclusion?leaf=1&tree_size=2499").await)
                [header::ETAG.as_str()],
            "a different proof is a different validator"
        );

        // A client that kept that ETag is answered 304 with no body, exactly
        // as it would be for a closed page.
        let again = feed_router(Arc::clone(&state), default_origins(), None)
            .oneshot({
                let mut request = local_request("/proof/inclusion?leaf=0&tree_size=2499");
                request.headers_mut().insert(
                    header::IF_NONE_MATCH,
                    HeaderValue::from_str(&etag).expect("a header value"),
                );
                request
            })
            .await
            .expect("the router answers");
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            headers_of(&again)[header::ETAG.as_str()],
            etag,
            "the 304 repeats the validator, or a cache drops the entry"
        );
        assert!(body_of(again).await.is_empty());

        // The proof is produced before the 304 is answered. A forged ETag on a
        // leaf that does not exist is therefore refused, and is not told that
        // nothing has changed.
        let forged = feed_router(Arc::clone(&state), default_origins(), None)
            .oneshot({
                let mut request = local_request("/proof/inclusion?leaf=99999&tree_size=2499");
                request
                    .headers_mut()
                    .insert(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
                request
            })
            .await
            .expect("the router answers");
        assert_eq!(forged.status(), StatusCode::BAD_REQUEST);

        let headers = headers_of(&served(&state, "/proof/consistency?first=10&second=2499").await);
        assert_eq!(
            headers[header::CACHE_CONTROL.as_str()],
            "public, max-age=31536000, immutable"
        );
        assert!(
            headers[header::ETAG.as_str()].contains("consistency"),
            "the two proofs cannot share a validator: {:?}",
            headers[header::ETAG.as_str()]
        );
    }

    /// What the proof endpoints refuse, and what they say when they do.
    #[tokio::test]
    async fn a_proof_this_feed_cannot_produce_is_refused_by_name() {
        let state = feed_holding(100);
        for (uri, expected) in [
            (
                "/proof/inclusion?leaf=0&tree_size=101",
                "tree size 101 requested, tree holds 100",
            ),
            (
                "/proof/inclusion?leaf=100&tree_size=100",
                "leaf 100 is outside a tree of size 100",
            ),
            (
                "/proof/consistency?first=50&second=101",
                "tree size 101 requested, tree holds 100",
            ),
            (
                "/proof/consistency?first=60&second=50",
                "consistency asked from 60 back to 50",
            ),
        ] {
            let response = served(&state, uri).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{}", uri);
            let body = String::from_utf8(body_of(response).await).expect("text");
            assert!(body.contains(expected), "{} answered: {}", uri, body);
            assert!(
                body.contains("its tree holds 100 messages"),
                "a refusal says what this feed does hold: {}",
                body
            );
        }

        // `tree_size` is required. Without it the request names no tree, and
        // there is no correct tree to answer for. Not the newest tree, because
        // the caller has no signed head for it. And not a guess.
        let response = served(&state, "/proof/inclusion?leaf=0").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = String::from_utf8(body_of(response).await).expect("text");
        assert!(body.contains("tree_size"), "{}", body);
    }

    /// Nothing above changes the chain. Every consumer still checks with the
    /// chain, so the chain has to keep answering exactly as it did.
    #[test]
    fn the_chain_still_stands_beside_the_tree() {
        let dir = TempDir::new().unwrap();
        let (path, key) = feed_at(&dir);
        let published = {
            let mut state = open(&path, &key).expect("a new database");
            grow_state(&mut state, 1, 50);
            (
                state.chain,
                state.signed_head().chain,
                state.tree_root().expect("a readable tree"),
            )
        };

        let state = open(&path, &key).expect("the same database");
        assert_eq!(state.chain, published.0, "the chain reloads as it did");
        assert_eq!(state.signed_head().chain, published.1);
        assert_eq!(state.tree_root().expect("a readable tree"), published.2);
        assert_eq!(
            state.chain,
            window_chain(&state.messages),
            "and it is still the fold over the stored bytes"
        );
        assert_eq!(
            state.tree_size(),
            state.last_id(),
            "one leaf per message, and the two commitments cover the same history"
        );
    }
    // ---------------------------------------------------------------------
    // Throughput. How many messages a second this sequencer publishes.
    //
    //   cargo test --release -- --ignored --nocapture publishes_
    //
    // Ignored because a number from a debug build only describes `debug`, and
    // because these tests write hundreds of thousands of messages. Nothing is
    // replaced by a stub. They call `publish_batch`, so they time the whole
    // publish: take the ids, serialize each message once, hash the chain over
    // those bytes, hash the leaves, insert the rows, append the tree's nodes,
    // read the root back, sign the checkpoint, commit, fsync.
    // ---------------------------------------------------------------------

    /// Where the throughput tests put the database, and why it is not where
    /// every other test puts one.
    ///
    /// `TempDir::new` writes under `/tmp`, and on this machine `/tmp` is a
    /// tmpfs. One 4 KiB write and fsync costs 0.9 us there and 1,723 us on the
    /// ext4 file system the repository sits on. That is 1.07 million fsyncs a
    /// second against 580. A publish rate measured on a tmpfs leaves out the one
    /// cost these tests exist to measure.
    ///
    /// So the database goes under the crate's `target` directory, which is on
    /// the same file system as the repository, unless `VX_BENCH_DIR` names
    /// another directory. Every test below prints the path it used, because a
    /// publish rate without a named file system is not a measurement.
    fn bench_dir() -> TempDir {
        let parent = std::env::var("VX_BENCH_DIR")
            .unwrap_or_else(|_| format!("{}/target", env!("CARGO_MANIFEST_DIR")));
        std::fs::create_dir_all(&parent).expect("the benchmark directory exists");
        TempDir::new_in(&parent).expect("a directory on a real file system")
    }

    /// A burst of `count` generated orders, ids starting at `first`.
    fn bench_burst(first: OrderId, count: u64) -> Vec<OrderMessage> {
        (first..first + count)
            .map(|id| order(id, generate::round2(100.0 + (id % 500) as f64 / 100.0)))
            .collect()
    }

    /// Publishes `total` messages `burst` at a time and returns how long that
    /// took. `state.next_id` is moved by hand, the way a live caller moves it
    /// before it builds the messages.
    fn bench_publish(state: &mut FeedState, total: u64, burst: u64) -> Duration {
        let mut next = state.next_id;
        let stop = next + total;
        let started = Instant::now();
        while next < stop {
            let batch = bench_burst(next, burst);
            state.next_id = next + burst;
            state.publish_batch(batch).expect("published");
            next += burst;
        }
        started.elapsed()
    }

    /// Messages a second, from a count and how long it took.
    fn bench_per_second(messages: u64, elapsed: Duration) -> f64 {
        messages as f64 / elapsed.as_secs_f64()
    }

    /// How the publish rate changes with the size of the burst.
    ///
    /// One transaction carries a whole burst and costs one fsync. A burst of
    /// 1,000 pays one fsync for 1,000 messages, and a burst of 1 pays one fsync
    /// for each message. These numbers show where the limit is, and one rate on
    /// its own would hide it.
    ///
    /// Three sequencers are timed at every burst size, so the disk's share and
    /// the processor's share are separate numbers:
    ///
    /// - **on disk**: `feed.db` on a real file, with the pragmas this repository
    ///   uses, `journal_mode = WAL` and `synchronous = FULL`, so every commit
    ///   really reaches the disk.
    /// - **in RAM**: the same `publish_batch` on a sequencer built with
    ///   `FeedState::new`, which holds its tree in memory and writes nothing.
    ///   Same serialization, same chain hashing, same leaf hashes, no database.
    /// - **hashing alone**: serialize, hash the chain, hash the leaf, and
    ///   nothing else. No part of a publish can go faster than this.
    #[test]
    #[ignore = "publishes about a million messages to disk; run it with --release"]
    fn publishes_faster_as_the_burst_grows() {
        let where_from = bench_dir();
        println!("\ndatabases under {}", where_from.path().display());
        for (burst, total) in [
            (1u64, 2_000u64),
            (10, 10_000),
            (100, 50_000),
            (1_000, 200_000),
            (10_000, 200_000),
        ] {
            let dir = bench_dir();
            let (path, key) = feed_at(&dir);
            let mut on_disk = open(&path, &key).expect("a new database");
            let disk = bench_publish(&mut on_disk, total, burst);
            drop(on_disk);
            let bytes = std::fs::metadata(&path).unwrap().len();

            let mut in_ram = FeedState::new(4, WALL);
            let ram = bench_publish(&mut in_ram, total, burst);
            drop(in_ram);

            println!(
                "burst {:>6} ({:>6} transactions for {:>7} messages): on disk {:>9.0} a second, \
                 in RAM {:>9.0} a second, {} bytes a message on disk",
                burst,
                total / burst,
                total,
                bench_per_second(total, disk),
                bench_per_second(total, ram),
                bytes / total,
            );
        }

        // Hashing alone. No storage of any kind. This is what one message costs
        // before anything is written down.
        const FOLD: u64 = 200_000;
        let messages = bench_burst(1, FOLD);
        let mut chain = EMPTY_CHAIN;
        let started = Instant::now();
        for msg in &messages {
            let json = serde_json::to_string(msg).expect("a message serializes");
            chain = logchain::extend_bytes(&chain, json.as_bytes());
            std::hint::black_box(merkle::leaf_hash(json.as_bytes()));
        }
        let folding = started.elapsed();
        std::hint::black_box(chain);
        println!(
            "serialize, fold the chain and hash the leaf, with no storage at all: \
             {:.0} a second, {:.3} us a message",
            bench_per_second(FOLD, folding),
            folding.as_secs_f64() * 1e6 / FOLD as f64,
        );
        println!();
    }

    /// Whether the publish rate holds, run long enough for the WAL to be
    /// checkpointed several times over.
    ///
    /// This test needs a rate that a full disk cannot end. The published history
    /// is never pruned, and `feed.db` keeps every message forever. A run at
    /// 100,000 messages a second would write about 25 MB a second, and no disk
    /// this program will meet could hold that for a minute. So the test
    /// **deletes the message rows behind the writer**. Everything older than the
    /// newest `KEEP` messages is removed after every burst, SQLite reuses the
    /// freed pages, and the message part of the file stops growing.
    ///
    /// Deleting is work the live sequencer does not do. It is timed on its own,
    /// reported on its own, and not counted in the publish rate.
    ///
    /// The Merkle tree is **not** deleted. `tree::root` reads the nodes back out
    /// of `merkle_nodes` on every publish, so removing a node would break the
    /// checkpoint the burst is signing. The tree writes about two rows for each
    /// message, and the growth this test reports is the tree's growth and
    /// nothing else.
    #[test]
    #[ignore = "publishes for a minute and deletes behind itself; run it with --release"]
    fn publishes_at_a_flat_rate_for_a_minute() {
        const BURST: u64 = 1_000;
        const KEEP: u64 = 20_000;
        const RUN: Duration = Duration::from_secs(60);
        const BUCKET: Duration = Duration::from_secs(5);

        let dir = bench_dir();
        let (path, key) = feed_at(&dir);
        println!("\ndatabase at {}", path.display());
        let mut state = open(&path, &key).expect("a new database");
        let opening_bytes = std::fs::metadata(&path).unwrap().len();

        let mut published = 0u64;
        let mut deleted = 0u64;
        let mut publishing = Duration::ZERO;
        let mut deleting = Duration::ZERO;
        let mut buckets: Vec<(u64, Duration)> = Vec::new();
        let mut bucket_messages = 0u64;
        let mut bucket_started = Instant::now();
        let run_started = Instant::now();

        while run_started.elapsed() < RUN {
            let next = state.next_id;
            let batch = bench_burst(next, BURST);
            state.next_id = next + BURST;
            let started = Instant::now();
            state.publish_batch(batch).expect("published");
            publishing += started.elapsed();
            published += BURST;
            bucket_messages += BURST;

            if published > KEEP {
                let oldest = published - KEEP;
                let started = Instant::now();
                let rows = state
                    .storage
                    .conn()
                    .expect("a feed with a database")
                    .execute(
                        "DELETE FROM feed_messages WHERE id <= ?1",
                        params![oldest as i64],
                    )
                    .expect("the rows behind the writer are removed");
                deleting += started.elapsed();
                deleted += rows as u64;
            }

            if bucket_started.elapsed() >= BUCKET {
                buckets.push((bucket_messages, bucket_started.elapsed()));
                bucket_messages = 0;
                bucket_started = Instant::now();
            }
        }

        let bytes = std::fs::metadata(&path).unwrap().len();
        let conn = state.storage.conn().expect("a feed with a database");
        let rows: u64 = conn
            .query_row("SELECT COUNT(*) FROM feed_messages", [], |row| row.get(0))
            .unwrap();
        let nodes: u64 = conn
            .query_row("SELECT COUNT(*) FROM merkle_nodes", [], |row| row.get(0))
            .unwrap();
        drop(state);

        println!(
            "\n{} messages published in bursts of {}, in {:.1} s of publishing plus {:.1} s of \
             deleting\n\
             {:.0} messages a second while publishing; {:.0} a second including the deletes\n\
             {} message rows deleted behind the writer, {} rows left, {} tree nodes\n\
             file {} bytes at the start and {} bytes at the end: {} bytes a message published, \
             all of it tree\n",
            published,
            BURST,
            publishing.as_secs_f64(),
            deleting.as_secs_f64(),
            bench_per_second(published, publishing),
            bench_per_second(published, publishing + deleting),
            deleted,
            rows,
            nodes,
            opening_bytes,
            bytes,
            (bytes - opening_bytes) / published,
        );
        for (index, (messages, took)) in buckets.iter().enumerate() {
            println!(
                "  seconds {:>3}-{:>3}: {:>9.0} messages a second",
                index as u64 * BUCKET.as_secs(),
                (index as u64 + 1) * BUCKET.as_secs(),
                bench_per_second(*messages, *took),
            );
        }
        println!();
    }
}
