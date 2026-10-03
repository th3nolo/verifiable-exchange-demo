use ed25519_dalek::SigningKey;
use rusqlite::{Connection, params};
use services::{logchain, store::{Change, ClaimRow, Counters, ExecutionState, Store, StoreError}};

fn commit(store: &mut Store, id: u64, key: &SigningKey) {
    let root = [id as u8; 32];
    let claim = ClaimRow { from_msg: 1, to_msg: id, root_before: [0;32], root_after: root,
        trades_total: 0, signature: Some(logchain::sign_claim(key, "", 1, id, &[0;32], &root, 0).to_bytes()) };
    store.commit(&[Change::ExecutionState(ExecutionState::default())],
        &Counters { last_seen: id, messages_processed: id, ..Counters::default() }, Some(&claim)).unwrap();
}

#[test]
fn stale_owner_is_fenced_on_commit_heartbeat_close_and_metadata() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let key = SigningKey::from_bytes(&[71;32]);
    let (mut old, _) = Store::open(&path, "http://local", 200, false).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute("UPDATE runs SET heartbeat_ms=0 WHERE run_id=?1", params![old.run_id()]).unwrap();
    let (mut current, _) = Store::open(&path, "http://local", 200, false).unwrap();
    current.set_matcher_pubkey(&logchain::to_hex(key.verifying_key().as_bytes())).unwrap();
    commit(&mut current, 2, &key);
    assert!(matches!(old.commit(&[], &Counters { last_seen:1, ..Counters::default() }, None), Err(StoreError::Fenced)));
    assert!(matches!(old.heartbeat(), Err(StoreError::Fenced)));
    assert!(matches!(old.close_stopped(), Err(StoreError::Fenced)));
    assert!(matches!(old.set_feed_session("bad"), Err(StoreError::Fenced)));
    assert!(matches!(old.set_feed_pubkey("bad"), Err(StoreError::Fenced)));
    assert!(matches!(old.set_matcher_pubkey("bad"), Err(StoreError::Fenced)));
    assert!(current.commit(&[], &Counters { last_seen:1, ..Counters::default() }, None).is_err());
    let cursor:i64 = connection.query_row("SELECT last_seen FROM resume_point WHERE run_id=?1", params![current.run_id()], |row|row.get(0)).unwrap();
    assert_eq!(cursor,2);
    current.heartbeat().unwrap();
    current.close_stopped().unwrap();
}

#[test]
fn invalid_last_claim_is_rejected_under_independently_held_key() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let key = SigningKey::from_bytes(&[72;32]);
    let (mut store, _) = Store::open(&path, "http://local", 200, false).unwrap();
    store.set_matcher_pubkey(&logchain::to_hex(key.verifying_key().as_bytes())).unwrap();
    commit(&mut store,1,&key);
    store.close_stopped().unwrap(); drop(store);
    let (mut store, snapshot) = Store::open(&path,"http://local",200,false).unwrap();
    Store::authenticate_snapshot(&snapshot.unwrap(),&key.verifying_key()).unwrap();
    store.close_stopped().unwrap(); drop(store);
    let conn = Connection::open(&path).unwrap();
    conn.execute("UPDATE claims SET root_after=?1, signature=zeroblob(64)",params![[99u8;32].as_slice()]).unwrap();
    let (_,snapshot)=Store::open(&path,"http://local",200,false).unwrap();
    assert!(Store::authenticate_snapshot(&snapshot.unwrap(),&key.verifying_key()).is_err());
}

#[test]
fn legacy_recovery_refusal_preserves_the_historical_root() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("state.db");
    let key=SigningKey::from_bytes(&[73;32]);
    let (mut store,_)=Store::open(&path,"http://local",200,false).unwrap();
    commit(&mut store,1,&key);
    store.close_stopped().unwrap(); drop(store);
    let conn=Connection::open(&path).unwrap();
    conn.execute("UPDATE resume_point SET root_version=4,execution_state=NULL",[]).unwrap();
    let err=Store::open(&path,"http://local",200,false).err().unwrap();
    assert!(err.to_string().contains("legacy root v4 omitted MidWindow"));
    let root:Vec<u8>=conn.query_row("SELECT root_after FROM claims",[],|row|row.get(0)).unwrap();
    assert_eq!(root,[1u8;32]);
}
