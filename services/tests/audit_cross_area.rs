//! Integration gates for the audit fixes, using public engine operations.
//! The large-position case requires the explicit synthetic compatibility mode
//! once the funded spot constructor is integrated.

use ed25519_dalek::SigningKey;
use services::domain::{OPERATOR_ACCOUNT, OrderMessage, OrderType, Side, TimeInForce};
use services::matcher::MatcherState;
use services::{logchain, operator};

const SYMBOL: &str = "AUDIT-USDC";

fn listed_engine() -> MatcherState {
    let key = SigningKey::from_bytes(&[3; 32]);
    let listing = operator::signed_as(
        &key,
        "",
        OrderMessage::ListSymbol {
            id: 1,
            timestamp: 0,
            account: OPERATOR_ACCOUNT,
            symbol: SYMBOL.into(),
            price_step: 0.01,
            quantity_step: 0.1,
            nonce: Some(format!("{:032x}", 1)),
            public_key: logchain::to_hex(key.verifying_key().as_bytes()),
            signature: String::new(),
        },
    );
    let mut engine = MatcherState::new();
    engine.apply_message(&listing).unwrap();
    assert!(engine.is_listed(SYMBOL));
    engine
}

fn order(
    id: u64,
    account: u32,
    side: Side,
    price: f64,
    quantity: f64,
    tif: TimeInForce,
) -> OrderMessage {
    OrderMessage::New {
        id,
        timestamp: id * 1_000,
        account,
        symbol: SYMBOL.into(),
        side,
        price,
        quantity,
        nonce: None,
        order_type: OrderType::Limit,
        time_in_force: tif,
        post_only: false,
    }
}

fn cancel(id: u64, account: u32, target_id: u64) -> OrderMessage {
    OrderMessage::Cancel {
        id,
        timestamp: id * 1_000,
        account,
        target_id,
        nonce: None,
    }
}

#[test]
fn fok_later_overflow_preserves_every_execution_effect_and_can_still_cancel() {
    let mut engine = listed_engine();
    for n in 0..9 {
        engine
            .apply_message(&order(
                2 * n + 2,
                7,
                Side::Sell,
                10_000_000.0,
                100_000_000.0,
                TimeInForce::GoodTillCancel,
            ))
            .unwrap();
        engine
            .apply_message(&order(
                2 * n + 3,
                9,
                Side::Buy,
                10_000_000.0,
                100_000_000.0,
                TimeInForce::GoodTillCancel,
            ))
            .unwrap();
    }
    engine
        .apply_message(&order(
            20,
            21,
            Side::Sell,
            10_000_000.0,
            10_000_000.0,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    engine
        .apply_message(&order(
            21,
            22,
            Side::Sell,
            10_000_000.0,
            20_000_000.0,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    let positions_before: Vec<_> = [7, 9, 21, 22]
        .into_iter()
        .map(|a| engine.position_of(a, SYMBOL))
        .collect();
    let trades_before = engine.trades_total();
    engine
        .apply_message(&order(
            22,
            9,
            Side::Buy,
            10_000_000.0,
            30_000_000.0,
            TimeInForce::FillOrKill,
        ))
        .unwrap();
    assert_eq!(
        engine.trades_total(),
        trades_before,
        "a FOK cannot retain an earlier fill when a later fill overflows"
    );
    assert_eq!(
        [7, 9, 21, 22]
            .into_iter()
            .map(|a| engine.position_of(a, SYMBOL))
            .collect::<Vec<_>>(),
        positions_before
    );
    assert_eq!(engine.open_order(20).unwrap().3, 100_000_000);
    assert_eq!(engine.open_order(21).unwrap().3, 200_000_000);
    assert!(engine.open_order(22).is_none());
    engine.apply_message(&cancel(23, 21, 20)).unwrap();
    assert!(engine.open_order(20).is_none());
    assert_eq!(engine.trades_total(), trades_before);
}

#[test]
fn partial_fill_and_owner_cancel_conserve_integer_deltas() {
    let mut engine = listed_engine();
    engine
        .apply_message(&order(
            2,
            3,
            Side::Sell,
            100.03,
            0.3,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    engine
        .apply_message(&order(
            3,
            4,
            Side::Buy,
            101.0,
            0.1,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    assert_eq!(engine.trades_total(), 1);
    assert_eq!(engine.open_order(2).unwrap().3, 2);
    let seller = engine.position_of(3, SYMBOL);
    let buyer = engine.position_of(4, SYMBOL);
    assert_eq!(i128::from(seller.0) + i128::from(buyer.0), 0);
    assert_eq!(i128::from(seller.2) + i128::from(buyer.2), 0);
    assert_eq!(buyer.2, -10_003);
    engine.apply_message(&cancel(4, 99, 2)).unwrap();
    assert_eq!(engine.open_order(2).unwrap().3, 2);
    engine.apply_message(&cancel(5, 3, 2)).unwrap();
    assert!(engine.open_order(2).is_none());
    assert_eq!(engine.position_of(3, SYMBOL), seller);
    assert_eq!(engine.position_of(4, SYMBOL), buyer);
}

#[test]
fn repeated_account_fills_conserve_cash_and_quantity_including_self_match() {
    let mut engine = listed_engine();
    engine
        .apply_message(&order(
            2,
            3,
            Side::Sell,
            100.01,
            0.1,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    engine
        .apply_message(&order(
            3,
            3,
            Side::Sell,
            100.02,
            0.2,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    engine
        .apply_message(&order(4, 4, Side::Buy, 101.0, 0.3, TimeInForce::FillOrKill))
        .unwrap();
    assert_eq!(engine.trades_total(), 2);
    let before = [engine.position_of(3, SYMBOL), engine.position_of(4, SYMBOL)];
    assert_eq!(i128::from(before[0].0) + i128::from(before[1].0), 0);
    assert_eq!(i128::from(before[0].2) + i128::from(before[1].2), 0);
    engine
        .apply_message(&order(
            5,
            3,
            Side::Sell,
            101.0,
            0.1,
            TimeInForce::GoodTillCancel,
        ))
        .unwrap();
    engine
        .apply_message(&order(6, 3, Side::Buy, 101.0, 0.1, TimeInForce::FillOrKill))
        .unwrap();
    assert_eq!(engine.trades_total(), 3);
    let after = [engine.position_of(3, SYMBOL), engine.position_of(4, SYMBOL)];
    assert_eq!(after[0].0, before[0].0);
    assert_eq!(after[0].2, before[0].2);
    assert_eq!(after[1], before[1]);
}
