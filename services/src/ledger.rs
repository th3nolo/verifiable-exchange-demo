//! Deterministically funded spot SIMULATION. No custody, deposits or RPC.
//!
//! Every asset uses thousandths of one asset. Base quantity tenths converts
//! by multiplying by 100; quote cash mills is price cents * quantity tenths.
//! PnL per symbol is a separate projection, never a spendable balance.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::domain::{AccountId, OrderId, Side};
use crate::store::OrderRow;

pub const ASSET_SCALE: i64 = 1_000;
pub const LEDGER_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerMode {
    SyntheticLegacy,
    FundedSimulation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketAssets {
    pub symbol: String,
    pub base_asset: String,
    pub quote_asset: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Funding {
    pub account: AccountId,
    pub asset: String,
    /// Thousandths of this asset. Genesis funding, applied exactly once.
    pub units: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingConfig {
    pub markets: Vec<MarketAssets>,
    pub funding: Vec<Funding>,
    /// Only zero fees are supported by version 1; reject another policy.
    pub fee_units: i64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Balance {
    pub available: i64,
    pub reserved: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceRow {
    pub account: AccountId,
    pub asset: String,
    pub balance: Balance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    pub order_id: OrderId,
    pub account: AccountId,
    pub symbol: String,
    pub side: Side,
    pub limit_cents: i64,
    pub remaining_tenths: i64,
    pub asset: String,
    pub units: i64,
}

/// Versioned, self-contained payload for the store/root owner. Rows are sorted
/// by (account, asset) and order id. No HashMap iteration or floats enter it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerSnapshot {
    pub version: u32,
    pub mode: LedgerMode,
    pub asset_scale: i64,
    pub config: Option<FundingConfig>,
    pub last_sequence: OrderId,
    pub balances: Vec<BalanceRow>,
    pub reservations: Vec<Reservation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerError(pub String);
impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for LedgerError {}
fn fail(reason: impl Into<String>) -> LedgerError {
    LedgerError(reason.into())
}

type BalanceKey = (AccountId, String);

#[derive(Debug, Clone)]
pub struct Ledger {
    mode: LedgerMode,
    config: Option<FundingConfig>,
    last_sequence: OrderId,
    balances: BTreeMap<BalanceKey, Balance>,
    reservations: BTreeMap<OrderId, Reservation>,
}

impl Ledger {
    /// Compatibility only: no balance validation and no simulated assets.
    pub fn synthetic_legacy() -> Self {
        Self {
            mode: LedgerMode::SyntheticLegacy,
            config: None,
            last_sequence: 0,
            balances: BTreeMap::new(),
            reservations: BTreeMap::new(),
        }
    }

    pub fn funded(mut config: FundingConfig) -> Result<Self, LedgerError> {
        config.markets.sort_by(|a, b| a.symbol.cmp(&b.symbol));
        config
            .funding
            .sort_by(|a, b| (a.account, &a.asset).cmp(&(b.account, &b.asset)));
        validate_config(&config)?;
        let balances = config
            .funding
            .iter()
            .map(|grant| {
                (
                    (grant.account, grant.asset.clone()),
                    Balance {
                        available: grant.units,
                        reserved: 0,
                    },
                )
            })
            .collect();
        Ok(Self {
            mode: LedgerMode::FundedSimulation,
            config: Some(config),
            last_sequence: 0,
            balances,
            reservations: BTreeMap::new(),
        })
    }

    pub fn mode(&self) -> LedgerMode {
        self.mode
    }
    pub fn is_funded(&self) -> bool {
        self.mode == LedgerMode::FundedSimulation
    }
    pub fn config(&self) -> Option<&FundingConfig> {
        self.config.as_ref()
    }
    pub fn balance(&self, account: AccountId, asset: &str) -> Balance {
        self.balances
            .get(&(account, asset.to_string()))
            .copied()
            .unwrap_or_default()
    }
    pub fn reservation(&self, order_id: OrderId) -> Option<&Reservation> {
        self.reservations.get(&order_id)
    }
    fn market(&self, symbol: &str) -> Result<&MarketAssets, LedgerError> {
        self.config
            .as_ref()
            .and_then(|config| config.markets.iter().find(|market| market.symbol == symbol))
            .ok_or_else(|| fail(format!("no funded asset mapping for {symbol}")))
    }

    /// Called after effective terms/bounds, before the first execution effect.
    /// A failed reserve changes no balance and does not create an obligation.
    pub fn reserve(
        &mut self,
        order_id: OrderId,
        account: AccountId,
        symbol: &str,
        side: Side,
        limit_cents: i64,
        qty_tenths: i64,
    ) -> Result<(), LedgerError> {
        if !self.is_funded() {
            return Ok(());
        }
        let expected = self
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| fail("sequence exhausted"))?;
        if order_id != expected || self.reservations.contains_key(&order_id) {
            return Err(fail("order reservation would replay an applied sequence"));
        }
        let market = self.market(symbol)?;
        let asset = match side {
            Side::Buy => &market.quote_asset,
            Side::Sell => &market.base_asset,
        }
        .clone();
        let units = reserve_units(side, limit_cents, qty_tenths)?;
        let key = (account, asset.clone());
        let before = self.balances.get(&key).copied().unwrap_or_default();
        let available = before
            .available
            .checked_sub(units)
            .filter(|amount| *amount >= 0)
            .ok_or_else(|| {
                fail(format!(
                    "insufficient available {asset} for account {account}"
                ))
            })?;
        let reserved = before
            .reserved
            .checked_add(units)
            .ok_or_else(|| fail("reserve overflow"))?;
        let next = Balance {
            available,
            reserved,
        };
        check_balance(next)?;
        self.balances.insert(key, next);
        self.reservations.insert(
            order_id,
            Reservation {
                order_id,
                account,
                symbol: symbol.to_string(),
                side,
                limit_cents,
                remaining_tenths: qty_tenths,
                asset,
                units,
            },
        );
        Ok(())
    }

    /// Atomic on both sides, including one account taking both sides. Credits
    /// and debits are combined by account/asset before checked conversion.
    /// The caller must preflight all fills of FOK on a staged Ledger first.
    pub fn settle_fill(
        &mut self,
        maker_order: OrderId,
        taker_order: OrderId,
        price_cents: i64,
        qty_tenths: i64,
    ) -> Result<(), LedgerError> {
        if !self.is_funded() {
            return Ok(());
        }
        if taker_order
            != self
                .last_sequence
                .checked_add(1)
                .ok_or_else(|| fail("sequence exhausted"))?
        {
            return Err(fail("fill taker is outside the current sequence"));
        }
        if maker_order == taker_order || price_cents <= 0 || qty_tenths <= 0 {
            return Err(fail("invalid fill"));
        }
        let maker = self
            .reservations
            .get(&maker_order)
            .ok_or_else(|| fail("maker reservation missing"))?;
        let taker = self
            .reservations
            .get(&taker_order)
            .ok_or_else(|| fail("taker reservation missing"))?;
        if maker.symbol != taker.symbol || maker.side == taker.side {
            return Err(fail("fill reservations disagree on market or side"));
        }
        let market = self.market(&maker.symbol)?;
        let (buyer, seller) = if maker.side == Side::Buy {
            (maker, taker)
        } else {
            (taker, maker)
        };
        if price_cents > buyer.limit_cents
            || price_cents < seller.limit_cents
            || qty_tenths > buyer.remaining_tenths
            || qty_tenths > seller.remaining_tenths
        {
            return Err(fail("fill exceeds reserved terms"));
        }
        let base = qty_tenths
            .checked_mul(100)
            .ok_or_else(|| fail("base fill overflow"))?;
        let cash = price_cents
            .checked_mul(qty_tenths)
            .ok_or_else(|| fail("quote fill overflow"))?;
        let buyer_reserved = buyer
            .limit_cents
            .checked_mul(qty_tenths)
            .ok_or_else(|| fail("buy reserve overflow"))?;
        let improvement = buyer_reserved
            .checked_sub(cash)
            .ok_or_else(|| fail("price improvement overflow"))?;
        let mut deltas: BTreeMap<BalanceKey, (i128, i128)> = BTreeMap::new();
        add_delta(
            &mut deltas,
            buyer.account,
            &market.quote_asset,
            i128::from(improvement),
            -i128::from(buyer_reserved),
        );
        add_delta(
            &mut deltas,
            seller.account,
            &market.quote_asset,
            i128::from(cash),
            0,
        );
        add_delta(
            &mut deltas,
            seller.account,
            &market.base_asset,
            0,
            -i128::from(base),
        );
        add_delta(
            &mut deltas,
            buyer.account,
            &market.base_asset,
            i128::from(base),
            0,
        );
        let mut next_balances = Vec::new();
        for (key, (available_delta, reserved_delta)) in deltas {
            let before = self.balances.get(&key).copied().unwrap_or_default();
            let available = i64::try_from(i128::from(before.available) + available_delta)
                .map_err(|_| fail("available fill overflow"))?;
            let reserved = i64::try_from(i128::from(before.reserved) + reserved_delta)
                .map_err(|_| fail("reserved fill overflow"))?;
            let next = Balance {
                available,
                reserved,
            };
            check_balance(next)?;
            next_balances.push((key, next));
        }
        let maker_next = after_fill(maker, qty_tenths)?;
        let taker_next = after_fill(taker, qty_tenths)?;
        // Everything that can fail is above this mutation boundary.
        for (key, next) in next_balances {
            self.balances.insert(key, next);
        }
        for next in [maker_next, taker_next] {
            if next.remaining_tenths == 0 {
                self.reservations.remove(&next.order_id);
            } else {
                self.reservations.insert(next.order_id, next);
            }
        }
        Ok(())
    }

    /// Accumulate every fill from the matching owner's immutable plan on a
    /// single staged ledger. The tuple is (maker id, taker id, cents, tenths).
    /// Reserve the incoming order on a clone first; discard that clone on any
    /// error. A can map FokPlan::fills() into these tuples without rescanning
    /// the book. Assign the result only with the accepted positions/book plan.
    pub fn stage_reserved_fills(
        &self,
        fills: impl IntoIterator<Item = (OrderId, OrderId, i64, i64)>,
    ) -> Result<Self, LedgerError> {
        let mut staged = self.clone();
        for (maker, taker, price, quantity) in fills {
            staged.settle_fill(maker, taker, price, quantity)?;
        }
        Ok(staged)
    }

    /// Release once. A repeated cancel/release is a no-op, never new funding.
    pub fn release(&mut self, order_id: OrderId) -> Result<bool, LedgerError> {
        let Some(reservation) = self.reservations.get(&order_id) else {
            return Ok(false);
        };
        let key = (reservation.account, reservation.asset.clone());
        let before = self
            .balances
            .get(&key)
            .copied()
            .ok_or_else(|| fail("reserved balance missing"))?;
        let available = before
            .available
            .checked_add(reservation.units)
            .ok_or_else(|| fail("release overflow"))?;
        let reserved = before
            .reserved
            .checked_sub(reservation.units)
            .ok_or_else(|| fail("release underflow"))?;
        let next = Balance {
            available,
            reserved,
        };
        check_balance(next)?;
        self.balances.insert(key, next);
        self.reservations.remove(&order_id);
        Ok(true)
    }

    /// Advance for every consumed message, including rejected orders. Replays
    /// cannot reserve or fund again. Matcher checks its sequence before effects.
    pub fn finish_sequence(&mut self, sequence: OrderId) -> Result<(), LedgerError> {
        let expected = self
            .last_sequence
            .checked_add(1)
            .ok_or_else(|| fail("sequence exhausted"))?;
        if sequence != expected {
            return Err(fail("ledger sequence out of order"));
        }
        self.last_sequence = sequence;
        Ok(())
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            version: LEDGER_VERSION,
            mode: self.mode,
            asset_scale: ASSET_SCALE,
            config: self.config.clone(),
            last_sequence: self.last_sequence,
            balances: self
                .balances
                .iter()
                .map(|((account, asset), balance)| BalanceRow {
                    account: *account,
                    asset: asset.clone(),
                    balance: *balance,
                })
                .collect(),
            reservations: self.reservations.values().cloned().collect(),
        }
    }

    /// Root payload only; version/domain framing is owned by the root writer.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.snapshot()).expect("integer ledger snapshot serializes")
    }

    pub fn from_snapshot(snapshot: LedgerSnapshot) -> Result<Self, LedgerError> {
        if snapshot.version != LEDGER_VERSION || snapshot.asset_scale != ASSET_SCALE {
            return Err(fail("unsupported ledger version or asset scale"));
        }
        if snapshot.mode == LedgerMode::SyntheticLegacy {
            if snapshot.config.is_some()
                || !snapshot.balances.is_empty()
                || !snapshot.reservations.is_empty()
            {
                return Err(fail("synthetic ledger cannot contain funded state"));
            }
            let mut ledger = Self::synthetic_legacy();
            ledger.last_sequence = snapshot.last_sequence;
            return Ok(ledger);
        }
        let config = snapshot
            .config
            .ok_or_else(|| fail("funded config missing"))?;
        let mut ledger = Self::funded(config)?;
        ledger.last_sequence = snapshot.last_sequence;
        ledger.balances.clear();
        for row in snapshot.balances {
            if ledger
                .balances
                .insert((row.account, row.asset), row.balance)
                .is_some()
            {
                return Err(fail("duplicate balance row"));
            }
        }
        for row in snapshot.reservations {
            if row.order_id == 0 || row.order_id > ledger.last_sequence {
                return Err(fail("reservation is outside applied history"));
            }
            if ledger.reservations.insert(row.order_id, row).is_some() {
                return Err(fail("duplicate reservation row"));
            }
        }
        ledger.validate()?;
        Ok(ledger)
    }

    /// Nonnegative balances, exact backing of all reserves, and conservation
    /// of each asset against explicit genesis funding (version 1 fees = 0).
    pub fn validate(&self) -> Result<(), LedgerError> {
        if !self.is_funded() {
            return Ok(());
        }
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| fail("funded config missing"))?;
        let mut expected: BTreeMap<&str, i128> = BTreeMap::new();
        for grant in &config.funding {
            *expected.entry(&grant.asset).or_default() += i128::from(grant.units);
        }
        let mut actual: BTreeMap<&str, i128> = BTreeMap::new();
        for ((_, asset), balance) in &self.balances {
            check_balance(*balance)?;
            if !config
                .markets
                .iter()
                .any(|m| &m.base_asset == asset || &m.quote_asset == asset)
            {
                return Err(fail("balance names an unconfigured asset"));
            }
            *actual.entry(asset).or_default() +=
                i128::from(balance.available) + i128::from(balance.reserved);
        }
        expected.retain(|_, total| *total != 0);
        actual.retain(|_, total| *total != 0);
        if expected != actual {
            return Err(fail("asset total differs from explicit funding"));
        }
        let mut obligations: BTreeMap<BalanceKey, i64> = BTreeMap::new();
        for reservation in self.reservations.values() {
            let market = self.market(&reservation.symbol)?;
            let asset = match reservation.side {
                Side::Buy => &market.quote_asset,
                Side::Sell => &market.base_asset,
            };
            if &reservation.asset != asset
                || reservation.units
                    != reserve_units(
                        reservation.side,
                        reservation.limit_cents,
                        reservation.remaining_tenths,
                    )?
            {
                return Err(fail("reservation terms or units disagree"));
            }
            let entry = obligations
                .entry((reservation.account, reservation.asset.clone()))
                .or_default();
            *entry = entry
                .checked_add(reservation.units)
                .ok_or_else(|| fail("obligations overflow"))?;
        }
        for (key, balance) in &self.balances {
            if balance.reserved != obligations.remove(key).unwrap_or(0) {
                return Err(fail("reserved balance differs from active obligations"));
            }
        }
        if !obligations.is_empty() {
            return Err(fail("obligation has no balance"));
        }
        Ok(())
    }

    /// B must call this with persisted open orders during recovery. A funded
    /// snapshot cannot omit/reassign an obligation or leave a ghost reserve.
    pub fn validate_obligations(&self, rows: &[OrderRow]) -> Result<(), LedgerError> {
        self.validate()?;
        if !self.is_funded() {
            return Ok(());
        }
        if rows.len() != self.reservations.len() {
            return Err(fail("open orders and reservations differ"));
        }
        let mut seen = BTreeSet::new();
        for row in rows {
            if !seen.insert(row.order_id) {
                return Err(fail("duplicate open order"));
            }
            let reservation = self
                .reservations
                .get(&row.order_id)
                .ok_or_else(|| fail("open order lacks reservation"))?;
            if row.account != reservation.account
                || row.symbol != reservation.symbol
                || row.side != reservation.side
                || row.price_cents != reservation.limit_cents
                || row.qty_tenths != reservation.remaining_tenths
            {
                return Err(fail("open order differs from reserved obligation"));
            }
        }
        Ok(())
    }
}

fn validate_config(config: &FundingConfig) -> Result<(), LedgerError> {
    if config.fee_units != 0 || config.markets.is_empty() {
        return Err(fail(
            "funded simulation requires markets and explicit zero fees",
        ));
    }
    let valid_asset = |asset: &str| {
        !asset.is_empty()
            && asset.len() <= 32
            && asset
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    };
    let mut symbols = BTreeSet::new();
    let mut assets = BTreeSet::new();
    for market in &config.markets {
        if crate::operator::valid_symbol(&market.symbol).is_err()
            || !symbols.insert(&market.symbol)
            || !valid_asset(&market.base_asset)
            || !valid_asset(&market.quote_asset)
            || market.base_asset == market.quote_asset
        {
            return Err(fail("invalid or duplicate market asset mapping"));
        }
        assets.insert(&market.base_asset);
        assets.insert(&market.quote_asset);
    }
    let mut funded = BTreeSet::new();
    for grant in &config.funding {
        if grant.units <= 0
            || !assets.contains(&grant.asset)
            || !funded.insert((grant.account, &grant.asset))
        {
            return Err(fail("invalid or duplicate genesis funding"));
        }
    }
    Ok(())
}
fn check_balance(balance: Balance) -> Result<(), LedgerError> {
    if balance.available < 0
        || balance.reserved < 0
        || balance.available.checked_add(balance.reserved).is_none()
    {
        return Err(fail("negative or overflowing asset balance"));
    }
    Ok(())
}
fn reserve_units(side: Side, price_cents: i64, qty_tenths: i64) -> Result<i64, LedgerError> {
    if price_cents <= 0 || qty_tenths <= 0 {
        return Err(fail("nonpositive reservation terms"));
    }
    match side {
        Side::Buy => price_cents.checked_mul(qty_tenths),
        Side::Sell => qty_tenths.checked_mul(100),
    }
    .ok_or_else(|| fail("reservation amount overflow"))
}
fn after_fill(before: &Reservation, qty_tenths: i64) -> Result<Reservation, LedgerError> {
    let mut next = before.clone();
    next.remaining_tenths = before
        .remaining_tenths
        .checked_sub(qty_tenths)
        .filter(|qty| *qty >= 0)
        .ok_or_else(|| fail("reservation fill underflow"))?;
    next.units = if next.remaining_tenths == 0 {
        0
    } else {
        reserve_units(next.side, next.limit_cents, next.remaining_tenths)?
    };
    Ok(next)
}
fn add_delta(
    into: &mut BTreeMap<BalanceKey, (i128, i128)>,
    account: AccountId,
    asset: &str,
    available: i128,
    reserved: i128,
) {
    let entry = into.entry((account, asset.to_string())).or_default();
    entry.0 += available;
    entry.1 += reserved;
}
