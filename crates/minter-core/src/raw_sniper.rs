//! Raw contract sniper — **pre-sign race** (FCFS / L2 sequencer path).
//!
//! Architecture:
//! 1. Resolve value + hard gas limit (no estimate at fire)
//! 2. Wait until `at_time − prep_lead`, then **pre-sign** all wallets (nonce + sign)
//! 3. Clock-fire at `at_time` → parallel `eth_sendRawTransaction` blast
//! 4. Receipts after send (not on the hot path)
//!
//! Does **not** gate on `getMintStatus` / `estimate_gas` at open.
//! Probe helpers remain for UI status only.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, U256};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::abi::build_calldata;
use crate::gas;
use crate::mint_ops::parse_at_time_unix;
use crate::progress::{MintEvent, MintReporter};
use crate::rpc::RpcClient;
use crate::safety_policy::{FeeRefreshMode, should_refresh_fees_at_fire};
use crate::sign::{BuiltTx, shorten_hash, sign_transaction};
use crate::types::{GasParams, MintResult, Signer, WalletStatus};

/// Default gas limit when UI leaves it empty (Hoodies winners used ~450k–650k).
const DEFAULT_GAS_LIMIT: u64 = 650_000;
/// Start pre-sign this many seconds before `at_time`.
const PREP_LEAD_SECS: i64 = 5;
/// Ceiling on how early the push loop may start.
///
/// Transactions are pre-signed at `at_time - PREP_LEAD_SECS`, so a longer lead
/// would ask the loop to push bytes that do not exist yet. Two seconds are held
/// back for the pre-sign itself and the fee refresh that follows it.
const MAX_PUSH_LEAD_MS: u64 = (PREP_LEAD_SECS as u64 - 2) * 1_000;
/// Gap left between the fee refresh and the first push.
const PUSH_FEE_MARGIN_MS: u64 = 400;
/// Reject a scheduled `at_time` further ahead than this (30 days).
///
/// Guards against a mistyped date parking the run in the pre-fire wait forever.
const MAX_SCHEDULE_AHEAD_SECS: i64 = 30 * 86_400;
/// Ceiling (1 ETH per unit) on a mint value derived from on-chain data.
///
/// The auto value is decoded from `getMintStatus()` by slot index, so a contract
/// whose layout differs from what we expect could otherwise put an arbitrary
/// amount into `msg.value`. An explicit `fixed_value` is never capped.
const MAX_AUTO_MINT_VALUE_WEI: u64 = 1_000_000_000_000_000_000;

// ─── Public config ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum SniperPreset {
    /// MintBay Generative V3/V4 public: `mint(uint256)` + Auto value via `getMintStatus`.
    #[default]
    MintBayPublic,
    /// Plain `mint(uint256)` — fire at `at_time` (or immediately).
    SimpleMintUint,
    /// User function signature + params.
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ValueMode {
    /// MintBay: (phase.mintPrice + collectorFee) * qty. Else falls back to fixed.
    #[default]
    Auto,
    Fixed,
}

#[derive(Clone)]
pub struct RawSniperConfig {
    pub contract: Address,
    pub preset: SniperPreset,
    /// Call signature for mint tx (e.g. `mint(uint256)`).
    pub function: String,
    /// Static params; for `mint(uint256)` use empty and set `quantity`.
    pub params: Vec<String>,
    pub quantity: u64,
    pub value_mode: ValueMode,
    /// Used when Fixed, or Auto fallback if MintBay status fails.
    pub fixed_value: U256,
    pub gas: GasParams,
    pub dry_run: bool,
    /// Unix seconds (optional). None → fire immediately after pre-sign.
    pub at_time: Option<i64>,
    /// Max wait until prep window (at_time − lead); also bounds hang waits.
    pub timeout_secs: u64,
    pub concurrency: usize,
    /// Optional hard gas limit per tx (from UI). Default applied in runner.
    pub gas_limit: Option<u64>,
    /// When to re-fetch fees + re-sign at fire (default mainnet-only).
    pub fee_refresh: FeeRefreshMode,
    /// Start pushing this many ms before `at_time`; 0 fires only at T0.
    ///
    /// The point is that `at_time` is read off the local clock and the chain
    /// opens on its own. Pushing early lets the node decide the moment instead
    /// of us guessing it.
    pub push_lead_ms: u64,
    /// Gap between pushes while waiting for the chain to open.
    pub push_interval_ms: u64,
}

impl Default for RawSniperConfig {
    fn default() -> Self {
        Self {
            contract: Address::ZERO,
            preset: SniperPreset::MintBayPublic,
            function: "mint(uint256)".into(),
            params: vec![],
            quantity: 1,
            value_mode: ValueMode::Auto,
            fixed_value: U256::ZERO,
            gas: GasParams::default(),
            dry_run: false,
            at_time: None,
            timeout_secs: 300,
            concurrency: 16,
            gas_limit: None,
            fee_refresh: FeeRefreshMode::MainnetOnly,
            push_lead_ms: 0,
            push_interval_ms: 15,
        }
    }
}

/// Normalise the two push knobs into what the loop will actually use.
///
/// A lead of zero switches the whole thing off and leaves the old behaviour
/// untouched, which is why the interval is only meaningful alongside a lead.
///
/// The interval, not the lead, is what bounds the miss: a knock refused a
/// moment before the open waits a whole interval for the next one. Aiming early
/// with a coarse step is therefore worse than aiming late — 45ms of flight and
/// a 100ms step turns "5ms early" into "95ms late".
fn push_plan(lead_ms: u64, interval_ms: u64) -> (u64, u64) {
    let lead = lead_ms.min(MAX_PUSH_LEAD_MS);
    if lead == 0 {
        return (0, 0);
    }
    // Below 5ms the knocks outpace the answers and only queue up; above a
    // second the step is coarser than a block and the lead stops meaning much.
    (lead, interval_ms.clamp(5, 1_000))
}

/// How long the loop keeps knocking after the local clock passes `at_time`.
///
/// Knocks are refused for free, so stopping dead at T0 only helps a clock that
/// runs slow. A clock that runs fast would hand the plain blast a mint that has
/// not opened yet — a revert and a spent nonce — so the loop outlives T0 by a
/// few blocks and lets the chain, not the clock, end it.
const PUSH_TAIL_MS: u64 = 300;

/// Where each wallet's knocking starts inside the first interval.
///
/// Fifty wallets knocking on the same tick is what put the node into a queue
/// during measurement: answers came back out of the order they were sent, which
/// is precisely the precision this loop is trying to buy. Spreading them across
/// the interval keeps every wallet's own cadence while leaving one or two
/// requests in flight instead of all of them.
fn push_stagger_ms(index: usize, wallets: usize, interval_ms: u64) -> u64 {
    if wallets <= 1 {
        return 0;
    }
    (index as u64 * interval_ms) / wallets as u64
}

/// Whether a conditional rejection is the node saying "not yet" rather than
/// something being wrong.
///
/// The wait is the expected answer for every push before the open, so it must
/// not be logged as an error 40 times a second — but a genuine failure (no such
/// method, malformed tx) has to surface, or the run silently pushes nothing.
fn is_condition_not_met(err: &str) -> bool {
    let e = err.to_ascii_lowercase();
    e.contains("condition not met") || e.contains("timestampmin") || e.contains("blocknumbermin")
}

// ─── Decode helpers (MintBay status) ─────────────────────────────────────────

fn word_u256(data: &[u8], index: usize) -> Result<U256> {
    let start = index * 32;
    let end = start + 32;
    if data.len() < end {
        bail!("eth_call result too short for word {index}");
    }
    Ok(U256::from_be_slice(&data[start..end]))
}

fn word_bool(data: &[u8], index: usize) -> Result<bool> {
    Ok(!word_u256(data, index)?.is_zero())
}

/// Saturating U256 → i64 (untrusted contract words must never panic).
pub(crate) fn u256_to_i64_sat(v: U256) -> i64 {
    u64::try_from(v)
        .map(|n| n.min(i64::MAX as u64) as i64)
        .unwrap_or(i64::MAX)
}

/// Saturating U256 → u8 (phase type words from arbitrary contracts).
fn u256_to_u8_sat(v: U256) -> u8 {
    u64::try_from(v)
        .map(|n| n.min(u8::MAX as u64) as u8)
        .unwrap_or(u8::MAX)
}

/// Seconds of true time, corrected for this machine's clock error.
fn now_unix() -> i64 {
    crate::timing::true_now_secs()
}

/// Milliseconds of true time. Every wait for a fire time goes through here, so
/// correcting it here covers the whole raw path at once.
fn now_unix_ms() -> i64 {
    crate::timing::true_now_ms()
}

fn cancelled(cancel: &Option<Arc<AtomicBool>>) -> bool {
    cancel
        .as_ref()
        .map(|c| c.load(Ordering::SeqCst))
        .unwrap_or(false)
}

fn report(rep: &Option<Arc<dyn MintReporter>>, ev: MintEvent) {
    if let Some(r) = rep {
        r.report(ev);
    }
}

/// Sleep until unix second `target` (or return if already past). Honours cancel.
async fn sleep_until_unix(target: i64, cancel: &Option<Arc<AtomicBool>>) -> Result<(), String> {
    loop {
        if cancelled(cancel) {
            return Err("cancelled by user".into());
        }
        let now = now_unix();
        let rem = target - now;
        if rem <= 0 {
            return Ok(());
        }
        let ms = if rem > 5 {
            500
        } else if rem > 1 {
            50
        } else {
            5
        };
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

/// Fine-grained wait for fire: target is unix **milliseconds**; spins last ~5ms.
async fn sleep_until_ms(target_ms: i64, cancel: &Option<Arc<AtomicBool>>) -> Result<(), String> {
    loop {
        if cancelled(cancel) {
            return Err("cancelled by user".into());
        }
        let now = now_unix_ms();
        let rem = target_ms - now;
        if rem <= 0 {
            return Ok(());
        }
        if rem > 2_000 {
            tokio::time::sleep(Duration::from_millis(100)).await;
        } else if rem > 50 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        } else if rem > 5 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        } else {
            // busy-ish spin for last few ms
            tokio::task::yield_now().await;
        }
    }
}

async fn resolve_mint_value(rpc: &RpcClient, config: &RawSniperConfig) -> (U256, String) {
    match config.value_mode {
        ValueMode::Fixed => (
            config.fixed_value,
            format!("fixed {} wei", config.fixed_value),
        ),
        ValueMode::Auto => {
            if matches!(config.preset, SniperPreset::MintBayPublic) {
                match fetch_mintbay_status(rpc, &config.contract).await {
                    Ok(st) => {
                        // The view fallback in `fetch_mintbay_status` cannot read the
                        // price fields (both stay zero). Sending an auto value that is
                        // only the collector fee would underpay and revert, so prefer
                        // the user's fixed fallback when the price is unknown.
                        let price_known =
                            !st.public_mint_price.is_zero() || !st.phase_mint_price.is_zero();
                        if !price_known && !config.fixed_value.is_zero() {
                            (
                                config.fixed_value,
                                format!(
                                    "MintBay auto: price unavailable (view fallback) — using fixed {} wei",
                                    config.fixed_value
                                ),
                            )
                        } else {
                            let v = st.mint_value(config.quantity);
                            // Bound a contract-derived value before it becomes
                            // msg.value. It is decoded from an on-chain response by
                            // slot index, so a layout change or a hostile contract
                            // could otherwise hand the signer an arbitrary amount.
                            let cap = U256::from(MAX_AUTO_MINT_VALUE_WEI)
                                .saturating_mul(U256::from(config.quantity.max(1)));
                            if v > cap {
                                let fallback = config.fixed_value;
                                (
                                    fallback,
                                    format!(
                                        "MintBay auto value {v} wei exceeds the {} wei/unit safety cap \
                                         — refusing it, using fixed {fallback} wei",
                                        MAX_AUTO_MINT_VALUE_WEI
                                    ),
                                )
                            } else {
                                (
                                    v,
                                    format!(
                                        "MintBay auto {} wei (phaseType={} minted={}/{})",
                                        v, st.current_phase_type, st.total_minted, st.max_supply
                                    ),
                                )
                            }
                        }
                    }
                    Err(e) => (
                        config.fixed_value,
                        format!(
                            "MintBay status fail ({e}) — using fixed {} wei",
                            config.fixed_value
                        ),
                    ),
                }
            } else {
                (
                    config.fixed_value,
                    format!("auto→fixed {} wei", config.fixed_value),
                )
            }
        }
    }
}

struct PreSigned {
    address: Address,
    raw: Bytes,
    hash: B256,
    /// Needed to re-sign on L1 if fees rise between prep and fire.
    nonce: u64,
    /// Set when the early push already got this transaction accepted, so the
    /// blast reports it instead of sending the same bytes a second time.
    early_hash: Option<B256>,
}

// ─── MintBay status ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MintBayStatus {
    pub public_mint_price: U256,
    pub max_supply: U256,
    pub total_minted: U256,
    pub collector_fee: U256,
    pub resolved_phase_id: U256,
    pub minting_paused: bool,
    pub current_phase_type: u8,
    pub phase_start: U256,
    pub phase_end: U256,
    pub phase_mint_price: U256,
}

impl MintBayStatus {
    /// Public mint open for sniping.
    pub fn is_public_open(&self, wall_now: i64) -> bool {
        if self.minting_paused {
            return false;
        }
        // 0=Paused 1=Allowlist 2=Public
        if self.current_phase_type != 2 {
            return false;
        }
        if self.resolved_phase_id.is_zero() {
            return false;
        }
        if !self.max_supply.is_zero() && self.total_minted >= self.max_supply {
            return false;
        }
        let start = u256_to_i64_sat(self.phase_start);
        let end = u256_to_i64_sat(self.phase_end);
        if start > 0 && wall_now < start {
            return false;
        }
        if end > 0 && wall_now > end {
            return false;
        }
        true
    }

    pub fn mint_value(&self, qty: u64) -> U256 {
        let price = if !self.resolved_phase_id.is_zero() {
            self.phase_mint_price
        } else {
            self.public_mint_price
        };
        let per = price.saturating_add(self.collector_fee);
        per.saturating_mul(U256::from(qty.max(1)))
    }
}

/// Decode a `getMintStatus()` return whose layout matches MintbayGenerative**V4**
/// (17 static words / 544 bytes).
///
/// Word map: 0 mintStart · 1 publicMintPrice · 2 maxSupply · 3 totalMinted ·
/// 4 collectorFee · 5 resolvedPhaseId · 6 isRevealed · 7 mintingPaused ·
/// 8 currentPhaseType · 9 phase.phaseType · 10 phase.startTime ·
/// 11 phase.endTime · 12 phase.mintPrice · 13..16 phase limits/root.
fn decode_mintbay_status_v4(raw: &[u8]) -> Result<MintBayStatus> {
    Ok(MintBayStatus {
        public_mint_price: word_u256(raw, 1)?,
        max_supply: word_u256(raw, 2)?,
        total_minted: word_u256(raw, 3)?,
        collector_fee: word_u256(raw, 4)?,
        resolved_phase_id: word_u256(raw, 5)?,
        minting_paused: word_bool(raw, 7)?,
        current_phase_type: u256_to_u8_sat(word_u256(raw, 8)?),
        phase_start: word_u256(raw, 10)?,
        phase_end: word_u256(raw, 11)?,
        phase_mint_price: word_u256(raw, 12)?,
    })
}

/// Decode a `getMintStatus()` return whose layout matches MintbayGenerative**V3**
/// (18 static words / 576 bytes).
///
/// V3's `MintStatus` carries an extra `bool isFreeMint` after `isRevealed`, so
/// everything from `mintingPaused` onward sits one slot later than in V4.
fn decode_mintbay_status_v3(raw: &[u8]) -> Result<MintBayStatus> {
    Ok(MintBayStatus {
        public_mint_price: word_u256(raw, 1)?,
        max_supply: word_u256(raw, 2)?,
        total_minted: word_u256(raw, 3)?,
        collector_fee: word_u256(raw, 4)?,
        resolved_phase_id: word_u256(raw, 5)?,
        // 6 isRevealed, 7 isFreeMint
        minting_paused: word_bool(raw, 8)?,
        current_phase_type: u256_to_u8_sat(word_u256(raw, 9)?),
        // 10 phase.phaseType
        phase_start: word_u256(raw, 11)?,
        phase_end: word_u256(raw, 12)?,
        phase_mint_price: word_u256(raw, 13)?,
    })
}

/// `getMintStatus()` selector 0x941ada0e — flat static ABI layout.
///
/// MintBay has shipped several contract generations behind this one selector
/// and they return **different tuple widths**: V4 is 17 words (544 bytes), V3
/// adds a `bool isFreeMint` for 18 words (576 bytes), and V1 predates the phase
/// fields at 16 words. Dispatch on the exact length — a `>=` check let an 18-word
/// V3 response through the V4 map, which read `phase.endTime` (a unix timestamp)
/// as `phase.mintPrice`. Since V3/V4 `mint()` enforce
/// `msg.value == qty * (mintPrice + collectorFee)`, that mispriced every
/// pre-signed tx and reverted the whole blast.
///
/// Falls back to individual view calls if the combined call fails (RPC / proxy quirks).
pub async fn fetch_mintbay_status(rpc: &RpcClient, contract: &Address) -> Result<MintBayStatus> {
    let data = Bytes::from(hex::decode("941ada0e").context("sel")?);
    match rpc.eth_call(&Address::ZERO, contract, &data).await {
        Ok(raw) if raw.len() == 17 * 32 => decode_mintbay_status_v4(&raw),
        Ok(raw) if raw.len() == 18 * 32 => decode_mintbay_status_v3(&raw),
        Ok(raw) if !raw.is_empty() => {
            // Unrecognized width (V1's 16 words, or a future layout): decoding by
            // fixed index would silently mis-map price fields, so use the views.
            crate::rlog!(
                "getMintStatus unrecognized return width ({} bytes), using view fallback",
                raw.len()
            );
            fetch_mintbay_status_fallback(rpc, contract).await
        }
        Ok(_) => {
            crate::rlog!("getMintStatus empty return, using view fallback");
            fetch_mintbay_status_fallback(rpc, contract).await
        }
        Err(e) => {
            crate::rlog!("getMintStatus eth_call failed ({e}), using view fallback");
            match fetch_mintbay_status_fallback(rpc, contract).await {
                Ok(st) if !st.max_supply.is_zero() || !st.collector_fee.is_zero() => Ok(st),
                Ok(_) => Err(e).context("getMintStatus eth_call (fallback also empty)"),
                Err(e2) => Err(e).context(format!("getMintStatus eth_call; fallback: {e2}")),
            }
        }
    }
}

async fn view_u256(rpc: &RpcClient, contract: &Address, sel_hex: &str) -> U256 {
    let Ok(bytes) = hex::decode(sel_hex) else {
        return U256::ZERO;
    };
    let data = Bytes::from(bytes);
    match rpc.eth_call(&Address::ZERO, contract, &data).await {
        Ok(raw) if raw.len() >= 32 => word_u256(&raw, 0).unwrap_or(U256::ZERO),
        _ => U256::ZERO,
    }
}

async fn fetch_mintbay_status_fallback(
    rpc: &RpcClient,
    contract: &Address,
) -> Result<MintBayStatus> {
    Ok(MintBayStatus {
        public_mint_price: U256::ZERO,
        max_supply: view_u256(rpc, contract, "d5abeb01").await,
        total_minted: view_u256(rpc, contract, "18160ddd").await,
        collector_fee: view_u256(rpc, contract, "f103eaaf").await,
        resolved_phase_id: view_u256(rpc, contract, "40c5b34e").await,
        minting_paused: !view_u256(rpc, contract, "e1a283d6").await.is_zero(),
        current_phase_type: u256_to_u8_sat(view_u256(rpc, contract, "055ad42e").await),
        phase_start: U256::ZERO,
        phase_end: U256::ZERO,
        phase_mint_price: U256::ZERO,
    })
}

fn build_mint_params(config: &RawSniperConfig) -> Result<Vec<String>> {
    // Explicit params always win.
    if !config.params.is_empty() {
        return Ok(config.params.clone());
    }
    // Parse the signature's actual arity instead of substring-sniffing it.
    // `contains("uint256")` / `contains("()")` misread the same non-canonical
    // spellings that used to corrupt the selector: `claim( )` (a space between
    // the parens) was not recognized as zero-arg and got a spurious quantity
    // argument, and `mint(uint)` missed the quantity branch. Fall back to the
    // old heuristics only if the signature doesn't parse.
    match crate::abi::parse_function_signature(&config.function) {
        Ok((_name, types)) => {
            if types.is_empty() {
                return Ok(vec![]);
            }
            // Single numeric arg → the mint quantity.
            if types.len() == 1 {
                let t = crate::abi::canonical_type_name(&types[0]);
                if t == "uint256" || t.starts_with("uint") {
                    return Ok(vec![config.quantity.max(1).to_string()]);
                }
            }
            Ok(vec![config.quantity.max(1).to_string()])
        }
        Err(_) => Ok(vec![config.quantity.max(1).to_string()]),
    }
}

// ─── Main entry (pre-sign race) ───────────────────────────────────────────────

pub async fn run_raw_sniper(
    signers: &[Signer],
    rpc: &RpcClient,
    config: &RawSniperConfig,
    cancel: Option<Arc<AtomicBool>>,
    reporter: Option<Arc<dyn MintReporter>>,
) -> Vec<MintResult> {
    if signers.is_empty() {
        return vec![];
    }

    let params = match build_mint_params(config) {
        Ok(p) => p,
        Err(e) => return fail_all(signers, format!("params: {e}")),
    };
    let calldata = match build_calldata(&config.function, &params) {
        Ok(c) => c,
        Err(e) => return fail_all(signers, format!("calldata: {e}")),
    };

    // Never default to mainnet when chain discovery fails: signing with the wrong
    // chain id can produce unusable transactions and hides an RPC outage.
    let chain_id = match rpc.chain_id().await {
        Ok(id) if id != 0 => id,
        Ok(_) => return fail_all(signers, "RPC returned invalid chain id 0"),
        Err(e) => return fail_all(signers, format!("chain id: {e}")),
    };
    let (base_fee, network_priority) = match rpc.fee_history().await {
        Ok(f) => f,
        Err(e) => {
            report(
                &reporter,
                MintEvent::message(format!(
                    "WARN fee_history failed at prep ({e}) — falling back to 1 gwei base/priority; \
                     tx may be underpriced, esp. on L2 where fees aren't refreshed at fire (audit M6)"
                )),
            );
            (U256::from(1_000_000_000u64), U256::from(1_000_000_000u64))
        }
    };
    let (mut max_fee, mut max_priority_fee) =
        match gas::calculate_fees(&config.gas, base_fee, network_priority) {
            Ok(f) => f,
            Err(e) => return fail_all(signers, format!("gas: {e}")),
        };

    let gas_limit = config
        .gas_limit
        .filter(|&g| g >= 21_000)
        .unwrap_or(DEFAULT_GAS_LIMIT);
    let concurrency = config.concurrency.max(1);
    let fire_at = config.at_time;
    let start_wall = now_unix();

    // Hard deadline only for hanging waits (not open-poll).
    //
    // NB: for a scheduled run this is intentionally derived from `at_time`, not
    // from run start — waiting until a future `at_time` is the whole point of a
    // scheduled snipe, so `timeout_secs` must not abort it. The "mistyped
    // at_time" hazard is handled by the sanity bound below instead.
    let wait_deadline = match fire_at {
        Some(at) => at.saturating_add(config.timeout_secs.max(60) as i64),
        None => start_wall.saturating_add(config.timeout_secs.max(60) as i64),
    };

    // Reject an absurdly distant `at_time` up front. Without this, a typo (wrong
    // year, extra digit) parks the run in the pre-fire wait loop indefinitely —
    // the loop's own deadline check can never fire, because `wait_deadline`
    // always lands *after* the prep window it guards.
    if let Some(at) = fire_at {
        let ahead = at.saturating_sub(start_wall);
        if ahead > MAX_SCHEDULE_AHEAD_SECS {
            return fail_all(
                signers,
                &format!(
                    "at_time is {} days in the future (max {} days) — check the date",
                    ahead / 86_400,
                    MAX_SCHEDULE_AHEAD_SECS / 86_400
                ),
            );
        }
    }

    report(
        &reporter,
        MintEvent::phase(
            "wait",
            format!(
                "PRE-SIGN RACE · contract={:?} qty={} gas_limit={} wallets={} at_time={:?}",
                config.contract,
                config.quantity,
                gas_limit,
                signers.len(),
                fire_at
            ),
        ),
    );
    report(
        &reporter,
        MintEvent::message(format!(
            "Mode: pre-sign → clock fire → blast | dry_run={} | no estimate/getMintStatus at T0",
            config.dry_run
        )),
    );

    // ── Wait until prep window (at_time − PREP_LEAD) ──
    if let Some(at) = fire_at {
        let prep_at = at.saturating_sub(PREP_LEAD_SECS);
        if now_unix() < prep_at {
            report(
                &reporter,
                MintEvent::message(format!(
                    "Waiting until prep T−{PREP_LEAD_SECS}s (fire at {at}, now {})…",
                    now_unix()
                )),
            );
            // Log every ~10s while waiting
            loop {
                if cancelled(&cancel) {
                    return fail_all(signers, "cancelled by user");
                }
                let now = now_unix();
                if now >= prep_at {
                    break;
                }
                if now > wait_deadline {
                    return fail_all(signers, "timeout before prep window");
                }
                let left = prep_at - now;
                if left % 10 == 0 || left <= 5 {
                    report(
                        &reporter,
                        MintEvent::message(format!(
                            "clock: prep in {left}s · fire in {}s",
                            at - now
                        )),
                    );
                }
                if let Err(e) = sleep_until_unix((now + 1).min(prep_at), &cancel).await {
                    return fail_all(signers, e);
                }
            }
        }
    }

    if cancelled(&cancel) {
        return fail_all(signers, "cancelled by user");
    }

    // ── Resolve value at prep time (MintBay auto once — not a fire gate) ──
    let (value, value_detail) = resolve_mint_value(rpc, config).await;
    report(
        &reporter,
        MintEvent::message(format!("Value: {value_detail}")),
    );

    // ── PRE-SIGN all wallets ──
    report(
        &reporter,
        MintEvent::phase(
            "prep",
            format!(
                "Pre-signing {} wallet(s) · gas_limit={gas_limit} · value={value} wei",
                signers.len()
            ),
        ),
    );

    let sem = Arc::new(Semaphore::new(concurrency));
    let mut prep_handles = Vec::new();

    for signer in signers.iter() {
        let signer = signer.clone();
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let rpc = rpc.clone();
        let calldata = calldata.clone();
        let contract = config.contract;
        let rep = reporter.clone();
        let cancel_w = cancel.clone();

        prep_handles.push(tokio::spawn(async move {
            let _permit = permit;
            let addr = signer.address();
            let fail = |e: String| Err((addr, e));

            if cancelled(&cancel_w) {
                return fail("cancelled by user".into());
            }

            report(
                &rep,
                MintEvent::wallet(
                    addr,
                    Some(WalletStatus::Wait),
                    Some("pre-sign".into()),
                    None,
                    None,
                ),
            );

            let nonce = match rpc.nonce(&addr).await {
                Ok(n) => n,
                Err(e) => return fail(format!("nonce: {e}")),
            };

            let tx = BuiltTx {
                chain_id,
                nonce,
                to: contract,
                value,
                data: calldata,
                gas_limit,
                max_fee,
                max_priority_fee,
            };

            let (raw, hash) = match sign_transaction(&signer, &tx) {
                Ok(x) => x,
                Err(e) => return fail(format!("sign: {e}")),
            };

            report(
                &rep,
                MintEvent::wallet(
                    addr,
                    Some(WalletStatus::Sim),
                    Some(format!(
                        "signed {} nonce={nonce} gas={gas_limit}",
                        shorten_hash(&hash)
                    )),
                    Some(hash),
                    None,
                ),
            );

            Ok(PreSigned {
                address: addr,
                raw,
                hash,
                nonce,
                early_hash: None,
            })
        }));
    }

    let mut prepared: Vec<PreSigned> = Vec::new();
    let mut prep_fails: Vec<MintResult> = Vec::new();
    for h in prep_handles {
        match h.await {
            Ok(Ok(ps)) => prepared.push(ps),
            Ok(Err((addr, e))) => {
                prep_fails.push(MintResult {
                    address: addr,
                    tx_hash: None,
                    status: WalletStatus::Failed,
                    gas_used: None,
                    block_number: None,
                    error: Some(e),
                });
            }
            Err(e) => {
                crate::rlog!("pre-sign task join error: {e}");
            }
        }
    }

    if prepared.is_empty() {
        report(
            &reporter,
            MintEvent::phase("error", "Pre-sign failed for all wallets"),
        );
        return prep_fails;
    }

    report(
        &reporter,
        MintEvent::message(format!(
            "Pre-signed {}/{} · ready to fire",
            prepared.len(),
            signers.len()
        )),
    );

    // Dry-run: stop after sign (no broadcast)
    if config.dry_run {
        let mut results = prep_fails;
        for ps in prepared {
            report(
                &reporter,
                MintEvent::wallet(
                    ps.address,
                    Some(WalletStatus::DryRunOk),
                    Some(format!("pre-signed {}", shorten_hash(&ps.hash))),
                    Some(ps.hash),
                    None,
                ),
            );
            results.push(MintResult {
                address: ps.address,
                tx_hash: Some(ps.hash),
                status: WalletStatus::DryRunOk,
                gas_used: Some(gas_limit),
                block_number: None,
                error: None,
            });
        }
        report(
            &reporter,
            MintEvent::phase(
                "done",
                format!("Dry-run pre-sign OK: {}/{}", results.len(), signers.len()),
            ),
        );
        return results;
    }

    // ── Clock fire ──
    //
    // With a push lead the wake-up moves earlier by the lead plus a margin for
    // the fee refresh, so the loop below starts pushing on time with fees that
    // are current rather than five seconds old.
    let (push_lead_ms, push_interval_ms) = push_plan(config.push_lead_ms, config.push_interval_ms);
    let wake_offset_ms = if push_lead_ms > 0 {
        push_lead_ms + PUSH_FEE_MARGIN_MS
    } else {
        0
    };
    // Correct the clock before waiting on it, not after.
    if let Some(at) = fire_at {
        if at.saturating_mul(1_000).saturating_sub(now_unix_ms())
            > crate::timing::CLOCK_SYNC_MIN_LEAD_MS
        {
            report(
                &reporter,
                MintEvent::message(crate::timing::sync_clock().await),
            );
        }
    }

    if let Some(at) = fire_at {
        let now = now_unix();
        if now < at {
            report(
                &reporter,
                MintEvent::phase(
                    "wait",
                    format!("Armed — firing in {}s (clock {at})", at - now),
                ),
            );
            let wake_ms = at
                .saturating_mul(1000)
                .saturating_sub(wake_offset_ms as i64);
            if let Err(e) = sleep_until_ms(wake_ms, &cancel).await {
                return fail_all(signers, e);
            }
        } else {
            report(
                &reporter,
                MintEvent::message(format!(
                    "at_time already passed by {}s — firing immediately",
                    now - at
                )),
            );
        }
    }

    if cancelled(&cancel) {
        return fail_all(signers, "cancelled by user");
    }

    // Fee refresh at fire: default MainnetOnly (no L2 latency); Always/Never via config.
    if should_refresh_fees_at_fire(chain_id, config.fee_refresh) {
        match rpc.fee_history().await {
            Ok((base, prio)) => match gas::calculate_fees(&config.gas, base, prio) {
                Ok((mf, pf)) => {
                    let bump_fee = mf > max_fee;
                    let bump_prio = pf > max_priority_fee;
                    if bump_fee || bump_prio {
                        let old_fee = max_fee;
                        let old_prio = max_priority_fee;
                        if bump_fee {
                            max_fee = mf;
                        }
                        if bump_prio {
                            max_priority_fee = pf;
                        }
                        report(
                            &reporter,
                            MintEvent::message(format!(
                                "fee refresh (mode={}): max_fee {}→{} gwei prio {}→{} gwei — re-signing {}",
                                config.fee_refresh.as_str(),
                                old_fee / U256::from(1_000_000_000u64),
                                max_fee / U256::from(1_000_000_000u64),
                                old_prio / U256::from(1_000_000_000u64),
                                max_priority_fee / U256::from(1_000_000_000u64),
                                prepared.len()
                            )),
                        );
                        let mut resign_ok = 0usize;
                        for ps in prepared.iter_mut() {
                            let Some(signer) = signers.iter().find(|s| s.address() == ps.address)
                            else {
                                continue;
                            };
                            let tx = BuiltTx {
                                chain_id,
                                nonce: ps.nonce,
                                to: config.contract,
                                value,
                                data: calldata.clone(),
                                gas_limit,
                                max_fee,
                                max_priority_fee,
                            };
                            match sign_transaction(signer, &tx) {
                                Ok((raw, hash)) => {
                                    ps.raw = raw;
                                    ps.hash = hash;
                                    resign_ok += 1;
                                }
                                Err(e) => {
                                    report(
                                        &reporter,
                                        MintEvent::message(format!(
                                            "[{:?}] re-sign failed (keeping prep): {e}",
                                            ps.address
                                        )),
                                    );
                                }
                            }
                        }
                        report(
                            &reporter,
                            MintEvent::message(format!("re-signed {resign_ok}/{}", prepared.len())),
                        );
                    } else {
                        report(
                            &reporter,
                            MintEvent::message("fee refresh: no increase — using prep signatures"),
                        );
                    }
                }
                Err(e) => {
                    report(
                        &reporter,
                        MintEvent::message(format!(
                            "fee refresh calc failed ({e}) — using prep fees"
                        )),
                    );
                }
            },
            Err(e) => {
                report(
                    &reporter,
                    MintEvent::message(format!(
                        "fee_history at fire failed ({e}) — using prep fees"
                    )),
                );
            }
        }
    } else {
        report(
            &reporter,
            MintEvent::message(format!(
                "fee refresh skipped (mode={}, chainId={})",
                config.fee_refresh.as_str(),
                chain_id
            )),
        );
    }

    // ── Early push ──
    //
    // `at_time` is read off the local clock, and the chain opens on its own: a
    // machine 800ms slow fires eight blocks late with nothing in the log to say
    // so. For the last stretch we therefore stop trusting the clock and let the
    // node answer instead.
    //
    // Every knock before the open carries `timestampMin`, which the node
    // refuses outright — no gas, no nonce spent, and the same signed bytes go
    // again next round. A knock is not a probe: it *is* that wallet's mint
    // attempt, which is why every wallet knocks for itself rather than waiting
    // on a scout. Waiting would cost them the answer's flight home plus their
    // own flight out, where knocking costs one interval.
    if push_lead_ms > 0 {
        if let Some(at) = fire_at {
            let open_ms = at.saturating_mul(1000);
            let deadline_ms = open_ms + PUSH_TAIL_MS as i64;
            let total = prepared.len();
            report(
                &reporter,
                MintEvent::phase(
                    "fire",
                    format!(
                        "EARLY PUSH T-{}ms · every {}ms · tail +{}ms · {} tx(s)",
                        push_lead_ms, push_interval_ms, PUSH_TAIL_MS, total
                    ),
                ),
            );
            let started_ms = now_unix_ms();
            let mut jobs = tokio::task::JoinSet::new();
            for (idx, ps) in prepared.iter().enumerate() {
                let rpc = rpc.clone();
                let raw = ps.raw.clone();
                let cancel = cancel.clone();
                let offset = push_stagger_ms(idx, total, push_interval_ms);
                jobs.spawn(async move {
                    // Spread the wallets across the interval so the node answers
                    // one or two at a time instead of queueing all of them.
                    if offset > 0 {
                        tokio::time::sleep(Duration::from_millis(offset)).await;
                    }
                    let mut knocks = 0u32;
                    loop {
                        if cancelled(&cancel) || now_unix_ms() >= deadline_ms {
                            return (idx, None, None, knocks);
                        }
                        knocks += 1;
                        match rpc
                            .send_raw_transaction_conditional(&raw, at.max(0) as u64)
                            .await
                        {
                            Ok(hash) => return (idx, Some(hash), None, knocks),
                            Err(e) => {
                                let msg = e.to_string();
                                // "Not yet" is the expected answer and the whole
                                // point; anything else means the mechanism is
                                // not available and knocking cannot help.
                                if !is_condition_not_met(&msg) {
                                    return (idx, None, Some(msg), knocks);
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(push_interval_ms)).await;
                    }
                });
            }

            let mut accepted = 0usize;
            let mut knocks_total = 0u32;
            let mut broken: Option<String> = None;
            while let Some(joined) = jobs.join_next().await {
                let Ok((idx, hash, err, knocks)) = joined else {
                    continue;
                };
                knocks_total += knocks;
                if let Some(hash) = hash {
                    prepared[idx].early_hash = Some(hash);
                    accepted += 1;
                    report(
                        &reporter,
                        MintEvent::wallet(
                            prepared[idx].address,
                            Some(WalletStatus::Sent),
                            Some(format!(
                                "EARLY SEND OK {} (T{:+}ms, knock {})",
                                shorten_hash(&hash),
                                now_unix_ms() - open_ms,
                                knocks
                            )),
                            Some(hash),
                            None,
                        ),
                    );
                } else if let Some(msg) = err {
                    if broken.is_none() {
                        broken = Some(msg);
                    }
                }
            }
            if cancelled(&cancel) {
                // Do NOT blanket fail_all: wallets whose tx was already accepted
                // into the mempool (early_hash set) are live and will very likely
                // mine. Discarding their hashes here would report confirmed/pending
                // mints as losses and lose the hash needed to verify — risking a
                // double mint on a manual retry. Keep the accepted ones as Sent
                // (carrying the hash); fail only those never accepted.
                return prepared
                    .iter()
                    .map(|p| match p.early_hash {
                        Some(hash) => MintResult {
                            address: p.address,
                            tx_hash: Some(hash),
                            status: WalletStatus::Sent,
                            gas_used: None,
                            block_number: None,
                            error: None,
                        },
                        None => MintResult {
                            address: p.address,
                            tx_hash: None,
                            status: WalletStatus::Failed,
                            gas_used: None,
                            block_number: None,
                            error: Some("cancelled by user".into()),
                        },
                    })
                    .collect();
            }
            if let Some(msg) = broken.filter(|_| accepted == 0) {
                report(
                    &reporter,
                    MintEvent::message(format!(
                        "early push unavailable ({msg}) — falling back to the T0 blast"
                    )),
                );
            }
            report(
                &reporter,
                MintEvent::message(format!(
                    "early push: {}/{} accepted, {} knock(s) over {}ms",
                    accepted,
                    total,
                    knocks_total,
                    now_unix_ms() - started_ms
                )),
            );
        }
    }

    report(
        &reporter,
        MintEvent::phase(
            "fire",
            format!(
                "BLAST {} pre-signed tx(s) @ t={}",
                prepared.len(),
                now_unix_ms()
            ),
        ),
    );

    // ── Parallel send only ──
    let send_sem = Arc::new(Semaphore::new(concurrency));
    let mut send_handles = Vec::new();

    for ps in prepared {
        let permit = match send_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let rpc = rpc.clone();
        let rep = reporter.clone();

        send_handles.push(tokio::spawn(async move {
            let addr = ps.address;
            let signed_hash = ps.hash;

            // Send first — only then report Sent with real RPC hash. A tx the
            // early push already placed is not sent twice; re-sending the same
            // bytes would only earn "already known" and muddy the report.
            let send_res = match ps.early_hash {
                Some(hash) => Ok(hash),
                None => rpc.race_send(&ps.raw).await,
            };
            // Release the send slot *before* polling for a receipt. Holding it
            // across `wait_for_receipt` (up to 90s) serialized the blast: with
            // more wallets than `concurrency`, wallet N+1 could not fire until
            // an earlier wallet's receipt landed, so it missed the drop entirely.
            drop(permit);
            match send_res {
                Ok(tx_hash) => {
                    report(
                        &rep,
                        MintEvent::wallet(
                            addr,
                            Some(WalletStatus::Sent),
                            Some(format!("SEND OK {}", shorten_hash(&tx_hash))),
                            Some(tx_hash),
                            None,
                        ),
                    );
                    // Receipt off hot path
                    match rpc.wait_for_receipt(&tx_hash, 90).await {
                        Ok(receipt) => {
                            let info = crate::rpc::parse_receipt(&receipt);
                            if info.success {
                                report(
                                    &rep,
                                    MintEvent::wallet(
                                        addr,
                                        Some(WalletStatus::Confirmed),
                                        Some(format!("block={}", info.block_number)),
                                        Some(tx_hash),
                                        None,
                                    ),
                                );
                                MintResult {
                                    address: addr,
                                    tx_hash: Some(tx_hash),
                                    status: WalletStatus::Confirmed,
                                    gas_used: Some(info.gas_used),
                                    block_number: Some(info.block_number),
                                    error: None,
                                }
                            } else {
                                report(
                                    &rep,
                                    MintEvent::wallet(
                                        addr,
                                        Some(WalletStatus::Failed),
                                        Some("reverted".into()),
                                        Some(tx_hash),
                                        Some("reverted".into()),
                                    ),
                                );
                                MintResult {
                                    address: addr,
                                    tx_hash: Some(tx_hash),
                                    status: WalletStatus::Failed,
                                    gas_used: Some(info.gas_used),
                                    block_number: Some(info.block_number),
                                    error: Some("reverted".into()),
                                }
                            }
                        }
                        Err(e) => {
                            report(
                                &rep,
                                MintEvent::wallet(
                                    addr,
                                    Some(WalletStatus::Sent),
                                    Some(format!("receipt timeout: {e}")),
                                    Some(tx_hash),
                                    Some(format!("receipt: {e}")),
                                ),
                            );
                            MintResult {
                                address: addr,
                                tx_hash: Some(tx_hash),
                                status: WalletStatus::Sent,
                                gas_used: None,
                                block_number: None,
                                error: Some(format!("receipt: {e}")),
                            }
                        }
                    }
                }
                Err(e) => {
                    // A send error is not proof the transaction never left. The
                    // request may have been accepted and only the response
                    // lost — with one configured endpoint a timeout is the only
                    // failure this path ever sees. Reporting Failed with no hash
                    // discarded the one thing needed to check, so a mined mint
                    // could be reported as a loss.
                    let err_s = format!("{e}");
                    match crate::errors::classify_send_failure(&err_s) {
                        crate::errors::SendOutcome::Rejected => {
                            // Provably never entered a pool (no funds, revert,
                            // intrinsic gas): the local hash is meaningless.
                            report(
                                &rep,
                                MintEvent::wallet(
                                    addr,
                                    Some(WalletStatus::Failed),
                                    Some(format!("send rejected {}", shorten_hash(&signed_hash))),
                                    None,
                                    Some(format!("send: {err_s}")),
                                ),
                            );
                            MintResult {
                                address: addr,
                                tx_hash: None,
                                status: WalletStatus::Failed,
                                gas_used: None,
                                block_number: None,
                                error: Some(format!("send: {err_s}")),
                            }
                        }
                        outcome => {
                            // Accepted ("already known") or ambiguous: ask the
                            // chain before calling it either way.
                            let accepted = matches!(
                                outcome,
                                crate::errors::SendOutcome::Accepted
                            );
                            report(
                                &rep,
                                MintEvent::wallet(
                                    addr,
                                    Some(WalletStatus::Sent),
                                    Some(if accepted {
                                        "already known — awaiting receipt".to_string()
                                    } else {
                                        "send unclear — checking chain".to_string()
                                    }),
                                    Some(signed_hash),
                                    None,
                                ),
                            );
                            match rpc.wait_for_receipt(&signed_hash, 90).await {
                                Ok(receipt) => {
                                    let info = crate::rpc::parse_receipt(&receipt);
                                    let status = if info.success {
                                        WalletStatus::Confirmed
                                    } else {
                                        WalletStatus::Failed
                                    };
                                    report(
                                        &rep,
                                        MintEvent::wallet(
                                            addr,
                                            Some(status),
                                            Some(format!("block={}", info.block_number)),
                                            Some(signed_hash),
                                            if info.success {
                                                None
                                            } else {
                                                Some("reverted".into())
                                            },
                                        ),
                                    );
                                    MintResult {
                                        address: addr,
                                        tx_hash: Some(signed_hash),
                                        status,
                                        gas_used: Some(info.gas_used),
                                        block_number: Some(info.block_number),
                                        error: if info.success {
                                            None
                                        } else {
                                            Some("reverted".into())
                                        },
                                    }
                                }
                                Err(wait_err) => {
                                    // Still unknown. Keep the hash and report
                                    // Sent, never Failed: the operator can look
                                    // the transaction up, and a later sweep or
                                    // manual check can settle it.
                                    let msg = format!(
                                        "send error ({err_s}); fate unknown after receipt wait: {wait_err}"
                                    );
                                    report(
                                        &rep,
                                        MintEvent::wallet(
                                            addr,
                                            Some(WalletStatus::Sent),
                                            Some("unresolved — check the hash".into()),
                                            Some(signed_hash),
                                            Some(msg.clone()),
                                        ),
                                    );
                                    MintResult {
                                        address: addr,
                                        tx_hash: Some(signed_hash),
                                        status: WalletStatus::Sent,
                                        gas_used: None,
                                        block_number: None,
                                        error: Some(msg),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }));
    }

    let mut results = prep_fails;
    for h in send_handles {
        match h.await {
            Ok(r) => results.push(r),
            Err(e) => crate::rlog!("send task join error: {e}"),
        }
    }

    report(
        &reporter,
        MintEvent::phase(
            "done",
            format!(
                "Race done: {}/{} ok",
                results
                    .iter()
                    .filter(|r| matches!(
                        r.status,
                        WalletStatus::Confirmed | WalletStatus::DryRunOk | WalletStatus::Sent
                    ))
                    .count(),
                results.len()
            ),
        ),
    );

    results
}

fn fail_all(signers: &[Signer], err: impl Into<String>) -> Vec<MintResult> {
    let err = err.into();
    signers
        .iter()
        .map(|s| MintResult {
            address: s.address(),
            tx_hash: None,
            status: WalletStatus::Failed,
            gas_used: None,
            block_number: None,
            error: Some(err.clone()),
        })
        .collect()
}

/// Parse at_time string for API layer.
pub fn parse_sniper_at_time(raw: Option<&str>) -> Result<Option<i64>> {
    match raw {
        None => Ok(None),
        Some(s) => parse_at_time_unix(s).map_err(|e| anyhow::anyhow!(e)),
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_lead_of_zero_leaves_the_old_behaviour_alone() {
        // Nothing to push means nothing to schedule, so the interval must not
        // quietly turn the loop on.
        assert_eq!(push_plan(0, 100), (0, 0));
        assert_eq!(push_plan(0, 0), (0, 0));
    }

    #[test]
    fn the_lead_cannot_outrun_the_pre_sign() {
        // Pre-signing starts at T-5s; a lead past that would push bytes that do
        // not exist yet, so it is capped rather than trusted.
        let (lead, _) = push_plan(60_000, 100);
        assert_eq!(lead, MAX_PUSH_LEAD_MS);
        assert!(
            (MAX_PUSH_LEAD_MS as i64) < PREP_LEAD_SECS * 1_000,
            "the push window has to sit inside the pre-signed stretch"
        );
    }

    #[test]
    fn the_interval_stays_between_a_flood_and_a_block() {
        assert_eq!(push_plan(1_000, 0).1, 5);
        assert_eq!(push_plan(1_000, 9_999).1, 1_000);
        assert_eq!(push_plan(1_000, 40).1, 40);
    }

    #[test]
    fn wallets_are_spread_across_the_interval_not_stacked_on_one_tick() {
        // Fifty wallets on the same tick is what put the node into a queue
        // during measurement, so no two may share an offset when they fit.
        let offsets: Vec<u64> = (0..5).map(|i| push_stagger_ms(i, 5, 15)).collect();
        assert_eq!(offsets, vec![0, 3, 6, 9, 12]);
        assert!(
            offsets.iter().all(|o| *o < 15),
            "an offset may not skip a whole interval"
        );
    }

    #[test]
    fn a_lone_wallet_does_not_wait_for_a_stagger_slot() {
        assert_eq!(push_stagger_ms(0, 1, 15), 0);
        assert_eq!(push_stagger_ms(0, 0, 15), 0);
    }

    #[test]
    fn waiting_is_told_apart_from_breaking() {
        // The refusal before the open is the expected answer and must not be
        // read as the mechanism being unavailable.
        assert!(is_condition_not_met("TimestampMin condition not met"));
        assert!(is_condition_not_met("BlockNumberMin condition not met"));
        assert!(!is_condition_not_met(
            "the method eth_sendRawTransactionConditional does not exist/is not available"
        ));
        assert!(!is_condition_not_met(
            "insufficient funds for gas * price + value"
        ));
    }
    use super::*;

    #[test]
    fn u256_to_i64_sat_saturates() {
        assert_eq!(u256_to_i64_sat(U256::from(1000u64)), 1000);
        assert_eq!(u256_to_i64_sat(U256::ZERO), 0);
        assert_eq!(u256_to_i64_sat(U256::from(i64::MAX as u64)), i64::MAX);
        // Above i64::MAX but within u64, and far beyond u64 — both clamp to i64::MAX.
        assert_eq!(u256_to_i64_sat(U256::from(u64::MAX)), i64::MAX);
        assert_eq!(u256_to_i64_sat(U256::MAX), i64::MAX);
    }

    #[test]
    fn u256_to_u8_sat_saturates() {
        assert_eq!(u256_to_u8_sat(U256::from(5u64)), 5);
        assert_eq!(u256_to_u8_sat(U256::from(255u64)), 255);
        assert_eq!(u256_to_u8_sat(U256::from(300u64)), 255);
        assert_eq!(u256_to_u8_sat(U256::MAX), 255);
    }

    #[test]
    fn parse_sniper_at_time_forms() {
        assert_eq!(parse_sniper_at_time(None).unwrap(), None);
        assert_eq!(
            parse_sniper_at_time(Some("1700000000")).unwrap(),
            Some(1_700_000_000)
        );
        // milliseconds are normalized to seconds
        assert_eq!(
            parse_sniper_at_time(Some("1700000000000")).unwrap(),
            Some(1_700_000_000)
        );
        assert_eq!(parse_sniper_at_time(Some("  ")).unwrap(), None);
        assert!(parse_sniper_at_time(Some("not-a-time")).is_err());
    }

    fn cfg(function: &str, params: Vec<String>, quantity: u64) -> RawSniperConfig {
        RawSniperConfig {
            function: function.to_string(),
            params,
            quantity,
            ..Default::default()
        }
    }

    #[test]
    fn build_mint_params_uint256_uses_quantity() {
        let p = build_mint_params(&cfg("mint(uint256)", vec![], 3)).unwrap();
        assert_eq!(p, vec!["3"]);
        // quantity floored to at least 1
        let p = build_mint_params(&cfg("mint(uint256)", vec![], 0)).unwrap();
        assert_eq!(p, vec!["1"]);
    }

    #[test]
    fn build_mint_params_explicit_params_win() {
        let p = build_mint_params(&cfg(
            "claimTo(address,uint256)",
            vec!["0xabc".into(), "2".into()],
            9,
        ))
        .unwrap();
        assert_eq!(p, vec!["0xabc", "2"]);
    }

    #[test]
    fn build_mint_params_zero_arg() {
        let p = build_mint_params(&cfg("claim()", vec![], 5)).unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn build_mint_params_fallback_quantity() {
        // Non-uint, non-zero-arg, no explicit params → default to quantity word.
        let p = build_mint_params(&cfg("publicMint()", vec![], 4)).unwrap();
        assert!(p.is_empty(), "zero-arg still wins");
        let p = build_mint_params(&cfg("weird(bytes32)", vec![], 4)).unwrap();
        assert_eq!(p, vec!["4"]);
    }

    #[test]
    fn mintbay_public_open_logic() {
        let mut st = MintBayStatus {
            public_mint_price: U256::ZERO,
            max_supply: U256::from(100),
            total_minted: U256::from(1),
            collector_fee: U256::from(400_000_000_000_000u64),
            resolved_phase_id: U256::from(1),
            minting_paused: false,
            current_phase_type: 2,
            phase_start: U256::ZERO,
            phase_end: U256::ZERO,
            phase_mint_price: U256::ZERO,
        };
        assert!(st.is_public_open(1_700_000_000));
        st.current_phase_type = 1;
        assert!(!st.is_public_open(1_700_000_000));
        st.current_phase_type = 2;
        st.minting_paused = true;
        assert!(!st.is_public_open(1_700_000_000));
        st.minting_paused = false;
        st.total_minted = U256::from(100);
        assert!(!st.is_public_open(1_700_000_000));
    }

    #[test]
    fn mintbay_value_formula() {
        let st = MintBayStatus {
            public_mint_price: U256::ZERO,
            max_supply: U256::from(10),
            total_minted: U256::ZERO,
            collector_fee: U256::from(400_000_000_000_000u64), // 0.0004 eth
            resolved_phase_id: U256::from(1),
            minting_paused: false,
            current_phase_type: 2,
            phase_start: U256::ZERO,
            phase_end: U256::ZERO,
            phase_mint_price: U256::from(1_000_000_000_000_000u64), // 0.001
        };
        // (0.001 + 0.0004) * 2
        assert_eq!(st.mint_value(2), U256::from(2_800_000_000_000_000u64));
    }

    #[test]
    fn build_mint_params_uses_real_arity_not_substrings() {
        let cfg = |func: &str, params: Vec<String>| RawSniperConfig {
            function: func.to_string(),
            params,
            quantity: 3,
            ..Default::default()
        };

        // Zero-arg, including the non-canonical spellings the old substring
        // checks misread (a space between the parens got a spurious argument).
        assert_eq!(
            build_mint_params(&cfg("claim()", vec![])).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            build_mint_params(&cfg("claim( )", vec![])).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            build_mint_params(&cfg(" mint ( ) ", vec![])).unwrap(),
            Vec::<String>::new()
        );

        // Single numeric arg → quantity, canonical and shorthand alike.
        assert_eq!(
            build_mint_params(&cfg("mint(uint256)", vec![])).unwrap(),
            vec!["3"]
        );
        assert_eq!(
            build_mint_params(&cfg("mint(uint)", vec![])).unwrap(),
            vec!["3"]
        );
        assert_eq!(
            build_mint_params(&cfg("mint( uint256 )", vec![])).unwrap(),
            vec!["3"]
        );

        // Explicit params always win.
        assert_eq!(
            build_mint_params(&cfg(
                "mint(address,uint256)",
                vec!["0xabc".into(), "7".into()]
            ))
            .unwrap(),
            vec!["0xabc", "7"]
        );
    }

    /// Build a fake `getMintStatus()` return with `words` 32-byte slots, setting
    /// the given (index, value) pairs.
    fn mk_words(words: usize, set: &[(usize, u64)]) -> Vec<u8> {
        let mut raw = vec![0u8; words * 32];
        for (i, v) in set {
            let start = i * 32;
            raw[start + 24..start + 32].copy_from_slice(&v.to_be_bytes());
        }
        raw
    }

    #[test]
    fn v4_layout_decodes_17_words() {
        // V4: w4 collectorFee, w5 resolvedPhaseId, w12 phase.mintPrice
        let raw = mk_words(
            17,
            &[
                (4, 400_000_000_000_000),
                (5, 1),
                (12, 8_000_000_000_000_000),
            ],
        );
        let st = decode_mintbay_status_v4(&raw).unwrap();
        assert_eq!(st.collector_fee, U256::from(400_000_000_000_000u64));
        assert_eq!(st.resolved_phase_id, U256::from(1u64));
        assert_eq!(st.phase_mint_price, U256::from(8_000_000_000_000_000u64));
    }

    #[test]
    fn v3_layout_shifts_by_one_from_word_seven() {
        // V3 has an extra `bool isFreeMint`, so mintPrice lives at w13, not w12.
        // w12 holds phase.endTime — decoding it as a price is the money bug.
        let end_time = 1_800_000_000u64; // a unix timestamp, NOT a price
        let price = 8_000_000_000_000_000u64;
        let raw = mk_words(
            18,
            &[
                (4, 400_000_000_000_000),
                (5, 1),
                (12, end_time),
                (13, price),
            ],
        );
        let st = decode_mintbay_status_v3(&raw).unwrap();
        assert_eq!(st.phase_mint_price, U256::from(price), "must read w13");
        assert_eq!(st.phase_end, U256::from(end_time));
        // The V4 map on the same bytes would have taken the timestamp as the price.
        let wrong = decode_mintbay_status_v4(&raw).unwrap();
        assert_eq!(wrong.phase_mint_price, U256::from(end_time));
        assert_ne!(
            wrong.phase_mint_price, st.phase_mint_price,
            "this divergence is exactly what the length dispatch prevents"
        );
    }

    #[test]
    fn mint_value_uses_phase_price_when_phase_active() {
        let raw = mk_words(18, &[(4, 1_000), (5, 7), (13, 5_000)]);
        let st = decode_mintbay_status_v3(&raw).unwrap();
        // resolved_phase_id != 0 → (phase_price + collector_fee) * qty
        assert_eq!(st.mint_value(3), U256::from((5_000u64 + 1_000) * 3));
    }

    #[test]
    fn short_response_errors_instead_of_panicking() {
        let raw = mk_words(5, &[]);
        assert!(decode_mintbay_status_v4(&raw).is_err());
        assert!(decode_mintbay_status_v3(&raw).is_err());
    }
}
