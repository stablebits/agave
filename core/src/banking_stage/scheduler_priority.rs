//! Priority/cost formula shared between the banking-stage scheduler
//! (which has a `Bank` reference) and sigverify's pf-floor approximation
//! (which doesn't).
//!
//! The arithmetic in [`calculate_priority_and_cost`] is centralized so
//! the two callers cannot drift. The bank-state inputs are still
//! approximated when invoked from sigverify (no `Bank` available there);
//! [`FeeContext::mainnet_defaults`] supplies stable mainnet values for
//! `lamports_per_signature` and `burn_percent`, and `FeatureSet::all_enabled`
//! for the feature-flag-dependent parts of the cost / fee calculation.
//! The mismatch is bounded and load-shedding-only — no correctness impact
//! on accepted transactions.
use {
    agave_feature_set::FeatureSet,
    agave_transaction_view::transaction_view::SanitizedTransactionView,
    solana_cost_model::cost_model::CostModel,
    solana_fee::FeeFeatures,
    solana_runtime::bank::Bank,
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction,
        transaction_meta::{TransactionConfiguration, TransactionMeta},
    },
    solana_svm_transaction::svm_message::SVMStaticMessage,
    solana_transaction::sanitized::MessageHash,
    std::sync::{Arc, LazyLock},
};

/// Bank-state inputs needed by [`calculate_priority_and_cost`]. Lets
/// callers without a live `Bank` (sigverify's pf-floor) invoke the
/// same priority formula by supplying a constants snapshot.
#[derive(Clone)]
pub struct FeeContext {
    pub feature_set: Arc<FeatureSet>,
    pub lamports_per_signature: u64,
    pub burn_percent: u64,
}

impl FeeContext {
    pub fn from_bank(bank: &Bank) -> Self {
        Self {
            feature_set: bank.feature_set.clone(),
            lamports_per_signature: bank.fee_structure().lamports_per_signature,
            // `Bank::burn_percent` is private; we use the same constant
            // it derives from. If burn percent ever becomes per-bank,
            // this and the bank-side reach for the value need to update
            // together.
            burn_percent: solana_fee_calculator::DEFAULT_BURN_PERCENT as u64,
        }
    }

    /// Constants snapshot for callers without a `Bank`. Mismatches
    /// against an actual bank are load-shedding-only.
    pub fn mainnet_defaults() -> Self {
        Self {
            feature_set: Arc::new(FeatureSet::all_enabled()),
            lamports_per_signature: 5_000,
            burn_percent: solana_fee_calculator::DEFAULT_BURN_PERCENT as u64,
        }
    }
}

/// Constants snapshot used by sigverify's pf-floor proxy metric.
pub static MAINNET_FEE_CONTEXT: LazyLock<FeeContext> = LazyLock::new(FeeContext::mainnet_defaults);

/// Calculate priority and cost for a transaction.
///
/// `priority = reward * MULTIPLIER / (1 + cost)` where:
/// - `cost = CostModel::calculate_cost(...).sum()`
/// - `reward = priority_fee + non_burned_share_of_base_fee` when the
///   base fee is non-zero; `reward = 0` when the base fee is zero
///   (matches `Bank::calculate_reward_and_burn_fee_details`'s
///   short-circuit; affects test banks with `lamports_per_signature = 0`).
///
/// The `+1` in the denominator avoids divide-by-zero from a buggy
/// zero-cost return; cost-model results are bounded away from zero in
/// practice. The multiplier prevents losing precision when `cost > reward`.
pub fn calculate_priority_and_cost<Tx: TransactionMeta + SVMStaticMessage>(
    transaction: &Tx,
    transaction_configuration: &TransactionConfiguration,
    fee_context: &FeeContext,
) -> (u64, u64) {
    let cost = CostModel::calculate_cost(transaction, &fee_context.feature_set).sum();
    let fee_details = solana_fee::calculate_fee_details(
        transaction,
        fee_context.lamports_per_signature,
        transaction_configuration.priority_fee_lamports,
        FeeFeatures::from(fee_context.feature_set.as_ref()),
    );
    // Match `Bank::calculate_reward_and_burn_fee_details`: when there is
    // no base fee (e.g. test bank with `lamports_per_signature = 0`),
    // reward is zero regardless of priority_fee.
    if fee_details.transaction_fee() == 0 {
        return (0, cost);
    }
    let burn = fee_details
        .transaction_fee()
        .saturating_mul(fee_context.burn_percent)
        / 100;
    let reward = fee_details
        .prioritization_fee()
        .saturating_add(fee_details.transaction_fee().saturating_sub(burn));

    const MULTIPLIER: u64 = 1_000_000;
    (
        reward
            .saturating_mul(MULTIPLIER)
            .saturating_div(cost.saturating_add(1)),
        cost,
    )
}

/// Calculate the pf-floor proxy priority used by sigverify.
///
/// Runs the shared formula against [`MAINNET_FEE_CONTEXT`] instead of a
/// live bank snapshot. This keeps the scheduler-published floor and the
/// sigverify / receive-side drop checks in the same full-formula comparison
/// space, independent of bank-vs-mainnet fee-context drift.
pub fn calculate_pf_drop_priority<Tx: TransactionMeta + SVMStaticMessage>(
    transaction: &Tx,
) -> Option<u64> {
    let transaction_configuration = transaction
        .transaction_configuration(&MAINNET_FEE_CONTEXT.feature_set)
        .ok()?;
    let (priority, _cost) = calculate_priority_and_cost(
        transaction,
        &transaction_configuration,
        &MAINNET_FEE_CONTEXT,
    );
    Some(priority)
}

/// Approximate banking-stage priority for a packet from raw bytes.
///
/// Parses the packet into a `SanitizedTransactionView` + `RuntimeTransaction`
/// and runs [`calculate_pf_drop_priority`]. This is the entry point sigverify
/// uses for its pf-floor check; lives here (rather than next to sigverify)
/// so sigverify_stage doesn't pull in transaction-parsing dependencies just
/// for one helper.
///
/// Returns `None` if the packet cannot be parsed; callers should leave such
/// packets alone (they will be rejected downstream if genuinely invalid).
pub fn approximate_priority(data: &[u8]) -> Option<u64> {
    let view = SanitizedTransactionView::try_new_sanitized(data, true).ok()?;
    let runtime_tx = RuntimeTransaction::<SanitizedTransactionView<_>>::try_new(
        view,
        MessageHash::Compute,
        None,
    )
    .ok()?;
    calculate_pf_drop_priority(&runtime_tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the constants the sigverify pf-floor relies on. If `mainnet_defaults`
    /// drifts from observed mainnet values, sigverify's drop floor would
    /// systematically miss its target on a real cluster.
    #[test]
    fn mainnet_defaults_constants() {
        let ctx = FeeContext::mainnet_defaults();
        assert_eq!(ctx.lamports_per_signature, 5_000);
        assert_eq!(
            ctx.burn_percent,
            solana_fee_calculator::DEFAULT_BURN_PERCENT as u64,
        );
    }

    /// Sanity check that `from_bank` always uses `DEFAULT_BURN_PERCENT` (the
    /// constant Bank itself derives from). If burn-percent ever becomes
    /// per-bank, this and the bank-side accessor need to update together.
    #[test]
    fn from_bank_uses_default_burn_percent() {
        use solana_keypair::Keypair;
        use solana_runtime::{bank::Bank, genesis_utils::create_genesis_config_with_leader};
        use solana_signer::Signer;
        let genesis_info =
            create_genesis_config_with_leader(1_000_000_000, &Keypair::new().pubkey(), 1);
        let (bank, _bank_forks) = Bank::new_with_bank_forks_for_tests(&genesis_info.genesis_config);
        assert_eq!(
            FeeContext::from_bank(&bank).burn_percent,
            solana_fee_calculator::DEFAULT_BURN_PERCENT as u64,
        );
    }
}
