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
    std::sync::Arc,
};

/// Bank-state inputs required by [`priority_and_cost`].
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
            // this has to be updated.
            burn_percent: solana_fee_calculator::DEFAULT_BURN_PERCENT as u64,
        }
    }
}

/// Calculate priority and cost for a transaction.
///
/// `priority = reward * MULTIPLIER / (1 + cost)` where:
/// - `cost = CostModel::calculate_cost(...).sum()`
/// - `reward = priority_fee + non_burned_share_of_base_fee` when the
///   base fee is non-zero; `reward = 0` when the base fee is zero
///   (via `solana_fee::split_reward_and_burn`'s zero-fee short-circuit;
///   affects test banks with `lamports_per_signature = 0`).
///
/// The `+1` in the denominator avoids divide-by-zero from a buggy
/// zero-cost return; cost-model results are bounded away from zero in
/// practice. The multiplier prevents losing precision when `cost > reward`.
pub fn priority_and_cost<Tx: TransactionMeta + SVMStaticMessage>(
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
    let (reward, _burn) = solana_fee::split_reward_and_burn(
        fee_details.transaction_fee(),
        fee_details.prioritization_fee(),
        fee_context.burn_percent,
    );

    const MULTIPLIER: u64 = 1_000_000;
    (
        reward
            .saturating_mul(MULTIPLIER)
            .saturating_div(cost.saturating_add(1)),
        cost,
    )
}

/// Priority value used for pf-floor comparison (dropping excessive load upstream
/// when the scheduler is saturated).
pub fn floor_priority<Tx: TransactionMeta + SVMStaticMessage>(
    transaction: &Tx,
    fee_context: &FeeContext,
) -> Option<u64> {
    let transaction_configuration = transaction
        .transaction_configuration(&fee_context.feature_set)
        .ok()?;
    let (priority, _cost) = priority_and_cost(transaction, &transaction_configuration, fee_context);
    Some(priority)
}

/// [`floor_priority`] starting from raw packet bytes.
pub fn floor_priority_from_bytes(data: &[u8], fee_context: &FeeContext) -> Option<u64> {
    let view = SanitizedTransactionView::try_new_sanitized(data, true).ok()?;
    let runtime_tx = RuntimeTransaction::<SanitizedTransactionView<_>>::try_new(
        view,
        MessageHash::Compute,
        None,
    )
    .ok()?;
    floor_priority(&runtime_tx, fee_context)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity check that `from_bank` always uses `DEFAULT_BURN_PERCENT` (the
    /// constant Bank itself derives from). If burn-percent ever becomes
    /// per-bank, this and the bank-side accessor need to update together.
    #[test]
    fn from_bank_uses_default_burn_percent() {
        use {
            solana_keypair::Keypair,
            solana_runtime::{bank::Bank, genesis_utils::create_genesis_config_with_leader},
            solana_signer::Signer,
        };
        let genesis_info =
            create_genesis_config_with_leader(1_000_000_000, &Keypair::new().pubkey(), 1);
        let (bank, _bank_forks) = Bank::new_with_bank_forks_for_tests(&genesis_info.genesis_config);
        assert_eq!(
            FeeContext::from_bank(&bank).burn_percent,
            solana_fee_calculator::DEFAULT_BURN_PERCENT as u64,
        );
    }
}
