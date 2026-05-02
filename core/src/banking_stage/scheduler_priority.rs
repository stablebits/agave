use {
    agave_transaction_view::transaction_view::SanitizedTransactionView,
    solana_cost_model::cost_model::CostModel,
    solana_fee::FeeFeatures,
    solana_runtime::bank::{Bank, CollectorFeeDetails},
    solana_runtime_transaction::{
        runtime_transaction::RuntimeTransaction,
        transaction_meta::{TransactionConfiguration, TransactionMeta},
    },
    solana_svm_transaction::svm_message::SVMStaticMessage,
    solana_transaction::sanitized::MessageHash,
};

/// Calculate priority and cost for a transaction:
///
/// Cost is calculated through the `CostModel`,
/// and priority is calculated through a formula here that attempts to sell
/// blockspace to the highest bidder.
///
/// The priority is calculated as:
/// P = R / (1 + C)
/// where P is the priority, R is the reward,
/// and C is the cost towards block-limits.
///
/// Current minimum costs are on the order of several hundred,
/// so the denominator is effectively C, and the +1 is simply
/// to avoid any division by zero due to a bug - these costs
/// are calculated by the cost-model and are not direct
/// from user input. They should never be zero.
/// Any difference in the prioritization is negligible for
/// the current transaction costs.
pub fn priority_and_cost<Tx: TransactionMeta + SVMStaticMessage>(
    transaction: &Tx,
    transaction_configuration: &TransactionConfiguration,
    bank: &Bank,
) -> (u64, u64) {
    let cost = CostModel::calculate_cost(transaction, &bank.feature_set).sum();
    let fee_details = solana_fee::calculate_fee_details(
        transaction,
        bank.fee_structure().lamports_per_signature,
        transaction_configuration.priority_fee_lamports,
        FeeFeatures::from(bank.feature_set.as_ref()),
    );
    let reward = bank
        .calculate_reward_and_burn_fee_details(&CollectorFeeDetails::from(fee_details))
        .get_deposit();

    // For many transactions, the cost will be greater than the fees in terms of raw lamports.
    // For the purposes of calculating prioritization, we multiply the fees by a large number so that
    // the cost is a small fraction.
    // An offset of 1 is used in the denominator to explicitly avoid division by zero.
    // We need a multiplier here to avoid rounding down too aggressively.
    // For many transactions, the cost will be greater than the fees in terms of raw lamports.
    // For the purposes of calculating prioritization, we multiply the fees by a large number so that
    // the cost is a small fraction.
    // An offset of 1 is used in the denominator to explicitly avoid division by zero.
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
    bank: &Bank,
) -> Option<u64> {
    let transaction_configuration = transaction
        .transaction_configuration(&bank.feature_set)
        .ok()?;
    let (priority, _cost) = priority_and_cost(transaction, &transaction_configuration, bank);
    Some(priority)
}

/// [`floor_priority`] starting from raw packet bytes.
pub fn floor_priority_from_bytes(data: &[u8], bank: &Bank) -> Option<u64> {
    let enable_instruction_accounts_limit = bank.feature_set.snapshot().limit_instruction_accounts;
    let view = SanitizedTransactionView::try_new_sanitized(data, enable_instruction_accounts_limit)
        .ok()?;
    let runtime_tx = RuntimeTransaction::<SanitizedTransactionView<_>>::try_new(
        view,
        MessageHash::Compute,
        None,
    )
    .ok()?;
    floor_priority(&runtime_tx, bank)
}
