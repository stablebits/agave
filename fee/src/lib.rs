#![cfg(feature = "agave-unstable-api")]
use {
    agave_feature_set::FeatureSet, solana_fee_structure::FeeDetails,
    solana_svm_transaction::svm_message::SVMStaticMessage,
};

/// Bools indicating the activation of features relevant
/// to the fee calculation.
// DEVELOPER NOTE:
// This struct may become empty at some point. It is preferable to keep it
// instead of removing, since fees will naturally be changed via feature-gates
// in the future. Keeping this struct will help keep things organized.
#[derive(Copy, Clone)]
pub struct FeeFeatures {}

impl From<&FeatureSet> for FeeFeatures {
    fn from(_feature_set: &FeatureSet) -> Self {
        Self {}
    }
}

/// Calculate fee for `SanitizedMessage`
pub fn calculate_fee(
    message: &impl SVMStaticMessage,
    lamports_per_signature: u64,
    prioritization_fee: u64,
    fee_features: FeeFeatures,
) -> u64 {
    calculate_fee_details(
        message,
        lamports_per_signature,
        prioritization_fee,
        fee_features,
    )
    .total_fee()
}

pub fn calculate_fee_details(
    message: &impl SVMStaticMessage,
    lamports_per_signature: u64,
    prioritization_fee: u64,
    _fee_features: FeeFeatures,
) -> FeeDetails {
    FeeDetails::new(
        calculate_signature_fee(SignatureCounts::from(message), lamports_per_signature),
        prioritization_fee,
    )
}

/// Split a transaction's collected fee into the leader's reward (deposit)
/// and the amount that should be burned, given a burn percentage. Single
/// source of truth for the runtime's fee-distribution math, also used by
/// the banking-stage scheduler's priority calculation and sigverify's
/// pf-floor proxy so they cannot drift from what the leader would actually
/// be paid.
///
/// Returns `(reward, burn)`. When `transaction_fee == 0`, returns
/// `(0, 0)` — mirrors the early-out in fee distribution and keeps test
/// banks with `lamports_per_signature == 0` consistent.
pub fn split_reward_and_burn(
    transaction_fee: u64,
    priority_fee: u64,
    burn_percent: u64,
) -> (u64, u64) {
    if transaction_fee == 0 {
        return (0, 0);
    }
    let burn = transaction_fee.saturating_mul(burn_percent) / 100;
    let reward = priority_fee.saturating_add(transaction_fee.saturating_sub(burn));
    (reward, burn)
}

/// Calculate fees from signatures.
pub fn calculate_signature_fee(
    SignatureCounts {
        num_transaction_signatures,
        num_ed25519_signatures,
        num_secp256k1_signatures,
        num_secp256r1_signatures,
    }: SignatureCounts,
    lamports_per_signature: u64,
) -> u64 {
    let signature_count = num_transaction_signatures
        .saturating_add(num_ed25519_signatures)
        .saturating_add(num_secp256k1_signatures)
        .saturating_add(num_secp256r1_signatures);
    signature_count.saturating_mul(lamports_per_signature)
}

pub struct SignatureCounts {
    pub num_transaction_signatures: u64,
    pub num_ed25519_signatures: u64,
    pub num_secp256k1_signatures: u64,
    pub num_secp256r1_signatures: u64,
}

impl<Tx: SVMStaticMessage> From<&Tx> for SignatureCounts {
    fn from(message: &Tx) -> Self {
        Self {
            num_transaction_signatures: message.num_transaction_signatures(),
            num_ed25519_signatures: message.num_ed25519_signatures(),
            num_secp256k1_signatures: message.num_secp256k1_signatures(),
            num_secp256r1_signatures: message.num_secp256r1_signatures(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reward_and_burn() {
        // Zero transaction fee → no reward, no burn (regardless of priority fee).
        assert_eq!(split_reward_and_burn(0, 0, 50), (0, 0));
        assert_eq!(split_reward_and_burn(0, 100, 50), (0, 0));

        // 50% burn (mainnet default): half of base fee burns, the rest plus
        // priority fee goes to the leader.
        assert_eq!(split_reward_and_burn(1000, 0, 50), (500, 500));
        assert_eq!(split_reward_and_burn(1000, 200, 50), (700, 500));

        // 100% burn: leader gets only the priority fee.
        assert_eq!(split_reward_and_burn(1000, 200, 100), (200, 1000));

        // 0% burn: leader gets the full fee.
        assert_eq!(split_reward_and_burn(1000, 200, 0), (1200, 0));
    }

    #[test]
    fn test_calculate_signature_fee() {
        const LAMPORTS_PER_SIGNATURE: u64 = 5_000;

        // Impossible case - 0 signatures.
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 0,
                    num_ed25519_signatures: 0,
                    num_secp256k1_signatures: 0,
                    num_secp256r1_signatures: 0,
                },
                LAMPORTS_PER_SIGNATURE,
            ),
            0
        );

        // Simple signature
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 1,
                    num_ed25519_signatures: 0,
                    num_secp256k1_signatures: 0,
                    num_secp256r1_signatures: 0,
                },
                LAMPORTS_PER_SIGNATURE,
            ),
            LAMPORTS_PER_SIGNATURE
        );

        // Pre-compile signatures.
        assert_eq!(
            calculate_signature_fee(
                SignatureCounts {
                    num_transaction_signatures: 1,
                    num_ed25519_signatures: 2,
                    num_secp256k1_signatures: 3,
                    num_secp256r1_signatures: 4,
                },
                LAMPORTS_PER_SIGNATURE,
            ),
            10 * LAMPORTS_PER_SIGNATURE
        );
    }
}
