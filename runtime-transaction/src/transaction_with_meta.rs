use {
    crate::transaction_meta::TransactionMeta,
    solana_svm_transaction::svm_transaction::SVMTransaction,
    solana_transaction::{sanitized::SanitizedTransaction, versioned::VersionedTransaction},
    std::borrow::Cow,
};

pub trait TransactionWithMeta: TransactionMeta + SVMTransaction {
    /// Required to interact with geyser plugins.
    /// This function should not be used except for interacting with geyser.
    /// It may do numerous allocations that negatively impact performance.
    fn as_sanitized_transaction(&self) -> Cow<'_, SanitizedTransaction>;
    /// Required to interact with several legacy interfaces that require
    /// `VersionedTransaction`. This should not be used unless necessary, as it
    /// performs numerous allocations that negatively impact performance.
    fn to_versioned_transaction(&self) -> VersionedTransaction;

    /// Returns the serialized transaction size in bytes.
    /// Runtime metadata is not included.
    fn serialized_size(&self) -> usize;

    /// Recompute and cache the transaction's message hash.
    ///
    /// Most transaction types compute their message hash at construction, so the default is a
    /// no-op. The scheduler's transaction-view receive path may defer this (storing a cheap
    /// placeholder) to keep the message-hash SHA256 off the hot receive thread; the consume
    /// worker calls this before the status-cache check / execution / commit, all of which key on
    /// `message_hash()`. Idempotent.
    fn recompute_message_hash(&mut self) {}
}
