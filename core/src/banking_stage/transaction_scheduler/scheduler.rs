use {
    super::{
        scheduler_common::SchedulingCommon, scheduler_error::SchedulerError,
        transaction_state_container::StateContainer,
    },
    solana_runtime_transaction::transaction_with_meta::TransactionWithMeta,
    std::num::Saturating,
};

pub(crate) trait Scheduler<Tx: TransactionWithMeta> {
    /// Schedule transactions from `container`.
    /// pre-graph and pre-lock filters may be passed to be applied
    /// before specific actions internally.
    fn schedule<S: StateContainer<Tx>>(
        &mut self,
        container: &mut S,
        budget: u64,
    ) -> Result<SchedulingSummary, SchedulerError>;

    /// Receive completed batches of transactions without blocking.
    /// Returns (num_transactions, num_retryable_transactions) on success.
    fn receive_completed(
        &mut self,
        container: &mut impl StateContainer<Tx>,
    ) -> Result<(usize, usize), SchedulerError> {
        let mut total_num_transactions = Saturating::<usize>(0);
        let mut total_num_retryable = Saturating::<usize>(0);
        loop {
            let (num_transactions, num_retryable) = self
                .scheduling_common_mut()
                .try_receive_completed(container)?;
            if num_transactions == 0 {
                break;
            }
            total_num_transactions += num_transactions;
            total_num_retryable += num_retryable;
        }
        let Saturating(total_num_transactions) = total_num_transactions;
        let Saturating(total_num_retryable) = total_num_retryable;
        Ok((total_num_transactions, total_num_retryable))
    }

    /// All schedulers should have access to the common context for shared
    /// implementation.
    fn scheduling_common_mut(&mut self) -> &mut SchedulingCommon<Tx>;

    /// Immutable accessor for `SchedulingCommon`, used by the controller
    /// to read channel depths without requiring mutable borrow.
    fn scheduling_common(&self) -> &SchedulingCommon<Tx>;

    /// Summed length of every `scheduler → consume_worker` channel.
    fn consume_work_queue_sum(&self) -> usize {
        self.scheduling_common()
            .consume_work_senders
            .iter()
            .map(|s| s.len())
            .sum()
    }

    /// Max length across all `scheduler → consume_worker` channels.
    fn consume_work_queue_max(&self) -> usize {
        self.scheduling_common()
            .consume_work_senders
            .iter()
            .map(|s| s.len())
            .max()
            .unwrap_or(0)
    }

    /// Length of the `consume_worker → scheduler` return channel.
    fn finished_work_queue_depth(&self) -> usize {
        self.scheduling_common().finished_consume_work_receiver.len()
    }
}
/// Metrics from scheduling transactions.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct SchedulingSummary {
    /// Starting queue size
    pub starting_queue_size: usize,
    /// Starting buffer size (outstanding txs are not counted in queue)
    pub starting_buffer_size: usize,

    /// Number of transactions scheduled.
    pub num_scheduled: usize,
    /// Number of transactions that were not scheduled due to conflicts.
    pub num_unschedulable_conflicts: usize,
    /// Number of transactions that were skipped due to thread capacity.
    pub num_unschedulable_threads: usize,
}
