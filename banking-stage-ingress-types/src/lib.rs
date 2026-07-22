#![cfg(feature = "agave-unstable-api")]
use {
    crossbeam_channel::{
        Receiver, RecvError, RecvTimeoutError, SendError, Sender, TryRecvError, TrySendError,
        bounded,
    },
    min_max_heap::MinMaxHeap,
    solana_perf::packet::PacketBatch,
    std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        time::Duration,
    },
};
#[cfg(feature = "dev-context-only-utils")]
use {
    solana_perf::packet::{BytesPacket, BytesPacketBatch, Meta, PACKET_DATA_SIZE, bytes::Bytes},
    wincode::{SchemaWrite, config::DefaultConfig},
};

pub type BankingPacketBatch = Arc<PacketBatch>;
pub type BankingPacketReceiver = Receiver<BankingPacketBatch>;

/// Result of inserting into a bounded priority channel.
#[derive(Debug, PartialEq, Eq)]
pub enum PrioritySendOutcome<T> {
    Inserted,
    Replaced(T),
    Rejected(T),
}

struct PriorityEntry<T> {
    priority: u64,
    sequence: u64,
    value: T,
}

impl<T> PartialEq for PriorityEntry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}

impl<T> Eq for PriorityEntry<T> {}

impl<T> PartialOrd for PriorityEntry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for PriorityEntry<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            // Older messages sort ahead of newer messages at equal priority.
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

struct PriorityQueue<T> {
    heap: MinMaxHeap<PriorityEntry<T>>,
    capacity: usize,
    next_sequence: u64,
    sender_count: usize,
    receiver_count: usize,
    notification_armed: bool,
}

struct PriorityChannelShared<T> {
    queue: Mutex<PriorityQueue<T>>,
    len: AtomicUsize,
    admission_floor: AtomicU64,
}

/// Cloneable producer for a bounded, replace-min priority channel.
pub struct PrioritySender<T> {
    shared: Arc<PriorityChannelShared<T>>,
    ready_sender: Sender<()>,
}

impl<T> Clone for PrioritySender<T> {
    fn clone(&self) -> Self {
        let mut queue = self.shared.queue.lock().unwrap();
        queue.sender_count = queue.sender_count.saturating_add(1);
        drop(queue);
        Self {
            shared: self.shared.clone(),
            ready_sender: self.ready_sender.clone(),
        }
    }
}

impl<T> Drop for PrioritySender<T> {
    fn drop(&mut self) {
        let mut queue = self.shared.queue.lock().unwrap();
        queue.sender_count = queue.sender_count.saturating_sub(1);
        if queue.sender_count == 0 && queue.receiver_count > 0 {
            // Wake a blocked receiver so it can observe disconnection after
            // draining any remaining values.
            arm_notification(&mut queue, &self.ready_sender);
        }
    }
}

impl<T> PrioritySender<T> {
    /// Compatibility helper for trusted producers that do not supply a
    /// priority. Such messages sort ahead of externally sourced traffic.
    pub fn send(&self, value: T) -> Result<(), SendError<T>> {
        match self.try_send(u64::MAX, value)? {
            PrioritySendOutcome::Inserted => {}
            PrioritySendOutcome::Replaced(_) | PrioritySendOutcome::Rejected(_) => {}
        }
        Ok(())
    }

    /// Inserts `value`, replacing the current minimum when full if and only if
    /// `priority` is strictly greater than the minimum priority.
    pub fn try_send(
        &self,
        priority: u64,
        value: T,
    ) -> Result<PrioritySendOutcome<T>, SendError<T>> {
        let mut queue = self.shared.queue.lock().unwrap();
        if queue.receiver_count == 0 {
            return Err(SendError(value));
        }

        let sequence = queue.next_sequence;
        queue.next_sequence = queue.next_sequence.wrapping_add(1);
        let entry = PriorityEntry {
            priority,
            sequence,
            value,
        };

        let (outcome, grew) = if queue.heap.len() < queue.capacity {
            queue.heap.push(entry);
            (PrioritySendOutcome::Inserted, true)
        } else if priority > queue.heap.peek_min().unwrap().priority {
            let evicted = queue.heap.push_pop_min(entry);
            (PrioritySendOutcome::Replaced(evicted.value), false)
        } else {
            (PrioritySendOutcome::Rejected(entry.value), false)
        };

        if grew {
            self.shared.len.fetch_add(1, Ordering::Relaxed);
        }
        // The heap is authoritative. The capacity-one side channel is only an
        // edge-triggered notification that the heap is non-empty.
        if !queue.heap.is_empty() {
            arm_notification(&mut queue, &self.ready_sender);
        }
        publish_admission_floor(&self.shared, &queue);
        Ok(outcome)
    }

    pub fn len(&self) -> usize {
        self.shared.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the minimum priority when the channel is full, otherwise zero.
    pub fn admission_floor(&self) -> u64 {
        self.shared.admission_floor.load(Ordering::Relaxed)
    }
}

/// Cloneable consumer handle for a bounded priority channel.
pub struct PriorityReceiver<T> {
    shared: Arc<PriorityChannelShared<T>>,
    ready_sender: Sender<()>,
    ready_receiver: Receiver<()>,
}

impl<T> Clone for PriorityReceiver<T> {
    fn clone(&self) -> Self {
        let mut queue = self.shared.queue.lock().unwrap();
        queue.receiver_count = queue.receiver_count.saturating_add(1);
        drop(queue);
        Self {
            shared: self.shared.clone(),
            ready_sender: self.ready_sender.clone(),
            ready_receiver: self.ready_receiver.clone(),
        }
    }
}

impl<T> Drop for PriorityReceiver<T> {
    fn drop(&mut self) {
        let mut queue = self.shared.queue.lock().unwrap();
        queue.receiver_count = queue.receiver_count.saturating_sub(1);
    }
}

impl<T> PriorityReceiver<T> {
    pub fn try_recv(&self) -> Result<(u64, T), TryRecvError> {
        self.ready_receiver.try_recv()?;
        self.pop_ready()
            .map_err(|RecvError| TryRecvError::Disconnected)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<(u64, T), RecvTimeoutError> {
        self.ready_receiver.recv_timeout(timeout)?;
        self.pop_ready()
            .map_err(|RecvError| RecvTimeoutError::Disconnected)
    }

    pub fn recv(&self) -> Result<(u64, T), RecvError> {
        self.ready_receiver.recv()?;
        self.pop_ready()
    }

    pub fn recv_batch(&self, max_items: usize) -> Result<Vec<(u64, T)>, RecvError> {
        self.ready_receiver.recv()?;
        self.pop_ready_batch(max_items)
    }

    /// Readiness receiver used to combine this channel with crossbeam
    /// `select!`. After receiving a token, call [`Self::pop_ready`].
    pub fn ready_receiver(&self) -> &Receiver<()> {
        &self.ready_receiver
    }

    pub fn pop_ready(&self) -> Result<(u64, T), RecvError> {
        let mut batch = self.pop_ready_batch(1)?;
        Ok(batch.pop().unwrap())
    }

    /// Pops up to `max_items` after receiving one readiness notification.
    /// Remaining values are covered by a newly armed notification.
    pub fn pop_ready_batch(&self, max_items: usize) -> Result<Vec<(u64, T)>, RecvError> {
        assert!(max_items > 0, "priority receive batch must be non-zero");
        let mut queue = self.shared.queue.lock().unwrap();
        assert!(
            queue.notification_armed,
            "readiness token must correspond to an armed notification"
        );
        queue.notification_armed = false;

        if queue.heap.is_empty() {
            debug_assert_eq!(queue.sender_count, 0);
            arm_notification(&mut queue, &self.ready_sender);
            return Err(RecvError);
        }

        let count = max_items.min(queue.heap.len());
        let mut batch = Vec::with_capacity(count);
        for _ in 0..count {
            let entry = queue.heap.pop_max().unwrap();
            batch.push((entry.priority, entry.value));
        }
        self.shared.len.fetch_sub(count, Ordering::Relaxed);
        publish_admission_floor(&self.shared, &queue);
        if !queue.heap.is_empty() || queue.sender_count == 0 {
            arm_notification(&mut queue, &self.ready_sender);
        }
        Ok(batch)
    }

    pub fn try_recv_batch(&self, max_items: usize) -> Result<Vec<(u64, T)>, TryRecvError> {
        self.ready_receiver.try_recv()?;
        self.pop_ready_batch(max_items)
            .map_err(|RecvError| TryRecvError::Disconnected)
    }

    pub fn recv_batch_timeout(
        &self,
        timeout: Duration,
        max_items: usize,
    ) -> Result<Vec<(u64, T)>, RecvTimeoutError> {
        self.ready_receiver.recv_timeout(timeout)?;
        self.pop_ready_batch(max_items)
            .map_err(|RecvError| RecvTimeoutError::Disconnected)
    }

    pub fn len(&self) -> usize {
        self.shared.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn publish_admission_floor<T>(shared: &PriorityChannelShared<T>, queue: &PriorityQueue<T>) {
    let floor = if queue.heap.len() == queue.capacity {
        queue.heap.peek_min().map_or(0, |entry| entry.priority)
    } else {
        0
    };
    shared.admission_floor.store(floor, Ordering::Relaxed);
}

fn arm_notification<T>(queue: &mut PriorityQueue<T>, ready_sender: &Sender<()>) {
    if queue.notification_armed {
        return;
    }
    match ready_sender.try_send(()) {
        Ok(()) => queue.notification_armed = true,
        Err(TrySendError::Full(())) => panic!("priority channel notification invariant"),
        Err(TrySendError::Disconnected(())) => {}
    }
}

pub fn priority_channel<T>(capacity: usize) -> (PrioritySender<T>, PriorityReceiver<T>) {
    assert!(capacity > 0, "priority channel capacity must be non-zero");
    let (ready_sender, ready_receiver) = bounded(1);
    let shared = Arc::new(PriorityChannelShared {
        queue: Mutex::new(PriorityQueue {
            heap: MinMaxHeap::with_capacity(capacity),
            capacity,
            next_sequence: 0,
            sender_count: 1,
            receiver_count: 1,
            notification_armed: false,
        }),
        len: AtomicUsize::new(0),
        admission_floor: AtomicU64::new(0),
    });
    (
        PrioritySender {
            shared: shared.clone(),
            ready_sender: ready_sender.clone(),
        },
        PriorityReceiver {
            shared,
            ready_sender,
            ready_receiver,
        },
    )
}

pub type PriorityBankingPacketSender = PrioritySender<BankingPacketBatch>;
pub type PriorityBankingPacketReceiver = PriorityReceiver<BankingPacketBatch>;

#[cfg(feature = "dev-context-only-utils")]
fn to_bytes_packet<T>(item: &T) -> BytesPacket
where
    T: SchemaWrite<DefaultConfig, Src = T> + ?Sized,
{
    let buffer = Bytes::from(wincode::serialize(item).expect("serialize request"));
    assert!(buffer.len() <= PACKET_DATA_SIZE);
    let mut meta = Meta::default();
    meta.size = buffer.len();
    BytesPacket::new(buffer, meta)
}

#[cfg(feature = "dev-context-only-utils")]
fn to_single_packet_batch<T>(item: &T) -> PacketBatch
where
    T: SchemaWrite<DefaultConfig, Src = T> + ?Sized,
{
    PacketBatch::Single(to_bytes_packet(item))
}

#[cfg(feature = "dev-context-only-utils")]
fn to_packet_batch<T>(items: &[T]) -> PacketBatch
where
    T: SchemaWrite<DefaultConfig, Src = T>,
{
    if let [item] = items {
        return to_single_packet_batch(item);
    }

    items
        .iter()
        .map(to_bytes_packet)
        .collect::<BytesPacketBatch>()
        .into()
}

#[cfg(feature = "dev-context-only-utils")]
pub fn to_banking_packet_batch<T>(items: &[T]) -> BankingPacketBatch
where
    T: SchemaWrite<DefaultConfig, Src = T>,
{
    Arc::new(to_packet_batch(items))
}

#[cfg(feature = "dev-context-only-utils")]
pub fn to_single_banking_packet_batch<T>(item: &T) -> BankingPacketBatch
where
    T: SchemaWrite<DefaultConfig, Src = T> + ?Sized,
{
    Arc::new(to_single_packet_batch(item))
}

/// Priority floor shared from the banking-stage scheduler to sigverify.
///
/// When saturated, the scheduler publishes the queue-min transaction's
/// priority. Sigverify drops at-or-below-floor arrivals.
/// In practice, transactions always have non-zero priorities.
#[derive(Debug)]
pub struct SchedulerPriorityFloor(AtomicU64);

impl SchedulerPriorityFloor {
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn set(&self, floor: u64) {
        self.0.store(floor, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.set(0);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for SchedulerPriorityFloor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        std::{
            sync::{Arc, Barrier},
            thread,
        },
    };

    #[test]
    fn priority_channel_receives_highest_first_and_fifo_on_ties() {
        let (sender, receiver) = priority_channel(8);
        assert_eq!(
            sender.try_send(10, "old-10"),
            Ok(PrioritySendOutcome::Inserted)
        );
        assert_eq!(
            sender.try_send(20, "twenty"),
            Ok(PrioritySendOutcome::Inserted)
        );
        assert_eq!(
            sender.try_send(10, "new-10"),
            Ok(PrioritySendOutcome::Inserted)
        );

        assert_eq!(receiver.try_recv().unwrap(), (20, "twenty"));
        assert_eq!(receiver.try_recv().unwrap(), (10, "old-10"));
        assert_eq!(receiver.try_recv().unwrap(), (10, "new-10"));
    }

    #[test]
    fn priority_channel_retains_best_values_at_capacity() {
        let (sender, receiver) = priority_channel(3);
        assert_eq!(sender.try_send(10, 10), Ok(PrioritySendOutcome::Inserted));
        assert_eq!(sender.try_send(30, 30), Ok(PrioritySendOutcome::Inserted));
        assert_eq!(sender.try_send(20, 20), Ok(PrioritySendOutcome::Inserted));
        assert_eq!(sender.admission_floor(), 10);

        assert_eq!(sender.try_send(5, 5), Ok(PrioritySendOutcome::Rejected(5)));
        assert_eq!(
            sender.try_send(25, 25),
            Ok(PrioritySendOutcome::Replaced(10))
        );
        assert_eq!(sender.admission_floor(), 20);

        assert_eq!(receiver.try_recv().unwrap(), (30, 30));
        assert_eq!(sender.admission_floor(), 0);
        assert_eq!(receiver.try_recv().unwrap(), (25, 25));
        assert_eq!(receiver.try_recv().unwrap(), (20, 20));
    }

    #[test]
    fn priority_channel_uses_one_notification_and_drains_in_batches() {
        let (sender, receiver) = priority_channel(8);
        sender.try_send(10, 10).unwrap();
        sender.try_send(30, 30).unwrap();
        sender.try_send(20, 20).unwrap();
        assert_eq!(receiver.ready_receiver().len(), 1);

        assert_eq!(
            receiver.try_recv_batch(2).unwrap(),
            vec![(30, 30), (20, 20)]
        );
        assert_eq!(receiver.ready_receiver().len(), 1);
        assert_eq!(receiver.try_recv_batch(2).unwrap(), vec![(10, 10)]);
        assert!(receiver.ready_receiver().is_empty());
    }

    #[test]
    fn priority_channel_disconnects_after_senders_are_drained() {
        let (sender, receiver) = priority_channel(1);
        sender.try_send(1, 1).unwrap();
        drop(sender);
        assert_eq!(receiver.recv().unwrap(), (1, 1));
        assert_eq!(receiver.recv(), Err(RecvError));
    }

    #[test]
    fn priority_channel_rejects_after_last_receiver_drops() {
        let (sender, receiver) = priority_channel(1);
        drop(receiver);
        assert_eq!(sender.try_send(1, 1), Err(SendError(1)));
    }

    #[test]
    fn priority_channel_supports_multiple_producers() {
        const PRODUCERS: usize = 4;
        const ITEMS_PER_PRODUCER: usize = 1_000;
        let capacity = PRODUCERS * ITEMS_PER_PRODUCER;
        let (sender, receiver) = priority_channel(capacity);
        let barrier = Arc::new(Barrier::new(PRODUCERS));
        let threads: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let sender = sender.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    for item in 0..ITEMS_PER_PRODUCER {
                        let value = producer * ITEMS_PER_PRODUCER + item;
                        assert_eq!(
                            sender.try_send(value as u64, value),
                            Ok(PrioritySendOutcome::Inserted)
                        );
                    }
                })
            })
            .collect();
        threads
            .into_iter()
            .for_each(|thread| thread.join().unwrap());

        for expected in (0..capacity).rev() {
            assert_eq!(receiver.try_recv().unwrap(), (expected as u64, expected));
        }
    }
}
