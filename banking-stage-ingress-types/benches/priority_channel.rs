use {
    agave_banking_stage_ingress_types::{PrioritySendOutcome, priority_channel},
    criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main},
    crossbeam_channel::bounded,
    std::{
        hint::black_box,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, Instant},
    },
};

const TOTAL_ITEMS: usize = 400_000;
const RECEIVE_BATCH_SIZE: usize = 64;

fn items_per_producer(producers: usize) -> usize {
    assert_eq!(TOTAL_ITEMS % producers, 0);
    TOTAL_ITEMS / producers
}

fn priority_mpsc(producers: usize, receive_batch_size: usize) -> Duration {
    let items_per_producer = items_per_producer(producers);
    let (sender, receiver) = priority_channel(TOTAL_ITEMS);
    // Rendezvous once to ensure every worker is ready, then again to release
    // them only after the timer has started.
    let barrier = Arc::new(Barrier::new(producers + 2));
    let consumer_barrier = barrier.clone();
    let consumer = thread::spawn(move || {
        consumer_barrier.wait();
        consumer_barrier.wait();
        if receive_batch_size == 1 {
            for _ in 0..TOTAL_ITEMS {
                black_box(receiver.recv().unwrap());
            }
        } else {
            let mut received = 0;
            while received < TOTAL_ITEMS {
                let batch = receiver.recv_batch(receive_batch_size).unwrap();
                received += batch.len();
                black_box(batch);
            }
        }
    });
    let producer_threads: Vec<_> = (0..producers)
        .map(|producer| {
            let sender = sender.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                barrier.wait();
                for item in 0..items_per_producer {
                    let value = producer * items_per_producer + item;
                    black_box(sender.try_send(value as u64, value).unwrap());
                }
            })
        })
        .collect();

    barrier.wait();
    let start = Instant::now();
    barrier.wait();
    producer_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    consumer.join().unwrap();
    start.elapsed()
}

fn crossbeam_mpsc(producers: usize) -> Duration {
    let items_per_producer = items_per_producer(producers);
    let (sender, receiver) = bounded(TOTAL_ITEMS);
    let barrier = Arc::new(Barrier::new(producers + 2));
    let consumer_barrier = barrier.clone();
    let consumer = thread::spawn(move || {
        consumer_barrier.wait();
        consumer_barrier.wait();
        for _ in 0..TOTAL_ITEMS {
            black_box(receiver.recv().unwrap());
        }
    });
    let producer_threads: Vec<_> = (0..producers)
        .map(|producer| {
            let sender = sender.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                barrier.wait();
                for item in 0..items_per_producer {
                    black_box(sender.send(producer * items_per_producer + item).unwrap());
                }
            })
        })
        .collect();

    barrier.wait();
    let start = Instant::now();
    barrier.wait();
    producer_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    consumer.join().unwrap();
    start.elapsed()
}

fn saturated_priority_mpsc(producers: usize) -> Duration {
    const CAPACITY: usize = 16_384;
    let items_per_producer = items_per_producer(producers);
    let (sender, _receiver) = priority_channel(CAPACITY);
    for priority in 0..CAPACITY {
        assert_eq!(
            sender.try_send(priority as u64 + 1, priority).unwrap(),
            PrioritySendOutcome::Inserted
        );
    }

    let barrier = Arc::new(Barrier::new(producers + 1));
    let producer_threads: Vec<_> = (0..producers)
        .map(|producer| {
            let sender = sender.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                barrier.wait();
                for item in 0..items_per_producer {
                    let priority =
                        CAPACITY as u64 + (producer * items_per_producer + item) as u64 + 1;
                    black_box(sender.try_send(priority, priority as usize).unwrap());
                }
            })
        })
        .collect();

    barrier.wait();
    let start = Instant::now();
    barrier.wait();
    producer_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    start.elapsed()
}

fn bench_priority_channel(c: &mut Criterion) {
    let mut group = c.benchmark_group("banking_priority_channel");
    group.sample_size(10);
    for producers in [1, 4, 8] {
        group.throughput(Throughput::Elements(TOTAL_ITEMS as u64));
        group.bench_with_input(
            BenchmarkId::new("priority_mpsc", producers),
            &producers,
            |b, &producers| {
                b.iter_custom(|iterations| {
                    (0..iterations)
                        .map(|_| priority_mpsc(producers, RECEIVE_BATCH_SIZE))
                        .sum()
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("priority_mpsc_single", producers),
            &producers,
            |b, &producers| {
                b.iter_custom(|iterations| {
                    (0..iterations).map(|_| priority_mpsc(producers, 1)).sum()
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("crossbeam_mpsc", producers),
            &producers,
            |b, &producers| {
                b.iter_custom(|iterations| (0..iterations).map(|_| crossbeam_mpsc(producers)).sum())
            },
        );
        group.bench_with_input(
            BenchmarkId::new("priority_full_replace", producers),
            &producers,
            |b, &producers| {
                b.iter_custom(|iterations| {
                    (0..iterations)
                        .map(|_| saturated_priority_mpsc(producers))
                        .sum()
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_priority_channel);
criterion_main!(benches);
