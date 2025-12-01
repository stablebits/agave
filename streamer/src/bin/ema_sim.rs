//! CLI simulator for the legacy `StakedStreamLoadEMA`.
//!
//! Usage:
//!   cargo run -p streamer --bin ema_sim -- <seq> [--stakes 100,10,1] [--total-stake 10000]
//!
//! The sequence is a whitespace/comma-separated list of stream counts per 5ms interval.

use solana_streamer::{
    nonblocking::{quic::ConnectionPeerType, stream_throttle::StakedStreamLoadEMA},
    quic::StreamerStats,
};
use std::sync::Arc;
use std::{
    env,
    io::{self, Read},
    str::FromStr,
};

fn parse_sequence(args: &[String]) -> Vec<u64> {
    let joined = if args.is_empty() {
        let mut buf = String::new();
        let _ = io::stdin().read_to_string(&mut buf);
        buf
    } else {
        args.join(" ")
    };

    joined
        .replace(',', " ")
        .split_whitespace()
        .filter_map(|s| u64::from_str(s).ok())
        .collect()
}

fn parse_stakes(arg: &str) -> Vec<u64> {
    arg.replace(',', " ")
        .split_whitespace()
        .filter_map(|s| u64::from_str(s).ok())
        .collect()
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let mut stakes_arg = "100,10,1".to_string();
    // Default total stake = 100 so stake fractions map naturally (1% => 1 unit).
    let mut total_stake = 10000_u64;
    let mut max_streams_per_ms = 500_u64;
    let mut max_unstaked_connections = 500_usize;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--stakes" => {
                if i + 1 < args.len() {
                    stakes_arg = args.remove(i + 1);
                    args.remove(i);
                    continue;
                }
            }
            "--total-stake" => {
                if i + 1 < args.len() {
                    if let Ok(v) = args[i + 1].parse::<u64>() {
                        total_stake = v;
                    }
                    args.drain(i..=i + 1);
                    continue;
                }
            }
            "--max-streams-per-ms" => {
                if i + 1 < args.len() {
                    if let Ok(v) = args[i + 1].parse::<u64>() {
                        max_streams_per_ms = v;
                    }
                    args.drain(i..=i + 1);
                    continue;
                }
            }
            "--max-unstaked-connections" => {
                if i + 1 < args.len() {
                    if let Ok(v) = args[i + 1].parse::<usize>() {
                        max_unstaked_connections = v;
                    }
                    args.drain(i..=i + 1);
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    let sequence = parse_sequence(&args);
    if sequence.is_empty() {
        eprintln!("No sequence provided.");
        std::process::exit(1);
    }
    let stakes = parse_stakes(&stakes_arg);

    let stats = Arc::new(StreamerStats::default());
    let ema = Arc::new(StakedStreamLoadEMA::new(
        stats.clone(),
        max_unstaked_connections,
        max_streams_per_ms,
    ));

    println!(
        "# max_streams_per_ms={} max_unstaked_connections={} max_staked_load_in_ema_window={} max_unstaked_load_in_throttling_window={}",
        max_streams_per_ms,
        max_unstaked_connections,
        ema.max_staked_load_in_ema_window(),
        ema.max_unstaked_load_in_throttling_window()
    );

    let mut header = vec![
        "step".to_string(),
        "load_in_5ms".to_string(),
        "ema".to_string(),
    ];
    for stake in &stakes {
        let pcnt = 100.0 * (*stake as f64) / (total_stake as f64);
        header.push(format!("quota_{:}%", pcnt));
    }

    let widths: Vec<usize> = std::iter::repeat(12).take(header.len()).collect();
    let print_row = |cols: &[String], csv: bool| {
        if csv {
            println!("{}", cols.join(","));
        } else {
            let padded: Vec<String> = cols
                .iter()
                .zip(widths.iter())
                .map(|(v, w)| format!("{:>width$}", v, width = *w))
                .collect();
            println!("{}", padded.join(" "));
        }
    };

    let csv = args.contains(&"--csv".to_string());
    print_row(&header, csv);

    for (idx, load) in sequence.iter().enumerate() {
        ema.increment_load_by_count(ConnectionPeerType::Staked(1), *load);
        // Advance EMA deterministically by one 5ms tick (same interval as EMA update).
        const STREAM_LOAD_EMA_INTERVAL_MS: u64 = 5;
        ema.update_ema(STREAM_LOAD_EMA_INTERVAL_MS as u128);

        let ema_val = ema.current_load_ema();

        let mut cols: Vec<String> = vec![idx.to_string(), load.to_string(), ema_val.to_string()];
        for stake in &stakes {
            // let stake_units = (*stake * total_stake) as u64;
            let quota = ema.available_load_capacity_in_throttling_duration(
                ConnectionPeerType::Staked(*stake),
                total_stake as u64,
            );
            cols.push(quota.to_string());
        }
        print_row(&cols, csv);
    }
}
