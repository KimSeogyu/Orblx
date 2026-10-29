//! The `tun-bench` command.
//!
//! The command measures one local TUN round trip.
//! The command exits 0 when the host cannot open a TUN device.

use std::process;

use orblx_datapath::{run_local_tun_bench, TunBenchOutcome};

fn main() {
    match run_local_tun_bench() {
        Ok(TunBenchOutcome::Skipped(reason)) => {
            println!("K3 tun_ready false");
            println!("{reason}");
        }
        Ok(TunBenchOutcome::Measured(report)) => {
            print!("{}", report.report_lines());
            if !report.pass() {
                process::exit(1);
            }
        }
        Err(err) => {
            eprintln!("tun_bench_error={err}");
            process::exit(1);
        }
    }
}
