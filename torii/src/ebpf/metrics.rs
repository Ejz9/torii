use aya::maps::{MapData, PerCpuArray, PerCpuValues};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub async fn run(
    mut metrics: PerCpuArray<MapData, u64>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    let Ok(nr_cpus) = aya::util::nr_cpus() else {
        error!("FATAL: Failed to get number of CPUs");
        std::process::exit(1);
    };
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
    loop {
        select! {
            _ = cancel_token.cancelled() => {
                info!("eBPF Metrics recieved shutdown signal. Halting.");
                break;
            }
            _ = interval.tick() => {}
        }
        let Ok(passed_raw) = metrics.get(&0, 0) else {
            error!("Failed to get pass metrics");
            continue;
        };
        let Ok(dropped_raw) = metrics.get(&1, 0) else {
            error!("Failed to get drop metrics");
            continue;
        };
        let passed_total: u64 = passed_raw.iter().copied().sum();
        let dropped_total: u64 = dropped_raw.iter().copied().sum();
        if passed_total > 0 || dropped_total > 0 {
            info!("Traffic last minute: {passed_total} passed, {dropped_total} dropped");
        }
        let Ok(zero_passes) = PerCpuValues::try_from(vec![0u64; nr_cpus]) else {
            error!("Failed to zero pass metrics");
            continue;
        };
        if let Err(e) = metrics.set(0, zero_passes, 0) {
            error!("Failed to reset pass metrics: {e}")
        }
        let Ok(zero_drops) = PerCpuValues::try_from(vec![0u64; nr_cpus]) else {
            error!("Failed to zero drop metrics");
            continue;
        };
        if let Err(e) = metrics.set(1, zero_drops, 0) {
            error!("Failed to reset drop metrics: {e}")
        }
    }
    Ok(())
}
