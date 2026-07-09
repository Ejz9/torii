#[cfg(feature = "ebpf")]
pub async fn init_ebpf(iface: &str) -> anyhow::Result<aya::Ebpf> {
    use anyhow::Context as _;
    use aya::programs::{Xdp, XdpMode};
    use log::{debug, warn};

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kekkai"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut Xdp = ebpf.program_mut("kekkai").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpMode::Skb)
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;
    log::info!("Kekkai eBPF successfully attached to {}", iface);
    Ok(ebpf)
}

#[cfg(not(feature = "ebpf"))]
pub async fn init_ebpf(_iface: &str) -> anyhow::Result<()> {
    log::info!("Kekkai eBPF disabled");
    Ok(())
}
