use aya::maps::{PerCpuArray, PerCpuHashMap};
use aya::programs::{KProbe, BtfTracePoint};
use aya::{include_bytes_aligned, Bpf, Btf, Pod};
use aya_log::BpfLogger;
use log::{info, warn, debug};
use tokio::signal;
use histogram::{Key, Histogram};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct DiskLatencyHistogramKey {
    pub major: i32,
    pub minor: i32
}

unsafe impl Pod for DiskLatencyHistogramKey {}



#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ioexporter"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ioexporter"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut KProbe = bpf.program_mut("mark_page_accessed").unwrap().try_into()?;
    program.load()?;
    program.attach("mark_page_accessed", 0)?;
    let program: &mut KProbe = bpf.program_mut("add_to_page_cache_lru").unwrap().try_into()?;
    program.load()?;
    program.attach("add_to_page_cache_lru", 0)?;
    let program: &mut KProbe = bpf.program_mut("mark_buffer_dirty").unwrap().try_into()?;
    program.load()?;
    program.attach("mark_buffer_dirty", 0)?;
    let program: &mut BtfTracePoint = bpf.program_mut("block_rq_insert").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
    program.load("block_rq_insert", &btf)?;
    program.attach()?;
    let program: &mut BtfTracePoint = bpf.program_mut("block_rq_complete").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
    program.load("block_rq_complete", &btf)?;
    program.attach()?;

    let metrics: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("METRICS").expect("failed to map IP_MAP"),
    )?;

    let map: PerCpuHashMap<_, Key<DiskLatencyHistogramKey>, u64> = PerCpuHashMap::try_from(
        bpf.take_map("BLOCK_HISTOGRAM").expect("failed to map BLOCK_HISTOGRAM"),
    )?;

    let histogram: Histogram<DiskLatencyHistogramKey> = Histogram::new_from_map(map);
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("mark_page_accessed: {:?}", metrics.get(&0, 0)?);
    println!("add_to_page_cache_lru: {:?}", metrics.get(&1, 0)?);
    println!("histo: {:?}", histogram.export_to_le_histogram());
    println!("mark_buffer_dirty: {:?}", metrics.get(&2, 0)?);
    info!("Exiting...");
    

    Ok(())
}
