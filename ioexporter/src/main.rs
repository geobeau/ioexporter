use aya::maps::{PerCpuArray, PerCpuHashMap};
use aya::programs::{BtfTracePoint, KProbe, TracePoint};
use aya::{include_bytes_aligned, Bpf, Btf, Pod};
use aya_log::BpfLogger;
// use libc::name_t;
use ebpf_histogram::{Histogram, Key, KeyWrapper};
use log::{debug, info, warn};
use phf::phf_map;
use prometheus::{Opts, Registry, TextEncoder};
use tokio::signal;

static OP_CODE: phf::Map<u8, &'static str> = phf_map! {
    0x00u8 => "nvme_cmd_flush",
    0x01u8 => "nvme_cmd_write",
    0x02u8 => "nvme_cmd_read",
    0x04u8 => "nvme_cmd_write_uncor",
    0x05u8 => "nvme_cmd_compare",
    0x08u8 => "nvme_cmd_write_zeroes",
    0x09u8 => "nvme_cmd_dsm",
    0x0du8 => "nvme_cmd_resv_register",
    0x0eu8 => "nvme_cmd_resv_report",
    0x11u8 => "nvme_cmd_resv_acquire",
    0x15u8 => "nvme_cmd_resv_release",
};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
// #[derive(Key)]
#[repr(C)]
pub struct DiskLatencyHistogramKey {
    pub major: i32,
    pub minor: i32,
}

unsafe impl Send for DiskLatencyHistogramKey {}
unsafe impl Sync for DiskLatencyHistogramKey {}
unsafe impl Pod for DiskLatencyHistogramKey {}
impl Key for DiskLatencyHistogramKey {
    fn get_label_keys() -> Vec<String> {
        vec!["major".to_string(), "minor".to_string()]
    }

    fn get_label_values(&self) -> Vec<String> {
        vec![self.major.to_string(), self.minor.to_string()]
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct NvneHistogramKey {
    // In practice, 31 first bytes are the disk and the last is opcode
    // This is done because of adding a mere u8 would require adding 32 bytes to keep alignement
    pub opaque: [u8; 32],
}

unsafe impl Send for NvneHistogramKey {}
unsafe impl Sync for NvneHistogramKey {}
unsafe impl Pod for NvneHistogramKey {}
impl Key for NvneHistogramKey {
    fn get_label_keys() -> Vec<String> {
        vec!["disk".to_string(), "operation".to_string()]
    }

    fn get_label_values(&self) -> Vec<String> {
        vec![
            String::from_utf8_lossy(&self.opaque[0..31]).to_string(),
            OP_CODE[&self.opaque[31]].to_string(),
        ]
    }
}

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
    let program: &mut KProbe = bpf
        .program_mut("add_to_page_cache_lru")
        .unwrap()
        .try_into()?;
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
    // sudo ls /sys/kernel/debug/tracing/events/ to find category
    let program: &mut TracePoint = bpf.program_mut("nvme_setup_cmd").unwrap().try_into()?;
    program.load()?;
    program.attach("nvme", "nvme_setup_cmd")?;
    let program: &mut TracePoint = bpf.program_mut("nvme_complete_rq").unwrap().try_into()?;
    program.load()?;
    program.attach("nvme", "nvme_complete_rq")?;

    let page_cache_metrics: PerCpuArray<_, u64> = PerCpuArray::try_from(
        bpf.take_map("PAGE_CACHE_METRICS")
            .expect("failed to map IP_MAP"),
    )?;

    let io_latency_map: PerCpuHashMap<_, KeyWrapper<DiskLatencyHistogramKey>, u64> =
        PerCpuHashMap::try_from(
            bpf.take_map("BLOCK_HISTOGRAM")
                .expect("failed to map BLOCK_HISTOGRAM"),
        )?;
    let nvme_latency_map: PerCpuHashMap<_, KeyWrapper<NvneHistogramKey>, u64> =
        PerCpuHashMap::try_from(
            bpf.take_map("NVME_HISTOGRAM")
                .expect("failed to map NVME_HISTOGRAM"),
        )?;

    let io_latency_histogram: Histogram<DiskLatencyHistogramKey> = Histogram::new_from_map(
        io_latency_map,
        Opts::new("io_disk_latency", "Histogram of IO latency"),
    );
    let nvme_latency_histogram: Histogram<NvneHistogramKey> = Histogram::new_from_map(
        nvme_latency_map,
        Opts::new("nvme_latency", "Histogram of IO latency"),
    );

    let r = Registry::new();
    r.register(Box::new(io_latency_histogram)).unwrap();
    r.register(Box::new(nvme_latency_histogram)).unwrap();
    println!("Starting exporter");
    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("mark_page_accessed: {:?}", page_cache_metrics.get(&0, 0)?);
    println!(
        "add_to_page_cache_lru: {:?}",
        page_cache_metrics.get(&1, 0)?
    );
    // println!("histo: {:?}", histogram.export_to_le_histogram());
    println!("mark_buffer_dirty: {:?}", page_cache_metrics.get(&2, 0)?);
    info!("Exiting...");

    let mut buffer = String::new();
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode_utf8(&metric_families, &mut buffer).unwrap();
    println!("{}", buffer);

    Ok(())
}
