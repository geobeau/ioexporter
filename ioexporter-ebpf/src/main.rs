#![no_std]
#![no_main]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]


mod vmlinux;

use aya_bpf::{macros::{kprobe, map, btf_tracepoint}, programs::{ProbeContext, BtfTracePointContext}, maps::{PerCpuArray}, helpers::bpf_ktime_get_ns};
use aya_log_ebpf::info;
use histogram_ebpf::BpfHistogram;


#[derive(Copy, Clone)]
#[repr(C)]
pub struct DiskLatencyHistogramKey {
    pub major: i32,
    pub minor: i32
}

#[map]
static METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);
#[map]
static BLOCK_HISTOGRAM: BpfHistogram<DiskLatencyHistogramKey> = BpfHistogram::with_max_entries(1000, 0);

static MARK_PAGE_ACCESSED_COUNTER_IDX: u32 = 0;
static ADD_TO_PAGE_LRU_COUNTER_IDX: u32 = 1;
static MARK_BUFFER_DIRTY_COUNTER_IDX: u32 = 2;
// https://elixir.bootlin.com/linux/latest/source/include/linux/blk_types.h#L354
static REQ_OP_BITS: u32 = 8;
static REQ_OP_MASK: u32 = (1 << REQ_OP_BITS) - 1;


#[kprobe]
pub fn mark_page_accessed(_: ProbeContext) -> u32 {
    unsafe {
        if let Some(metric) = METRICS.get_ptr_mut(MARK_PAGE_ACCESSED_COUNTER_IDX){
            *metric += 1;
        }
    }

    return 0
}

#[kprobe]
pub fn add_to_page_cache_lru(_: ProbeContext) -> u32 {
    unsafe {
        if let Some(metric) = METRICS.get_ptr_mut(ADD_TO_PAGE_LRU_COUNTER_IDX){
            *metric += 1;
        }
    }

    return 0
}

#[kprobe]
pub fn mark_buffer_dirty(_: ProbeContext) -> u32 {
    unsafe {
        if let Some(metric) = METRICS.get_ptr_mut(MARK_BUFFER_DIRTY_COUNTER_IDX){
            *metric += 1;
        }
    }

    return 0
}


// #[btf_tracepoint(function="block_rq_insert")]
// pub fn block_rq_insert(ctx: BtfTracePointContext) -> u32 {
//     let req: *const vmlinux::request = unsafe { ctx.arg(0) };
//     info!(&ctx, "rq insert {p}", req as usize);

//     return 0
// }

#[btf_tracepoint(function="block_rq_insert")]
pub fn block_rq_insert(ctx: BtfTracePointContext) -> u32 {
    let req: *const vmlinux::request = unsafe { ctx.arg(0) };
    // info!(&ctx, "rq insert {}", req as usize);

    unsafe {
        let disk: vmlinux::gendisk = *((*(*req).q).disk);
        info!(&ctx, "insert disk {}.{}", disk.major, disk.minors);
        
        // RQ_TRACKER.insert(&ptr, &0, 0).unwrap();
    }
    return 0
}

#[btf_tracepoint(function="block_rq_complete")]
pub fn block_rq_complete(ctx: BtfTracePointContext) -> u32 {
    let req: *const vmlinux::request = unsafe { ctx.arg(0) };

    unsafe {
        let timestamp = bpf_ktime_get_ns();
        let disk: vmlinux::gendisk = *((*(*req).q).disk);
        let latency = timestamp - (*req).io_start_time_ns;
        let flags = (*req).cmd_flags & REQ_OP_MASK;
        BLOCK_HISTOGRAM.observe(DiskLatencyHistogramKey{ major: disk.major, minor: disk.minors }, latency);
        info!(&ctx, "complete disk {}.{} -> Latency: {}us, (flags: {})", disk.major,disk.minors, latency / 1000, flags);
    }
    return 0
}




#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
