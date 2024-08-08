#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
use aya_ebpf::{
    cty::c_long,
    helpers,
    macros::{map, tracepoint},
    programs::TracePointContext,
    maps::LruHashMap,
};

#[repr(C)]
pub struct NvmeTrackerEntry {
    pub from: u64,
    pub opcode: u8,
    pub pad1: u8,
    pub pad2: u16,
    pub pad3: u32
}

#[repr(C)]
pub struct NvneHistogramKey {
     // In practice, 31 first bytes are the disk and the last is opcode
    // This is done because of adding a mere u8 would require adding 32 bytes to keep alignement 
    pub opaque: [u8; 32],
}

use aya_log_ebpf::info;
use ebpf_histogram_ebpf::BpfHistogram;

#[map]
static STATE_TRACKER: LruHashMap<u16, NvmeTrackerEntry> = LruHashMap::with_max_entries(1000, 0);


#[map]
static NVME_HISTOGRAM: BpfHistogram<NvneHistogramKey> = BpfHistogram::with_max_entries(1000, 0);



#[tracepoint(name = "nvme_setup_cmd", category = "nvme")]
pub fn nvme_setup_cmd(ctx: TracePointContext) -> c_long {
    match try_nvme_setup_cmd(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}


// name: nvme_setup_cmd
// ID: 1399
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;

//         field:char disk[32];    offset:8;       size:32;        signed:1;
//         field:int ctrl_id;      offset:40;      size:4; signed:1;
//         field:int qid;  offset:44;      size:4; signed:1;
//         field:u8 opcode;        offset:48;      size:1; signed:0;
//         field:u8 flags; offset:49;      size:1; signed:0;
//         field:u8 fctype;        offset:50;      size:1; signed:0;
//         field:u16 cid;  offset:52;      size:2; signed:0;
//         field:u32 nsid; offset:56;      size:4; signed:0;
//         field:bool metadata;    offset:60;      size:1; signed:0;
//         field:u8 cdw10[24];     offset:61;      size:24;        signed:0;

pub fn try_nvme_setup_cmd(ctx: TracePointContext) -> Result<c_long, c_long> {
    // sudo cat /sys/kernel/debug/tracing/events/nvme/nvme_setup_cmd/format
    const CID_OFFSET: usize = 52;
    const OPCODE_OFFSET: usize = 48;
    let opcode: u8 = unsafe { ctx.read_at(OPCODE_OFFSET)? };
    let cid: u16 = unsafe { ctx.read_at(CID_OFFSET)? };

    info!(&ctx, "nvme start cid {}", cid);
    unsafe {
        let from = helpers::bpf_ktime_get_ns();
        // TODO find a better way to pad
        let entry = NvmeTrackerEntry{ from, opcode, pad1: 0, pad2: 0, pad3: 0};
        STATE_TRACKER.insert(&cid, &entry, 0)?;

        info!(&ctx, "nvme disk {}:{}:{}", entry.from, cid, entry.opcode);
    }
    return Ok(0);
}


#[tracepoint(name = "nvme_complete_rq", category = "nvme")]
pub fn nvme_complete_rq(ctx: TracePointContext) -> c_long {
    match try_nvme_complete_rq(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}



pub fn try_nvme_complete_rq(ctx: TracePointContext) -> Result<c_long, c_long> {
    // sudo cat /sys/kernel/debug/tracing/events/nvme/nvme_setup_cmd/format
    const DISK_OFFSET: usize = 8;
    let mut opaque: [u8; 32] = unsafe { ctx.read_at(DISK_OFFSET)? };
    const CID_OFFSET: usize = 48;
    let cid: u16 = unsafe { ctx.read_at(CID_OFFSET)? };
    unsafe {
        let now = &helpers::bpf_ktime_get_ns();
        let entry = match STATE_TRACKER.get(&cid) {
            Some(entry) => entry,
            None => return Err(1),
        };
        let from = entry.from;
        let opcode = entry.opcode;
        let elasped = now - from;
        info!(&ctx, "nvme call finished for {}/{} elapsed {}us", cid, opcode, elasped / 1000);
        opaque[31] = opcode;
        let sub_key = NvneHistogramKey{ opaque };
        NVME_HISTOGRAM.observe(sub_key, elasped)
    }

    return Ok(0);
}
