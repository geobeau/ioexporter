#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext, maps::PerCpuArray};


#[map]
static PAGE_CACHE_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);


static MARK_PAGE_ACCESSED_COUNTER_IDX: u32 = 0;
static ADD_TO_PAGE_LRU_COUNTER_IDX: u32 = 1;
static MARK_BUFFER_DIRTY_COUNTER_IDX: u32 = 2;

#[kprobe]
pub fn mark_page_accessed(_: ProbeContext) -> u32 {
    unsafe {
        if let Some(metric) = PAGE_CACHE_METRICS.get_ptr_mut(MARK_PAGE_ACCESSED_COUNTER_IDX){
            *metric += 1;
        }
    }

    return 0
}

#[kprobe]
pub fn add_to_page_cache_lru(_: ProbeContext) -> u32 {
    unsafe {
        if let Some(metric) = PAGE_CACHE_METRICS.get_ptr_mut(ADD_TO_PAGE_LRU_COUNTER_IDX){
            *metric += 1;
        }
    }

    return 0
}

#[kprobe]
pub fn mark_buffer_dirty(_: ProbeContext) -> u32 {
    unsafe {
        if let Some(metric) = PAGE_CACHE_METRICS.get_ptr_mut(MARK_BUFFER_DIRTY_COUNTER_IDX){
            *metric += 1;
        }
    }

    return 0
}
