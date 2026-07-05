#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    helpers::bpf_get_current_pid_tgid,
};
use aya_log_ebpf::info;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[map]
static EXEC_COUNTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn exec_monitor(ctx: TracePointContext) -> u32 {
    match try_exec_monitor(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_exec_monitor(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let current_count = unsafe { EXEC_COUNTS.get(&pid).copied().unwrap_or(0) };

    let new_count = current_count + 1;

    unsafe {
        EXEC_COUNTS.insert(&pid, &new_count, 0).map_err(|_| 1u32)?;
    }

    info!(&ctx, "PID: {} has now executed {} programs", pid, new_count);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
