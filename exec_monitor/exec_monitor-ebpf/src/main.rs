#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    helpers::bpf_get_current_pid_tgid,
};
use aya_log_ebpf::info;

#[tracepoint]
pub fn exec_monitor(ctx: TracePointContext) -> u32 {
    match try_exec_monitor(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_exec_monitor(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    info!(&ctx, "SECURITY ALERT: Process {} executed a new program!", pid);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
