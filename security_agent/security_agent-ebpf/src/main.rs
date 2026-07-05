#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    helpers::{bpf_get_current_comm, bpf_send_signal},
};
use aya_log_ebpf::info;

#[kprobe]
pub fn security_agent(ctx: ProbeContext) -> u32 {
    match try_security_agent(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_security_agent(ctx: ProbeContext) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    let malicious_comm = b"wget\0\0\0\0\0\0\0\0\0\0\0\0";
    let mut is_malicious = true;
    for i in 0..4 {
        if comm[i] != malicious_comm[i] {
            is_malicious = false;
            break;
        }
    }

    if is_malicious {
        info!(&ctx, "🚨 SECURITY ALERT: Blocked 'wget' from opening a file!");
        
        unsafe {
            bpf_send_signal(9);
        }
    }
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
