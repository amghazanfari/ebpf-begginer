#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, tracepoint},
    programs::{XdpContext, TracePointContext},
    helpers::bpf_get_current_pid_tgid,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpError, Ipv4Hdr, IpProto},
};

#[xdp]
pub fn firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end { return Err(()); }
    Ok((start + offset) as *const T)
}

fn try_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*ethhdr).ether_type() } != Ok(EtherType::Ipv4) {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };

    let proto = unsafe { (*ipv4hdr).proto() }
        .map_err(|IpError::InvalidProto(_proto)| ())?;

    let action = match proto {
        IpProto::Icmp => {
            info!(&ctx, "🛡️ FIREWALL: Dropped ICMP (Ping) packet!");
            return Ok(xdp_action::XDP_DROP);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };
    Ok(action)
}

#[tracepoint]
pub fn exec_monitor(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "👁️ MONITOR: Process {} just executed a command!", pid);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
