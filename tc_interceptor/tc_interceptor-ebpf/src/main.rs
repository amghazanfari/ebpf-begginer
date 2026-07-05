#![no_std]
#![no_main]

use aya_ebpf::{
    macros::classifier,
    programs::TcContext,
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

#[classifier]
pub fn tc_interceptor(ctx: TcContext) -> i32 {
    match try_tc_interceptor(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_tc_interceptor(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(TC_ACT_PIPE),
    }
    
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let dest_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    let proto = unsafe { (*ipv4hdr).proto() };
    if !matches!(proto, Ok(IpProto::Tcp)) {
        return Ok(TC_ACT_PIPE);
    }

    let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + 20)? };

    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

    if dest_port == 80 || dest_port == 443 {
        info!(&ctx, "OUTBOUND web traffic to IP: {:i} on Port: {}", dest_addr, dest_port);
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
