# Chapter 3: Basic Networking with XDP

## 3.1 The eXpress Data Path (XDP)

XDP is a specialized eBPF program type designed for high-performance packet processing. It attaches directly to the **receive (RX) path of a network interface card (NIC)**.

In standard networking, when a packet arrives, the NIC driver allocates an `sk_buff` structure, copies the packet data, and forwards it to the Linux TCP/IP stack. XDP bypasses this overhead by executing immediately upon packet reception, before memory allocation occurs. At this stage, the packet is processed as a raw byte array.

### XDP Return Codes
Upon inspecting a packet, an XDP program dictates its fate by returning one of several action codes:
- `XDP_PASS`: Permits the packet to proceed to the standard Linux network stack.
- `XDP_DROP`: Discards the packet immediately (efficient for DDoS mitigation).
- `XDP_TX`: Transmits the packet back out through the receiving interface.
- `XDP_REDIRECT`: Forwards the packet to a different network interface or CPU.
- `XDP_ABORTED`: Indicates an error during processing; the packet is dropped and a tracepoint is triggered.

## 3.2 Exercise: Project Generation

Generate a dedicated workspace for XDP development:

```bash
cargo generate -n xdp_firewall -d program_type=xdp https://github.com/aya-rs/aya-template
```

## 3.3 Exercise: Implementing an ICMP Filter

This exercise demonstrates how to manually parse network headers to identify and drop ICMP (Ping) packets.

### Step 1: Network Parsing Dependencies
The `network-types` crate provides safe, zero-copy Rust structures for mapping network headers over raw byte arrays.

```bash
cd xdp_firewall/xdp_firewall-ebpf
cargo add network-types
```

### Step 2: The eBPF Parser Implementation
Replace the contents of `xdp_firewall-ebpf/src/main.rs` with the following implementation. The `ptr_at` function enforces strict bounds checking, a requirement for passing the eBPF Verifier.

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action, 
    macros::xdp, 
    programs::XdpContext
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
};

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    // Validate IPv4 traffic using safe getter methods
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    // Validate and handle ICMP protocol
    let proto = unsafe { (*ipv4hdr).proto() }.unwrap_or(IpProto::Unknown);

    if proto == IpProto::Icmp {
        info!(&ctx, "BLOCKING Ping (ICMP) from source IP: {:i}", source_addr);
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
```

## 3.4 Exercise: Execution and Testing

Execute the userspace loader. To test ICMP filtering locally, target the loopback interface (`lo`):

```bash
RUST_LOG=info cargo xtask run -- --iface lo
```

Verify the mitigation by transmitting ICMP echo requests in an adjacent terminal:
```bash
ping 127.0.0.1
```
The packets will be dropped silently at the interface level, triggering the log statement.
