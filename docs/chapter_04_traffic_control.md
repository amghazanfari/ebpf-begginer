# Chapter 4: Traffic Control (TC) and Network Manipulation

## 4.1 XDP vs Traffic Control (TC)

While XDP provides optimal performance for ingress packet filtering, Traffic Control (TC) offers a broader scope for network manipulation. The primary distinctions are:

1. **Directionality:** XDP executes exclusively on **Ingress**. TC supports attachment to both **Ingress** and **Egress** paths.
2. **Data Structures:** XDP operates on raw, unparsed byte arrays. TC executes after the kernel has parsed the packet and allocated an `sk_buff` (Socket Buffer) structure, granting the eBPF program access to richer networking metadata.

### TC Return Codes
Similar to XDP, a TC eBPF program determines packet flow via specific return codes:
- `TC_ACT_PIPE`: Passes the packet to the subsequent TC program or the default network stack.
- `TC_ACT_SHOT`: Drops the packet immediately.
- `TC_ACT_OK`: Terminates the TC pipeline and permits the packet to proceed.
- `TC_ACT_REDIRECT`: Redirects the packet to an alternate network interface.
- `TC_ACT_STOLEN`: Indicates the eBPF program has consumed the packet, effectively dropping it from the kernel's perspective.

## 4.2 Exercise: Project Generation

Generate a TC workspace using the classifier template:

```bash
cargo generate -n tc_interceptor -d program_type=classifier https://github.com/aya-rs/aya-template
```

## 4.3 Exercise: Egress Traffic Interception

This exercise implements a TC program that monitors outbound traffic and logs connections targeting standard web ports (80 and 443).

### Step 1: Dependencies
Include the `network-types` crate in the eBPF package:
```bash
cd tc_interceptor/tc_interceptor-ebpf
cargo add network-types
```

### Step 2: The Classifier Implementation
Replace `tc_interceptor-ebpf/src/main.rs` with the following logic:

```rust
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
```

## 4.4 Exercise: Egress Configuration

By default, the userspace loader may attach the program to the Ingress path. Modify `tc_interceptor/src/main.rs` to enforce Egress attachment:

```rust
    tc::qdisc_add_clsact(&iface)?;
    let program: &mut dyn Program = bpf.program_mut("tc_interceptor").unwrap();
    let tc_program: &mut aya::programs::tc::SchedClassifier = program.try_into()?;
    tc_program.load()?;
    
    // Attach to Egress
    tc_program.attach(&iface, aya::programs::tc::TcAttachType::Egress)?;
```

Execute the agent and trigger an outbound connection via `curl -I https://google.com` to observe the trace logs.
