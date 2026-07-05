# Chapter 4: Traffic Control (TC) and Network Manipulation

Excellent work building your XDP firewall! Now it's time to explore the next major eBPF network hook point: **Traffic Control (TC)**.

## 4.1 XDP vs TC: What's the Difference?

You might be wondering: *"If XDP is so fast, why do we need anything else?"*

1. **Ingress vs Egress:** XDP *only* works on **Ingress** (incoming packets). It intercepts packets the moment they arrive at the NIC. If you want to intercept **Egress** (outgoing packets)—for example, to stop a compromised container from connecting to a malicious server—you must use TC.
2. **Raw Bytes vs Socket Buffers (`sk_buff`):** XDP works on raw bytes in memory. TC, however, runs slightly higher up in the Linux network stack. By the time a packet reaches TC, the kernel has already parsed it and wrapped it in a massive data structure called an `sk_buff` (Socket Buffer). This means TC eBPF programs have access to richer socket information.

### The Power of TC Return Codes
Just like XDP, when a TC eBPF program finishes inspecting an `sk_buff`, it must return a specific code telling the kernel what to do next:
- `TC_ACT_PIPE`: "Pass this packet along to the next TC program in the chain, or to the regular network stack." (Very similar to `XDP_PASS`).
- `TC_ACT_SHOT`: "Drop this packet immediately!" (Similar to `XDP_DROP`).
- `TC_ACT_OK`: "Terminate the TC pipeline and allow the packet to proceed."
- `TC_ACT_REDIRECT`: "Send this packet out a completely different network interface."
- `TC_ACT_STOLEN`: "My eBPF program has taken full ownership of this packet memory." (Used for advanced packet mangling).

## 4.2 Exercise: Generating a TC Project

Let's generate a new workspace tailored for TC.

Go to your `/home/amir/ebpf` directory and run:

```bash
cargo generate -n tc_interceptor -d program_type=classifier https://github.com/aya-rs/aya-template
```
*(Note: TC eBPF programs are historically referred to as "classifiers" or "actions" in Linux terminology).*

## 4.3 Exercise: Intercepting Outgoing Traffic

Let's write a TC program that intercepts outgoing traffic and logs the destination IP address of any web traffic (port 80 or 443).

### Step 1: Add Network Parsing Dependencies
Just like with XDP, we will use the `network-types` crate.

Navigate into the eBPF directory:
```bash
cd tc_interceptor/tc_interceptor-ebpf
cargo add network-types
```

### Step 2: The TC eBPF Code
Open `tc_interceptor-ebpf/src/main.rs`.

Unlike XDP, our context is no longer `XdpContext`. It is now `TcContext`! Furthermore, we will use the same `ptr_at` trick we used before to safely read the packet data.

Replace the contents of `tc_interceptor-ebpf/src/main.rs` with the following:

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
        // If our parser fails, drop the packet
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

    // 3. Read the TCP Header (located after Ethernet + 20-byte IPv4 header)
    let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + 20)? };

    // dest is stored as a [u8; 2] array, so we convert it to a u16
    let dest_port = u16::from_be_bytes(unsafe { (*tcphdr).dest });

    // 4. Log HTTP (80) and HTTPS (443) traffic
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

## 4.4 Configuring the Userspace for Egress

There's one more critical step. By default, Aya might attach the TC program to the **Ingress** path. Since we want to monitor outgoing web traffic, we need to explicitly attach it to the **Egress** path.

Open `tc_interceptor/src/main.rs` (the userspace code) and look for the `TcAttachOptions` block:

```rust
    tc::qdisc_add_clsact(&iface)?;
    let program: &mut dyn Program = bpf.program_mut("tc_interceptor").unwrap();
    let tc_program: &mut aya::programs::tc::SchedClassifier = program.try_into()?;
    tc_program.load()?;
    
    // Change this line to attach to Egress instead of Ingress!
    tc_program.attach(&iface, aya::programs::tc::TcAttachType::Egress)?;
```

## 4.5 Run and Test

1. From the root of your workspace (`cd /home/amir/ebpf/tc_interceptor`), run the program:
   ```bash
   RUST_LOG=info cargo xtask run
   ```
2. In a separate terminal, trigger some outbound web traffic by using `curl`:
   ```bash
   curl -I https://google.com
   ```

You should see your eBPF program logging the outbound connection to Google's IP address! When you've got this working, let me know and we will jump into **Chapter 5: Tracepoints and Uprobes**!
