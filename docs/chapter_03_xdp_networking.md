# Chapter 3: High-Performance Networking with XDP

Welcome to the exciting world of high-performance packet processing! While Kprobes are excellent for tracing what the kernel is doing, XDP is the standard for building blazingly fast network agents, DDoS mitigators, and cloud-native firewalls (like Cilium).

## 3.1 What is XDP (eXpress Data Path)?

XDP is a specialized type of eBPF program that attaches directly to the **receive (RX) path of a network interface card (NIC)**. 

Normally, when a packet arrives at your machine, the NIC driver allocates memory (an `sk_buff`), copies the packet, and hands it off to the massive, complex Linux TCP/IP stack. This takes time and CPU cycles.

**XDP bypasses all of this.** An XDP program executes *immediately* when the NIC receives the packet, before the Linux kernel has even allocated a memory structure for it. At this point, the packet is just a raw array of bytes in memory. 

### The Power of XDP Return Codes
When your XDP program finishes analyzing a packet, it must return a specific code to tell the kernel what to do next:
- `XDP_PASS`: "This packet is fine. Send it up to the normal Linux network stack."
- `XDP_DROP`: "Drop this packet immediately!" (This is how XDP mitigates DDoS attacks with zero overhead).
- `XDP_TX`: "Bounce this packet right back out the same network interface."
- `XDP_REDIRECT`: "Send this packet out a different network interface."
- `XDP_ABORTED`: "My program encountered an error, drop the packet and log a warning."

## 3.2 Exercise: Generating an XDP Project

Let's generate a new project specifically tailored for XDP. 

Open your terminal, ensure you are in your `/home/amir/ebpf` directory, and run:

```bash
cargo generate -n xdp_firewall -d program_type=xdp https://github.com/aya-rs/aya-template
```

This will create a new workspace called `xdp_firewall`. 

### Exploring the XDP Template

Open `xdp_firewall-ebpf/src/main.rs`. You'll notice it looks quite different from your Kprobe program!

```rust
#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

// ... panic handler ...
```

By default, the template simply logs that a packet arrived and returns `XDP_PASS` (allowing the packet through). 

## 3.3 Exercise: Building a Simple ICMP (Ping) Dropper

Right now, our program just logs "received a packet". Because XDP operates on raw bytes, to understand the packet, we must manually parse its headers: Ethernet -> IPv4 -> ICMP.

In this exercise, we will write a program that drops all ping requests (ICMP) but allows everything else to pass.

### Step 1: Add Network Parsing Dependencies
Parsing raw bytes safely in Rust can be tedious. Aya provides an excellent crate called `network-types` that gives us safe, zero-copy Rust structures for network headers.

Navigate into the `xdp_firewall-ebpf` directory:
```bash
cd xdp_firewall/xdp_firewall-ebpf
cargo add network-types
```

### Step 2: Write the Packet Parser

Now, open `xdp_firewall-ebpf/src/main.rs` and replace the entire contents with the following code. Read the comments carefully—this code acts as a textbook example of safe eBPF memory access!

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

// A helper function to safely check if our memory access is within the packet boundaries.
// In eBPF, the verifier will REJECT your program if you don't explicitly check bounds!
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

    // 2. We only care about IPv4 traffic.
    // The `ether_type()` method safely handles byte-order for us!
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // 3. Read the IPv4 Header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    
    // 4. Extract the Source IP address
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    // 5. Extract protocol using safe methods
    let proto = unsafe { (*ipv4hdr).proto() }.unwrap_or(IpProto::Unknown);

    if proto == IpProto::Icmp {
        // Log that we are blocking a ping
        info!(&ctx, "BLOCKING Ping (ICMP) from source IP: {:i}", source_addr);
        return Ok(xdp_action::XDP_DROP);
    }

    // Allow all other IPv4 traffic
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### Notice the `{:i}` in the log macro?
`aya_log_ebpf::info!` has special formatters. `{:i}` tells the userspace logging daemon to decode that integer specifically as an IPv4 address string!

## 3.4 Exercise: Run and Test Your Firewall

1. Return to the root of your `xdp_firewall` workspace:
   ```bash
   cd ..
   ```
2. Run your new XDP firewall (by default, the userspace code attaches it to `eth0`, or you can specify your network interface like `wlan0` or `lo` if needed by looking at the userspace `src/main.rs`):
   ```bash
   RUST_LOG=info cargo xtask run
   ```

**The Test:**
While your program is running, open a completely separate terminal and try to ping your own machine:
```bash
ping 127.0.0.1
```
*(Wait, pinging localhost uses the `lo` interface! If you want to test this, you will need to open `xdp_firewall/src/main.rs`, find the `opt.iface` parameter, and change the default interface to `"lo"` or pass `--iface lo` when running).*

Try running it:
```bash
RUST_LOG=info cargo xtask run -- --iface lo
```
Then ping `127.0.0.1`. Your pings should freeze entirely because they are being dropped by the kernel, and your eBPF program should log the blocked IPs!

When you have successfully blocked ICMP packets, let me know, and we'll explore **Chapter 4: Traffic Control (TC) and Network Manipulation**!
