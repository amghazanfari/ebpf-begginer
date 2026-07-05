# Chapter 8: Capstone Project - Unified eBPF Architecture

Production-grade observability and security suites typically employ a unified agent architecture, synthesizing multiple eBPF programs into a cohesive deployment model managed by a singular userspace application.

## 8.1 Multi-Program Structuring

Aya supports the compilation and execution of heterogeneous eBPF program types within a single binary payload. This capstone project integrates the network filtering mechanisms constructed in Chapter 3 with the process monitoring capabilities defined in Chapter 5.

## 8.2 Exercise: Unified Agent Implementation

### Step 1: Base Project Configuration
Initialize the workspace and provision the necessary dependencies:

```bash
cargo generate -n mini_cilium -d program_type=xdp https://github.com/aya-rs/aya-template
cd mini_cilium/mini_cilium-ebpf
cargo add network-types
```

### Step 2: Multi-Program eBPF Integration
Modify `mini_cilium-ebpf/src/main.rs` to encapsulate both the `#[xdp]` macro and the `#[tracepoint]` macro within the same module.

```rust
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
            info!(&ctx, "FIREWALL: Dropped ICMP packet.");
            return Ok(xdp_action::XDP_DROP);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };
    Ok(action)
}

#[tracepoint]
pub fn exec_monitor(ctx: TracePointContext) -> u32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    info!(&ctx, "MONITOR: Process {} executed a command.", pid);
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
```

### Step 3: Userspace Orchestration
Modify `mini_cilium/src/main.rs` to sequentially instantiate and attach both eBPF programs via the `aya` API framework.

```rust
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mini_cilium"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            log::warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Attach XDP Program
    let program: &mut aya::programs::Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, aya::programs::XdpMode::default())
        .context("failed to attach the XDP program")?;
    log::info!("Attached XDP Firewall to interface: {}", opt.iface);

    // Attach Tracepoint Program
    let program: &mut aya::programs::TracePoint = ebpf.program_mut("exec_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;
    log::info!("Attached Tracepoint Exec Monitor");

    println!("Unified agent is operational. Waiting for SIGINT...");
    signal::ctrl_c().await?;
    println!("Exiting...");
```

Compile and execute the program to observe simultaneous enforcement of networking restrictions and telemetry collection.
