# Chapter 8: Capstone Project - The Mini-Cilium Agent

Congratulations! You have learned the three fundamental pillars of eBPF:
1. **High-Performance Networking** (XDP & TC)
2. **System Observability** (Tracepoints & Kprobes)
3. **State Management & Active Security** (Maps & Signal Injection)

Real-world Cloud Native tools like **Cilium** and **Tetragon** don't just use one of these features—they combine them all into a massive, unified agent. In this final Capstone project, you will architect a unified "Mini-Cilium" agent that runs multiple different eBPF programs simultaneously from a single Userspace control plane!

## 8.1 The Unified Agent Architecture

Up until now, you generated a separate project for each program type. But Aya allows you to compile multiple eBPF programs into a single binary and load them all together!

In this capstone, we will combine our XDP Firewall (from Chapter 3) and our Process Exec Monitor (from Chapter 5) into a single agent.

## 8.2 Exercise: Building Mini-Cilium

### Step 1: Generate the Project
Navigate to `/home/amir/ebpf` and generate a base XDP project:

```bash
cargo generate -n mini_cilium -d program_type=xdp https://github.com/aya-rs/aya-template
```
Then, add the networking dependencies:
```bash
cd mini_cilium/mini_cilium-ebpf
cargo add network-types
```

### Step 2: The Unified eBPF Code
Open `mini_cilium-ebpf/src/main.rs`. Notice how we can simply declare two different macros (`#[xdp]` and `#[tracepoint]`) in the exact same file! 

Replace the contents with:

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
```

### Step 3: The Unified Userspace Code
Now open `mini_cilium/src/main.rs` (the userspace code). We need to modify it so it loads *both* programs into the kernel!

Find the `bpf.load()` code, and modify it to look exactly like this:

```rust
    // Load the eBPF bytecode
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

    // 1. Attach the XDP Firewall
    let program: &mut Xdp = ebpf.program_mut("firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, aya::programs::XdpMode::default())
        .context("failed to attach the XDP program with default mode")?;
    log::info!("Attached XDP Firewall to interface: {}", opt.iface);

    // 2. Attach the Tracepoint Monitor
    let program: &mut aya::programs::TracePoint = ebpf.program_mut("exec_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;
    log::info!("Attached Tracepoint Exec Monitor");

    println!("Mini-Cilium is fully operational. Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");
```

### Step 4: Run Your Unified Agent!

1. From the `mini_cilium` directory, run your agent (don't forget to attach it to the loopback interface if you want to test pings locally!):
   ```bash
   RUST_LOG=info cargo xtask run -- --iface lo
   ```
2. Open a separate terminal.
3. Run `ls` to trigger the Exec Monitor!
4. Run `ping 127.0.0.1` to trigger the Firewall!

You will see logs streaming from both programs simultaneously within the same rust application!

## Conclusion

You have successfully completed this eBPF bootcamp! You now understand the core mechanics used to build industry-leading tools like **Cilium**, **Tetragon**, **Falco**, and **Pixie**. 

With Rust and Aya, the kernel is no longer a black box—it is a programmable playground. Happy hacking!
