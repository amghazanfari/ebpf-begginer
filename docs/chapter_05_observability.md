# Chapter 5: Advanced Observability with Tracepoints and Uprobes

So far, we have manipulated the network and traced raw kernel functions using Kprobes. While Kprobes are incredibly powerful, they have a major downside: **they are unstable**. Kernel functions change names or get removed between Linux updates, which can break your eBPF Kprobes!

To build a reliable observability or security agent (like Cilium or Tetragon), we rely on two other powerful hook points: **Tracepoints** and **Uprobes**.

## 5.1 Tracepoints: Stable Kernel Hooks
Tracepoints are static markers placed manually by Linux kernel developers. They are guaranteed to remain stable across kernel versions. 

Whenever you want to observe a system event (like a process starting, a file opening, or a network socket connecting), you should always look for a Tracepoint first, and only fall back to a Kprobe if a Tracepoint doesn't exist.

## 5.2 Uprobes: Spying on User-Space
What if you want to monitor something that never reaches the kernel? For example, what if you want to intercept the plaintext HTTP data *before* it gets encrypted by OpenSSL? 

**Uprobes (User-Space Probes)** allow you to attach eBPF programs to functions inside *any running application*. You can attach a Uprobe to `bash` to see exactly what commands a user is typing, or to `libssl.so` to intercept `SSL_write`.

## 5.3 Exercise: Building an Exec Monitor (Tracepoint)

In this exercise, we will build a security tool that logs every time a new process is executed on the system. We will use the `sched_process_exec` tracepoint.

### Step 1: Generate the Tracepoint Project
Go to `/home/amir/ebpf` and run:

```bash
cargo generate -n exec_monitor -d program_type=tracepoint https://github.com/aya-rs/aya-template
```

When it asks: `Where to attach the tracepoint?`
Type: `sched:sched_process_exec`

### Step 2: Write the Tracepoint Code
Open `exec_monitor/exec_monitor-ebpf/src/main.rs`.

Aya's `TracePointContext` is very simple to use. However, reading the raw string of the command that was executed requires reading kernel memory. To do this, we use the `bpf_probe_read_user_str_bytes` helper.

Replace the contents of `exec_monitor-ebpf/src/main.rs` with:

```rust
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
    // 1. Get the PID of the process
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // 2. We can simply log that an execution happened for this PID
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
```

### Step 3: Run and Test
1. Navigate to the root of the workspace: `cd /home/amir/ebpf/exec_monitor`
2. Run it: `RUST_LOG=info cargo xtask run`
3. Open a new terminal and type some commands like `ls`, `cat`, or `echo`.

Watch your logs! Every time a new process spawns, your eBPF tracepoint will instantly catch it. This is exactly how commercial Cloud Native Security tools monitor what is happening inside Docker containers!

Once you have the `exec_monitor` running and catching your `ls` commands, let me know, and we will move on to **Chapter 6: eBPF Maps**, where we will finally learn how to share complex data structures (like the actual command string `ls`) between the kernel and userspace!
