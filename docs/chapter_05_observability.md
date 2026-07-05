# Chapter 5: Advanced Observability with Tracepoints and Uprobes

While Kprobes offer significant utility for kernel tracing, their reliance on dynamic function names makes them susceptible to breakage across different Linux kernel versions. For production-grade observability and security agents, stability is paramount.

## 5.1 Tracepoints

Tracepoints are static instrumentation markers embedded directly within the kernel source code by Linux developers. They are explicitly maintained as a stable API across kernel releases. For standard system events (e.g., process execution, file I/O, network connections), Tracepoints are the preferred mechanism over Kprobes.

## 5.2 Uprobes

Uprobes (User-Space Probes) extend eBPF's tracing capabilities to userspace applications. They allow eBPF programs to attach to specific functions within running binaries or shared libraries. Common use cases include tracing bash inputs or intercepting unencrypted data structures prior to TLS encryption via `libssl.so`.

## 5.3 Exercise: Tracepoint Implementation

This exercise implements a system monitor utilizing the `sched_process_exec` tracepoint to log process executions.

### Step 1: Project Generation

Generate a tracepoint project:

```bash
cargo generate -n exec_monitor -d program_type=tracepoint https://github.com/aya-rs/aya-template
```
Configure the attachment point as: `sched:sched_process_exec`.

### Step 2: Implementation
Replace the contents of `exec_monitor-ebpf/src/main.rs` with the following. The implementation leverages `bpf_get_current_pid_tgid` to identify the invoking process.

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
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
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

### Step 3: Execution
Run the userspace application:
```bash
RUST_LOG=info cargo xtask run
```
Execute commands in a secondary terminal to observe the tracepoint triggering.
