# Chapter 7: Security Observability and Active Mitigation

Modern Cloud Native Security solutions extend beyond passive observability into proactive system enforcement. eBPF provides the infrastructure necessary to intercept and terminate unauthorized kernel operations dynamically.

## 7.1 Active Mitigation Mechanisms

eBPF enforces system state via two primary vectors:
1. **BPF-LSM (Linux Security Modules):** Allows eBPF to interface directly with the LSM framework, returning denial codes to block systemic actions. This methodology requires the `CONFIG_BPF_LSM` kernel configuration.
2. **Signal Injection:** Utilizes standard tracepoints or kprobes coupled with signal injection APIs to immediately terminate an offending process. This technique maintains broader compatibility across standard Linux kernels.

## 7.2 Exercise: Process Mitigation via Signal Injection

This exercise constructs an agent that hooks the file access routine (`do_sys_openat2`) and transmits a `SIGKILL` to any process matching a restricted name pattern (e.g., `wget`).

### Step 1: Project Generation

Generate a kprobe project targeted at file access operations:
```bash
cargo generate -n security_agent -d program_type=kprobe https://github.com/aya-rs/aya-template
```
Target the `do_sys_openat2` kernel function.

### Step 2: Signal Injection Implementation

Modify `security_agent-ebpf/src/main.rs` to evaluate the active process nomenclature and transmit a termination signal if a match is determined.

```rust
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
    helpers::{bpf_get_current_comm, bpf_send_signal},
};
use aya_log_ebpf::info;

#[kprobe]
pub fn security_agent(ctx: ProbeContext) -> u32 {
    match try_security_agent(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_security_agent(ctx: ProbeContext) -> Result<u32, u32> {
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
    let malicious_comm = b"wget\0\0\0\0\0\0\0\0\0\0\0\0";

    let mut is_malicious = true;
    for i in 0..4 {
        if comm[i] != malicious_comm[i] {
            is_malicious = false;
            break;
        }
    }

    if is_malicious {
        info!(&ctx, "SECURITY ALERT: Mitigating unauthorized execution of 'wget'");
        unsafe {
            bpf_send_signal(9);
        }
    }

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

### Step 3: Execution and Verification

Execute the binary:
```bash
RUST_LOG=info cargo xtask run
```
Invoke the restricted application in a secondary terminal (`wget https://google.com`). The process will be terminated prematurely by the kernel, yielding a `Killed` directive to standard output.
