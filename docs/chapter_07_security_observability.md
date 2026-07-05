# Chapter 7: Security Observability - Catching Malicious Activity

Observing the system is only half the battle. In modern Cloud Native Security (like Cilium Tetragon or Falco), the goal is not just to log malicious activity, but to **stop it actively in its tracks**.

In this chapter, we will transition from passive observability to **Active Response**. We will write an eBPF program that monitors file access and immediately kills any process that is deemed malicious.

## 7.1 Active Mitigation in eBPF

There are two main ways eBPF can block kernel activity:
1. **BPF-LSM (Linux Security Modules):** This allows eBPF to hook into the Linux Security Module framework directly (like SELinux or AppArmor) and return an "Access Denied" error. This is the modern, preferred way to block activity, but it requires a very specific kernel configuration (`CONFIG_BPF_LSM`).
2. **Signal Injection:** We can attach a standard `kprobe` or `tracepoint`, and if we detect malicious activity, we can use an eBPF helper function to instantly send a `SIGKILL` (Kill Signal) to the process making the request. 

Because Signal Injection works on almost all standard Linux kernels, we will use it for this exercise!

## 7.2 Exercise: The Anti-Wget Security Agent

Let's imagine that downloading files via `wget` is strictly forbidden on our production servers. We want to write a security agent that instantly kills `wget` the moment it tries to open any file (which happens immediately when it starts up or tries to resolve a DNS name).

### Step 1: Generate the Project

Navigate to `/home/amir/ebpf` and generate a new kprobe project:
```bash
cargo generate -n security_agent -d program_type=kprobe https://github.com/aya-rs/aya-template
```
When it asks where to attach the kprobe, type: `do_sys_openat2` (This is the kernel function responsible for opening files).

### Step 2: The EBPF Code

Open `security_agent-ebpf/src/main.rs`.

We are going to use two eBPF helper functions:
1. `bpf_get_current_comm`: Gets the name of the currently running process (up to 16 bytes).
2. `bpf_send_signal`: Sends a signal to the current process. Signal `9` is `SIGKILL`.

Replace the contents with:

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
    // 1. Get the name of the current process (comm is short for "command")
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    // 2. The command name is a byte array. Let's check if it matches "wget"
    // "wget" is 4 characters, padded with null bytes.
    let malicious_comm = b"wget\0\0\0\0\0\0\0\0\0\0\0\0";

    // Compare the current command to our forbidden command
    let mut is_malicious = true;
    for i in 0..4 {
        if comm[i] != malicious_comm[i] {
            is_malicious = false;
            break;
        }
    }

    // 3. If it is malicious, send a SIGKILL!
    if is_malicious {
        // Log the alert to userspace
        info!(&ctx, "🚨 SECURITY ALERT: Blocked 'wget' from opening a file!");
        
        // Send signal 9 (SIGKILL)
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

### Step 3: Run and Test

1. Navigate to the root of your workspace: `cd /home/amir/ebpf/security_agent`
2. Run your security agent:
   ```bash
   RUST_LOG=info cargo xtask run
   ```
3. Open a completely separate terminal and try to run `wget`:
   ```bash
   wget https://google.com
   ```

**What should happen:**
The moment `wget` executes and attempts to open standard system libraries or sockets via `do_sys_openat2`, your eBPF program will detect its name, fire a `SIGKILL` directly from the kernel, and the `wget` process will terminate instantly with a `Killed` message in your terminal!

Try this out. Once you have successfully killed `wget`, let me know, and we will move on to our final **Chapter 8: The Capstone Mini-Cilium Agent**!
