# Chapter 2: Kprobes and Tracing

## 2.1 The Kprobe Hook Point

A **Kprobe** (Kernel Probe) is a mechanism that allows developers to dynamically intercept execution at almost any instruction within the Linux kernel. When the kernel reaches the specified function, the attached eBPF program executes, providing access to inspect function arguments, return values, or simply record the invocation event.

Two primary variants exist:
1. `kprobe`: Executes *before* the target kernel function executes.
2. `kretprobe`: Executes *after* the target kernel function executes, facilitating inspection of its return value.

## 2.2 Analyzing the eBPF Architecture

An eBPF project is divided into Kernel Space and User Space components.

### 2.2.1 The Kernel Space Program
The code located in `my_ebpf_agent-ebpf/src/main.rs` represents the logic executed within the kernel. 

The `#[kprobe]` macro instructs the compiler to format the function as a kprobe eBPF program. A typical logging implementation utilizes the `aya_log_ebpf` crate:
```rust
info!(&ctx, "function try_to_wake_up called");
```
This macro leverages a ring buffer to efficiently stream log data from the kernel to the userspace application.

### 2.2.2 The User Space Program
The application in `my_ebpf_agent/src/main.rs` manages the lifecycle of the eBPF program:
1. **Loading**: Reads and loads the compiled eBPF bytecode via `bpf.load()`.
2. **Attaching**: Binds the loaded program to the specific kernel function via `attach()`.
3. **Listening**: Initializes the asynchronous logger to receive events from the kernel via `BpfLogger::init(...)`.

## 2.3 Exercise 2.1: Extracting System State

eBPF's primary utility lies in system state inspection. This exercise modifies the eBPF program to extract the Process ID (PID) of the application responsible for triggering the kernel function.

eBPF programs interact with the kernel through restricted "Helper Functions." To retrieve the PID, the `bpf_get_current_pid_tgid()` helper is used.

**Step 1:** Modify `my_ebpf_agent-ebpf/src/main.rs` to import the helper function:
```rust
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
```

**Step 2:** Extract the PID within the probe function. The helper returns a 64-bit integer where the upper 32 bits contain the Thread Group ID (which corresponds to the PID in userspace semantics).

```rust
fn try_my_ebpf_agent(ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    info!(&ctx, "try_to_wake_up called by PID: {}", pid);
    
    Ok(0)
}
```

## 2.4 Exercise 2.2: Compilation and Execution

After saving modifications, the userspace program must be recompiled and executed with elevated privileges to attach the probe.

```bash
cd my_ebpf_agent
RUST_LOG=info cargo xtask run
```

The output stream will display the active Process IDs invoking the traced kernel function.
