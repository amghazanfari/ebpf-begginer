# Chapter 2: Your First eBPF Program - Kprobes and Tracing

Awesome job running your first eBPF program! You just dynamically attached sandboxed code to a live running kernel.

Let's dive into what is actually happening.

## What is a Kprobe?

A **Kprobe** (Kernel Probe) allows you to dynamically intercept almost any function within the Linux kernel. When the kernel reaches the specified function, your eBPF program runs, allowing you to inspect arguments, return values, or simply log that the function was called.

There are two types:
1. `kprobe`: Runs *before* the kernel function executes.
2. `kretprobe`: Runs *after* the kernel function executes (allowing you to inspect its return value).

## Exploring the Generated Code

Your generated project has two halves: the Kernel Space (eBPF code) and User Space (the Rust program that manages the eBPF code).

### 1. The Kernel Space Program
Open `my_ebpf_agent-ebpf/src/main.rs`. This is the code running inside the kernel!

Notice the `#[kprobe]` macro. This tells Aya to compile this function as a kprobe eBPF program.
Inside `try_my_ebpf_agent`, you'll see a line like:
```rust
info!(&ctx, "function try_to_wake_up called");
```
Aya sets up an efficient ring buffer behind the scenes to ship these logs from the kernel up to your userspace program.

### 2. The User Space Program
Open `my_ebpf_agent/src/main.rs`. This program does the heavy lifting:
1. **Loads** the compiled eBPF bytecode (`bpf.load()`).
2. **Attaches** the program to the kernel function (`bpf.program_mut("my_ebpf_agent").unwrap().attach(...)`).
3. **Listens** for logs coming from the kernel (`BpfLogger::init(...)`).

## Exercise 2.1: Extracting the Process ID (PID)

Logging a static string is cool, but eBPF is powerful because it lets you inspect system state. Let's modify our eBPF program to log the Process ID (PID) of the application that triggered the `try_to_wake_up` function.

In eBPF, we use "Helper Functions" to ask the kernel for information safely. To get the PID, we use `bpf_get_current_pid_tgid()`. 

**Step 1:** Open `my_ebpf_agent-ebpf/src/main.rs`.
**Step 2:** Import the helper function at the top of the file:
```rust
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
```
**Step 3:** Inside your `try_my_ebpf_agent` function, extract the PID and log it. The `bpf_get_current_pid_tgid` function returns a 64-bit integer where the top 32 bits are the PID (Thread Group ID in kernel terms) and the bottom 32 bits are the thread ID.
Change your logging code to look like this:

```rust
fn try_my_ebpf_agent(ctx: ProbeContext) -> Result<u32, u32> {
    // Call the helper function
    let pid_tgid = bpf_get_current_pid_tgid();
    
    // The PID is in the upper 32 bits
    let pid = (pid_tgid >> 32) as u32;

    // Log the PID dynamically!
    info!(&ctx, "try_to_wake_up called by PID: {}", pid);
    
    Ok(0)
}
```

## Exercise 2.2: Recompile and Run

Once you've saved the changes to the eBPF code, run your userspace program again (make sure you use `sudo` or run it as root as eBPF requires privileges):

```bash
cd my_ebpf_agent
RUST_LOG=info cargo xtask run
```

*Note: The `cargo xtask run` command is a neat Aya feature that automatically compiles your eBPF code, compiles your userspace code, and then runs the userspace code.*

Try this out! You should now see a stream of logs showing exactly which Process IDs are waking up tasks on your machine. Let me know when you get this working, and we will move on to high-performance networking with XDP in Chapter 3!
