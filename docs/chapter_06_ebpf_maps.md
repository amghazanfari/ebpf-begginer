# Chapter 6: eBPF Maps - Storing and Sharing State

So far, our eBPF programs have been stateless. They inspect a packet or an event, log a string, and immediately forget it happened. But what if we want to build a firewall that tracks how many times an IP address has been blocked? Or a security agent that tracks how many processes a specific user has spawned?

To do this, we need **eBPF Maps**.

## 6.1 What are eBPF Maps?

eBPF Maps are highly efficient data structures (like HashMaps, Arrays, and Ring Buffers) that live directly in kernel memory. 

They are magical for two reasons:
1. **Statefulness:** eBPF programs can store data in them across multiple executions.
2. **Two-Way Sharing:** Your userspace Rust program can read from and write to these exact same maps! This is how the kernel communicates rich data structures to your userspace control plane.

*(Fun fact: The `info!()` logging macro we've been using actually uses a special type of map called a `PerfEventArray` under the hood to stream those strings to userspace!)*

## 6.2 Exercise: Tracking Execution Counts

Let's modify our `exec_monitor` from Chapter 5. Instead of just logging that a process executed, let's use a `HashMap` to explicitly count **how many times** each Process ID (PID) executes a new program.

### Step 1: Define the Map in Kernel Space
Open `exec_monitor-ebpf/src/main.rs`.

Add the map imports at the top:
```rust
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
```

Now, define your HashMap globally. It will map a `u32` (the PID) to a `u32` (the execution count). We allocate space for 1024 unique PIDs:
```rust
#[map]
static EXEC_COUNTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
```

### Step 2: Update the Map in eBPF
Inside your `try_exec_monitor` function, replace your logging code with this logic:

```rust
fn try_exec_monitor(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // 1. Try to get the current count for this PID. Default to 0 if it doesn't exist.
    // Unsafe is required because we are directly reading kernel map memory.
    let current_count = unsafe { EXEC_COUNTS.get(&pid).copied().unwrap_or(0) };

    // 2. Increment the count
    let new_count = current_count + 1;

    // 3. Save it back to the map!
    unsafe {
        // The last argument is flags (0 means BPF_ANY: create or update)
        EXEC_COUNTS.insert(&pid, &new_count, 0).map_err(|_| 1u32)?;
    }

    // 4. Log the updated count
    info!(&ctx, "PID: {} has now executed {} programs", pid, new_count);

    Ok(0)
}
```

### Step 3: Read the Map from Userspace
Now, let's look at the userspace code to see how we can read this map from outside the kernel.

Open `exec_monitor/src/main.rs`. After the tracepoint is attached (around line 34), add this code to periodically read and print the map contents:

```rust
    // Add this import at the top of your file:
    // use aya::maps::HashMap;
    // use tokio::time::{sleep, Duration};

    let program: &mut TracePoint = bpf.program_mut("exec_monitor").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    info!("Waiting for Ctrl-C...");

    // Create a binding to the eBPF Map
    let mut exec_counts: aya::maps::HashMap<_, u32, u32> = 
        aya::maps::HashMap::try_from(bpf.map_mut("EXEC_COUNTS").unwrap())?;

    // Periodically print the top offenders
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            
            println!("--- Current Execution Counts ---");
            // Iterate over all entries in the kernel map
            for item in exec_counts.iter() {
                if let Ok((pid, count)) = item {
                    println!("PID {}: {} execs", pid, count);
                }
            }
        }
    });

    signal::ctrl_c().await?;
    info!("Exiting...");
```

## 6.3 Run and Test

1. Run your updated program:
   ```bash
   RUST_LOG=info cargo xtask run
   ```
2. Open a new terminal and run several commands (like `ls`, `whoami`, etc.).

You should now see the kernel `info!` logs showing the incrementing counts immediately, AND every 5 seconds, your userspace program will directly query the kernel map and print a summary of all PIDs!

Let me know when you get the map working and iterating correctly, and we will move on to **Chapter 7: Security Observability**!
