# Chapter 6: eBPF Maps and State Management

Standard eBPF programs operate ephemerally; data is inspected, potentially logged, and immediately discarded. Constructing advanced systems—such as rate-limiting firewalls or behavioral anomaly detectors—requires state persistence across multiple execution cycles.

## 6.1 Understanding eBPF Maps

eBPF Maps provide highly efficient data structures (e.g., HashMaps, Arrays, Ring Buffers) allocated directly within kernel memory. They serve two critical functions:
1. **State Persistence:** Permitting an eBPF program to retain and modify data across numerous invocations.
2. **Kernel-User Communication:** Providing an API for userspace applications to read, modify, and delete entries within the kernel-allocated maps concurrently.

## 6.2 Exercise: Aggregating Execution Metrics

This exercise refactors the `exec_monitor` to aggregate execution counts per Process ID utilizing an eBPF HashMap.

### Step 1: Map Declaration

Modify `exec_monitor-ebpf/src/main.rs` to include a globally accessible HashMap structure supporting a maximum of 1024 unique entries:

```rust
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[map]
static EXEC_COUNTS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
```

### Step 2: Map Interaction

Implement the logic to retrieve, increment, and store the execution counter within the tracepoint context:

```rust
fn try_exec_monitor(ctx: TracePointContext) -> Result<u32, u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    let current_count = unsafe { EXEC_COUNTS.get(&pid).copied().unwrap_or(0) };
    let new_count = current_count + 1;

    unsafe {
        EXEC_COUNTS.insert(&pid, &new_count, 0).map_err(|_| 1u32)?;
    }

    info!(&ctx, "PID: {} has now executed {} programs", pid, new_count);
    Ok(0)
}
```

### Step 3: Userspace Retrieval

Modify `exec_monitor/src/main.rs` to establish an asynchronous polling routine that extracts the map contents directly from the kernel interface:

```rust
    let mut exec_counts: aya::maps::HashMap<_, u32, u32> = 
        aya::maps::HashMap::try_from(bpf.map_mut("EXEC_COUNTS").unwrap())?;

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            
            println!("--- Current Execution Counts ---");
            for item in exec_counts.iter() {
                if let Ok((pid, count)) = item {
                    println!("PID {}: {} execs", pid, count);
                }
            }
        }
    });
```

Compile and execute the program to observe bidirectional data transfer.
