# Chapter 1: Getting Started with eBPF and Aya

## What is eBPF?

eBPF (Extended Berkeley Packet Filter) is a revolutionary technology that allows you to run sandboxed programs in an operating system kernel. It is used to safely and efficiently extend the capabilities of the kernel without requiring to change kernel source code or load kernel modules.

eBPF programs are event-driven and run when the kernel or an application passes a certain hook point. Examples of hook points include system calls, function entry/exit, kernel tracepoints, and network events.

## Why Rust and Aya?

Traditionally, eBPF programs are written in C and compiled using Clang/LLVM. The userspace programs that load and interact with them are written in C, Go, or Python.

[Aya](https://aya-rs.dev/) is an eBPF library built with a focus on developer experience and operability. It allows us to write both our eBPF programs AND our userspace programs entirely in Rust! This gives us memory safety, a fantastic package manager (Cargo), and an excellent developer experience.

## Setting up your environment

To write eBPF programs in Rust, you'll need the Rust toolchain, a linker (`bpf-linker`), and the Aya generator (`cargo-generate`).

**Exercise 1.1: Install Dependencies**

Open your terminal and run the following commands to install everything you need:

```bash
# 1. Install the nightly Rust toolchain (required for eBPF)
rustup toolchain install nightly --component rust-src

# 2. Install bpf-linker
cargo install bpf-linker

# 3. Install cargo-generate
cargo install cargo-generate
```

## Creating Your First Project

Once the dependencies are installed, we can generate our project structure.

**Exercise 1.2: Generate the Aya Project**

Run the following command inside your workspace:

```bash
cargo generate -n my_ebpf_agent -d program_type=kprobe https://github.com/aya-rs/aya-template
```

This will create a new directory called `my_ebpf_agent` with two sub-projects:
1. `my_ebpf_agent`: The userspace program (loads the eBPF code into the kernel).
2. `my_ebpf_agent-ebpf`: The actual eBPF code that runs in the kernel.

Explore the generated files. Once you have successfully generated the template, we'll move on to Chapter 2, where we will write our first `kprobe` program to intercept kernel functions!
