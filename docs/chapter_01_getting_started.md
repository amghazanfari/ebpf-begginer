# Chapter 1: Getting Started with eBPF and Aya

## 1.1 What is eBPF?

eBPF (Extended Berkeley Packet Filter) is a technology that allows sandboxed programs to execute within the operating system kernel. It is utilized to safely and efficiently extend the capabilities of the kernel without requiring modifications to kernel source code or the loading of kernel modules.

eBPF programs are event-driven and execute when the kernel or an application passes a specific hook point. Examples of hook points include system calls, function entry and exit points, kernel tracepoints, and network events.

## 1.2 The Role of Rust and Aya

Traditionally, eBPF programs are authored in C and compiled using the Clang/LLVM toolchain. The userspace programs responsible for loading and interacting with them are typically written in C, Go, or Python.

[Aya](https://aya-rs.dev/) is an eBPF library engineered with a focus on developer experience and operability. It facilitates the development of both eBPF programs and userspace applications entirely in Rust. This approach provides memory safety, access to the Cargo package manager, and a unified development ecosystem.

## 1.3 Environment Setup

To develop eBPF programs in Rust, the environment must be configured with the Rust toolchain, a linker (`bpf-linker`), and the Aya project generator (`cargo-generate`).

**Exercise 1.1: Dependency Installation**

Execute the following commands to install the required dependencies:

```bash
# 1. Install the nightly Rust toolchain (required for compiling eBPF)
rustup toolchain install nightly --component rust-src

# 2. Install bpf-linker
cargo install bpf-linker

# 3. Install cargo-generate
cargo install cargo-generate
```

## 1.4 Project Initialization

Once the environment is prepared, the project structure can be generated using Aya templates.

**Exercise 1.2: Generating the Aya Project**

Execute the following command within the workspace directory:

```bash
cargo generate -n my_ebpf_agent -d program_type=kprobe https://github.com/aya-rs/aya-template
```

This command generates a new directory named `my_ebpf_agent` containing two sub-projects:
1. `my_ebpf_agent`: The userspace program responsible for loading the eBPF code into the kernel.
2. `my_ebpf_agent-ebpf`: The eBPF code intended to run within the kernel space.

Review the generated file structure to understand the separation between userspace and kernel space components.
