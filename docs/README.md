# Building a Next-Generation eBPF Agent in Rust

This book provides a comprehensive, step-by-step guide to mastering eBPF using the Rust programming language. It covers the fundamentals of eBPF development, culminating in the construction of a sophisticated agent capable of high-performance networking, deep observability, and security enforcement—similar in architecture to projects like Cilium.

The curriculum utilizes the [Aya](https://aya-rs.dev/) framework, which enables developers to write both eBPF programs and the userspace control plane entirely in safe Rust.

## Table of Contents

- [Chapter 1: Getting Started with eBPF and Aya](./chapter_01_getting_started.md)
- [Chapter 2: Your First eBPF Program - Kprobes and Tracing](./chapter_02_kprobes.md)
- [Chapter 3: High-Performance Networking with XDP (eXpress Data Path)](./chapter_03_xdp_networking.md)
- [Chapter 4: Traffic Control (TC) and Network Manipulation](./chapter_04_traffic_control.md)
- [Chapter 5: Advanced Observability with Tracepoints and Uprobes](./chapter_05_observability.md)
- [Chapter 6: eBPF Maps - Storing and Sharing State](./chapter_06_ebpf_maps.md)
- [Chapter 7: Security Observability - Catching Malicious Activity](./chapter_07_security_observability.md)
- [Chapter 8: Capstone Project - The Mini-Cilium Agent](./chapter_08_capstone.md)
