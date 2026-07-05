# A Beginner's Guide to eBPF in Rust

This tutorial is a humble, step-by-step introduction to learning eBPF using the Rust programming language. It is designed specifically for beginners who want to explore how eBPF works under the hood without getting overwhelmed.

By following this guide, you will learn the basics of eBPF and eventually combine different concepts to build a simple, educational eBPF agent.

All the code and examples are available on GitHub. If you find this guide helpful, feel free to drop a star!
⭐ **[github.com/amghazanfari/ebpf-begginer](https://github.com/amghazanfari/ebpf-begginer)**

We will use the [Aya](https://aya-rs.dev/) framework, which allows us to write both eBPF programs and the userspace applications entirely in Rust.

## Table of Contents

- [Chapter 1: Getting Started with eBPF and Aya](./chapter_01_getting_started.md)
- [Chapter 2: Kprobes and Tracing](./chapter_02_kprobes.md)
- [Chapter 3: Basic Networking with XDP](./chapter_03_xdp_networking.md)
- [Chapter 4: Traffic Control (TC)](./chapter_04_traffic_control.md)
- [Chapter 5: Tracepoints and Uprobes](./chapter_05_observability.md)
- [Chapter 6: eBPF Maps and State](./chapter_06_ebpf_maps.md)
- [Chapter 7: Basic Security and Mitigation](./chapter_07_security_observability.md)
- [Chapter 8: Combining Programs (A Simple Agent)](./chapter_08_capstone.md)
