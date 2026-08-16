# xdp_fw — High-Performance XDP Firewall

> A high-performance Linux network firewall built with eBPF / XDP, providing L3/L4 stateful traffic filtering, L7 DPI, rate limiting, and real-time telemetry.

**Language:** C / eBPF
**Technology:** Linux eBPF, XDP, TC, libbpf
**Status:** Public Portfolio Version
**Last Updated:** 2026-06-07

> **Note:** This repository is a public portfolio version of the project. Some implementation details and environment-specific configurations have been omitted to protect security and confidentiality.

---

## Project Overview

`xdp_fw` is a high-performance Linux network firewall that performs packet inspection and traffic control at the XDP hook, before packets enter the traditional Linux networking stack.

The project focuses on building an eBPF-based dataplane capable of performing packet filtering, state tracking, rate limiting, DPI inspection, and event telemetry with minimal processing overhead.

The architecture is inspired by modern eBPF-based network security dataplanes.

### Core Capabilities

* **L3/L4 Flow Tracking**

  * Stateful five-tuple connection tracking
  * TCP connection state management
  * Fast-path packet processing

* **L7 DPI**

  * TLS ClientHello inspection
  * Application-level traffic identification
  * DPI state management

* **Stateful Firewall Engine**

  * Conntrack-based stateful filtering
  * Fast-path processing for established flows
  * Dynamic policy management

* **Token Bucket Rate Limiting**

  * Multi-level token bucket design
  * Traffic rate control
  * Burst handling

* **Event Telemetry Pipeline**

  * Kernel-to-userspace event delivery
  * Network event reporting
  * L7 event reporting
  * Monitoring integration

---

# Architecture

The system consists of two BPF programs and one userspace control program.

| Component         | Description                                                                                                             |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `xdp_fw.c`        | XDP ingress firewall and packet processing pipeline                                                                     |
| `trace_connect.c` | TC egress connection tracking and tracepoint-based state synchronization                                                |
| `main.c`          | Userspace control plane for loading BPF programs, managing maps, applying policies, and providing monitoring interfaces |

### High-Level Data Flow

```text
                    Network Interface
                           │
                           ▼
                    ┌─────────────┐
                    │     XDP     │
                    └──────┬──────┘
                           │
                           ▼
                ┌────────────────────┐
                │ Packet Inspection  │
                │                    │
                │ L3 / L4 Parsing    │
                │ Flow Tracking      │
                │ Conntrack          │
                │ Rate Limiting      │
                │ DPI                │
                │ Security Policy    │
                └─────────┬──────────┘
                          │
             ┌────────────┴────────────┐
             │                         │
             ▼                         ▼
        DROP / PASS              Event Telemetry
                                       │
                                       ▼
                                Userspace Control
                                       │
                                       ▼
                              Metrics / Monitoring
```

---

# BPF Program Architecture

```text
types.h
   │
   └── Shared data structures
       between Kernel and Userspace
             │
             ▼
          maps.h
             │
             ├── Policy / Rate Limiting
             │
             ├── Conntrack
             │
             ├── DPI State
             │
             ├── Circuit Breaker
             │
             └── SYN Cookie
                    │
                    ▼
                xdp_fw.c
              XDP Ingress
                    │
                    └──────────────┐
                                   │
events.h                           │
   │                               │
   └── Event generation            │
       and telemetry               │
                                   │
                                   ▼
                           trace_connect.c
                              TC Egress
                                   │
                                   ▼
                             main.c
                         Userspace Control
```

---

# Packet Processing Pipeline

The XDP dataplane performs multiple processing stages before deciding whether a packet should be accepted or dropped.

Typical processing includes:

```text
Packet
  │
  ▼
Ethernet Parsing
  │
  ▼
IPv4 / IPv6 Parsing
  │
  ▼
TCP / UDP Parsing
  │
  ▼
Flow Lookup
  │
  ├── Existing Flow ──► Fast Path
  │
  └── New Flow
          │
          ▼
     Security Policy
          │
          ▼
     Rate Limiting
          │
          ▼
       DPI / L7
          │
          ▼
      Final Action
      ┌───┴────┐
      ▼        ▼
    PASS      DROP
```

---

# BPF Maps

The project uses BPF Maps as the primary state-sharing mechanism between kernel-space BPF programs and the userspace control plane.

Major state categories include:

* Flow / Conntrack state
* Firewall policies
* Rate-limiting state
* DPI state
* Security counters
* Event buffers
* Circuit-breaker state
* SYN Cookie state

The core structures shared between kernel and userspace are defined in `types.h`.

---

# Stateful Firewall

The firewall maintains state for network flows using the standard five-tuple:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol
```

This allows established connections to take a fast processing path while new connections undergo additional policy and inspection.

```text
New Flow
   │
   ▼
Policy Check
   │
   ▼
Conntrack Creation
   │
   ▼
DPI / Rate Limit
   │
   ▼
Established Flow
   │
   ▼
Fast Path
```

---

# L7 DPI

The project provides L7 inspection for TLS traffic by inspecting the TLS ClientHello message.

The DPI pipeline maintains protocol state to avoid repeatedly parsing the same flow.

```text
TCP Flow
   │
   ▼
TLS Detection
   │
   ▼
ClientHello
   │
   ▼
Protocol / Metadata Extraction
   │
   ▼
DPI State Update
   │
   ▼
Security Decision / Telemetry
```

Environment-specific DPI configurations and deployment details are intentionally omitted from the public version.

---

# Rate Limiting

The firewall implements token-bucket based traffic control.

The design supports multiple levels of rate limiting so that traffic can be controlled at different scopes.

```text
Global Limit
     │
     ▼
Interface / Policy Limit
     │
     ▼
Flow Limit
     │
     ▼
Packet Decision
```

The token bucket mechanism provides support for:

* Configurable rate
* Burst capacity
* Token refill
* Per-flow or policy-based limits
* Fast-path enforcement inside XDP

---

# Event Telemetry

Kernel-space events are exported to userspace through the event pipeline.

The telemetry subsystem provides different event categories, including:

* Network security events
* Flow events
* L7 / DPI events
* Rate-limit events
* Firewall decisions

Conceptually:

```text
BPF Program
    │
    ▼
Event Generation
    │
    ▼
BPF Event Buffer
    │
    ▼
Userspace
    │
    ├── Dashboard
    ├── Metrics
    └── Monitoring
```

---

# Userspace Control Plane

`main.c` provides the userspace control plane.

Responsibilities include:

* Loading BPF programs
* Initializing BPF Maps
* Sharing state between BPF components
* Updating firewall policies
* Managing runtime configuration
* Receiving kernel events
* Providing runtime monitoring
* Controlling firewall behavior

The userspace component acts as the control plane while the XDP programs perform the dataplane processing.

```text
             Control Plane
          ┌─────────────────┐
          │    main.c       │
          │                 │
          │ Policy Control  │
          │ Map Management  │
          │ Event Handling  │
          │ Monitoring      │
          └────────┬────────┘
                   │
                   │ BPF Maps / Events
                   │
          ┌────────▼────────┐
          │    Dataplane    │
          │                 │
          │    XDP / TC     │
          └─────────────────┘
```

---

# Monitoring

The project includes a monitoring pipeline based on Prometheus and Grafana.

The architecture is:

```text
XDP / TC
   │
   ▼
Userspace Statistics
   │
   ▼
Metric Exporter
   │
   ▼
Prometheus
   │
   ▼
Grafana
```

The monitoring layer is used to observe:

* Packet processing statistics
* Flow counts
* Firewall decisions
* Rate-limiting activity
* DPI events
* System-level metrics

Environment-specific monitoring configurations are not included in the public repository.

---

# Project Structure

```text
xdp_fw/
│
├── xdp_fw.c
│       └── XDP ingress firewall
│
├── trace_connect.c
│       └── TC egress / tracepoint connection tracking
│
├── main.c
│       └── Userspace control plane
│
├── types.h
│       └── Shared kernel/userspace data structures
│
├── maps.h
│       └── BPF Map definitions
│
├── policy.h
│       └── Firewall / rate-limit / conntrack logic
│
├── events.h
│       └── Event generation and telemetry
│
├── docs/
│   ├── architecture.md
│   ├── dataplane.md
│   ├── maps.md
│   ├── dpi.md
│   ├── userspace.md
│   ├── deployment.md
│   ├── exporter.md
│   ├── monitoring.md
│   └── roadmap.md
│
└── Makefile
```

---

# Documentation

Detailed technical documentation is organized under `docs/`.

| Document               | Description                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------- |
| `docs/architecture.md` | Overall architecture, component responsibilities, and design decisions                            |
| `docs/dataplane.md`    | Packet processing pipeline, XDP processing stages, rate limiting, circuit breaker, and SYN Cookie |
| `docs/maps.md`         | BPF Map architecture and shared data structures                                                   |
| `docs/dpi.md`          | Conntrack / DPI architecture, DPI state machine, TLS ClientHello processing                       |
| `docs/userspace.md`    | Userspace control plane, event system, dashboard, and runtime control                             |
| `docs/deployment.md`   | Generic build and deployment requirements                                                         |
| `docs/exporter.md`     | Metrics exporter architecture and Prometheus integration                                          |
| `docs/monitoring.md`   | Prometheus / Grafana monitoring architecture                                                      |
| `docs/roadmap.md`      | Known issues, technical debt, and future improvements                                             |

---

# Build

The project requires a Linux environment with BPF / XDP support.

Generate the kernel BTF header:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Build the project:

```bash
make clean
make DEBUG=1
```

Verify BPF networking attachments:

```bash
sudo bpftool net list
```

The exact build dependencies may vary depending on the Linux distribution and kernel version.

See:

```text
docs/deployment.md
```

for the public deployment documentation.

---

# Dependencies

The project may use the following components depending on the enabled features:

* Linux Kernel
* eBPF / XDP
* libbpf
* bpftool
* LLVM / Clang
* libpcap
* OpenSSL
* nDPI
* jitterentropy
* Boost
* Intel TBB
* Prometheus
* Grafana

Specific dependency versions and environment-specific build configurations are documented separately where applicable.

---

# Security and Public Repository Scope

This repository intentionally does **not** contain:

* Private keys
* API credentials
* Production certificates
* Internal IP addresses
* Internal domain names
* Production infrastructure configuration
* Private deployment information
* Real customer or production traffic data
* Environment-specific secrets

All examples and configurations included in this repository are intended for development, testing, or demonstration purposes.

---

# Technical Highlights

This project demonstrates practical experience with:

* Linux kernel networking
* eBPF / XDP
* TC
* libbpf
* BPF Maps
* Stateful packet processing
* Conntrack
* L3/L4 packet parsing
* L7 DPI
* TLS ClientHello inspection
* Token Bucket rate limiting
* Kernel/userspace communication
* Event-driven telemetry
* Prometheus / Grafana
* High-performance network dataplane design

---

# Roadmap

Potential future improvements include:

* IPv6 feature expansion
* Improved DPI protocol coverage
* More efficient state management
* NUMA-aware optimization
* Multi-queue / RSS optimization
* Advanced observability
* Extended policy management
* Additional XDP offload support
* Performance benchmarking under high packet rates

---

## Portfolio Notice

This repository is maintained as a public technical portfolio to demonstrate the architecture, implementation approach, and engineering concepts used in the project.

Some implementation details and environment-specific configurations have been omitted to protect security and confidentiality.
