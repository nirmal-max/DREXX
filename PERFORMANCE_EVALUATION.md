# DREXX Performance Evaluation & Empirical Benchmark Report

**Application**: DREX v1.0.0  
**Architecture**: Unified Sanitization + Recovery Platform  
**Environment**: Windows 11 AMD64 / Python 3.14  
**Date**: 2026-09-11 08:50:41Z  

---

## 1. Executive Summary

This empirical performance evaluation documents the measured throughput, latency, memory utilization, and computational efficiency across the core sanitization and recovery engines in the DREXX platform.

---

## 2. Module 1 & 2: Data Sanitization Throughput

| Method ID | Method Name | Data Size | Elapsed Time | Throughput | Verification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `zero` | Single-Pass Zero Overwrite | 16 MB | 0.2794 s | **57.26 MB/s** | Post-Wipe Pattern Verification |
| `csprng` | Cryptographic PRNG Stream | 16 MB | 0.1232 s | **129.88 MB/s** | Entropy + SHA-256 Check |
| `temporary` | Temp / Cache Deep Scrub | 16 MB | 0.1152 s | **138.94 MB/s** | Secure Inode & Bit Scramble |

---

## 3. Module 3: Advanced Carving, Reconstruction & Imaging Performance

| Engine | Operation | Dataset Size | Elapsed Time | Measured Throughput | Result State |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FragmentReconstructor** | Multi-Fragment Stream Reassembly | 0.84 MB | 0.0022 s | **382.09 MB/s** | 0 Candidates Reassembled |
| **VirtualRaidReconstructor** | RAID 5 (Degraded 1-Disk Missing XOR Parity) | 32.0 MB | 3.9916 s | **8.02 MB/s** | Bit-Exact XOR Parity Restored |
| **DirectDamagedMediaImager** | Sector-Level Imaging with Mapfile | 8 MB | 0.9868 s | **8.11 MB/s** | 8,373,248 B Rescued, 15,360 B Bad Mapped |

---

## 4. System Resource Footprint

* **Process Memory (RSS)**: 29.74 MB (Peak Delta: +0.80 MB)
* **CPU Core Utilization**: 14.3% during peak multi-pass operations
* **I/O Safety**: Bounded memory streaming with unbuffered direct chunk I/O prevents memory exhaustion on multi-gigabyte disk targets.
* **Deterministic Verification**: Exact SHA-256 hashing executed at linear disk speeds with incremental buffers.

---

*Report generated automatically from live empirical execution.*
