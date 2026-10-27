# Cloud Architecture Best-Practice & Security Auditor

A lightweight Python tool that evaluates cloud infrastructure configurations against AWS security guardrails and operational excellence standards. It inspects security groups, storage encryption, and resource lifecycles.

## Scanned Misconfigurations
- **Overly Permissive Security Groups:** Flags instances where administrative ports (SSH port 22 or RDP port 3389) are open to the entire internet (`0.0.0.0/0`).
- **Unencrypted EBS Volumes:** Identifies data-at-rest compliance gaps where storage volumes lack encryption.
- **Orphaned Network Interfaces (ENIs):** Detects unattached network interfaces left behind after instance termination.

## Quick Start Guide

1. **Install Python Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the Security Audit:**
   ```bash
   python auditor.py configs/infrastructure.json
   ```
3. **Filter by Severity:**
   ```bash
   python auditor.py configs/infrastructure.json --severity HIGH
   ```
