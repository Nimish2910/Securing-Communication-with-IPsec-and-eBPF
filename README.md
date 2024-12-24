

# Securing Communication with IPsec and eBPF

## Overview

This project demonstrates how to secure communication between two virtual machines (Alice and Bob) using **IPsec** concepts and **eBPF** (extended Berkeley Packet Filter). It ensures confidentiality and integrity of the exchanged messages while protecting against eavesdropping by a third-party (Eve).

The implementation includes:

- **Packet Capture**: Ingress and egress UDP packet handling.
- **Key Exchange**: Secure Diffie-Hellman-based shared key derivation.
- **Encryption/Decryption**: Real-time encryption and decryption of messages.
- **Traffic Analysis**: Insights into message statistics between Alice and Bob.

## Features

1. **Secure Communication**:
   - Capture UDP packets on port `12345`.
   - Encrypt egress messages and decrypt ingress messages using a shared key derived via Diffie-Hellman.

2. **eBPF Integration**:
   - Implement eBPF programs to manage network traffic at the kernel level.
   - Log packet details, including payloads and message statistics, to `trace_pipe`.

3. **Packet Statistics**:
   - Count ingress and egress messages to analyze traffic patterns.

## Setup Instructions

### Prerequisites

- Install required tools:
  ```bash
  sudo apt update && sudo apt install -y clang llvm
  wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
  wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli

Development Environment

Using Multipass (Local Machine)
	1.	Install Multipass: Multipass Installation Guide.
	2.	Launch VMs:

multipass launch 22.04 --name alice --disk 10G --memory 4G --cpus 2
multipass launch 22.04 --name bob --disk 10G --memory 4G --cpus 2


	3.	Retrieve VM IPs:

multipass info



Using vSphere Virtual Machines

Follow the vSphere tutorial to configure and use department-provided VMs as Alice and Bob.

Running the eBPF Program
	1.	Compile the program:

./ecc ingress.c


	2.	Run the program:

sudo ./ecli run package.json


	3.	Observe the output:

sudo -s
echo 1 > /sys/kernel/debug/tracing/tracing_on
sudo cat /sys/kernel/debug/tracing/trace_pipe



Project Components
	1.	Packet Capture:
	•	Modify ingress.c to:
	•	Capture both ingress and egress UDP packets on port 12345.
	•	Log UDP payload content.
	2.	Key Exchange:
	•	Use Diffie-Hellman key exchange with predefined modulus (p = 23) and generator (g = 5).
	•	Derive a shared key between Alice and Bob.
	3.	Encryption and Decryption:
	•	Apply XOR encryption to outgoing messages.
	•	Decrypt incoming messages using the derived shared key.
	4.	Message Statistics:
	•	Count ingress and egress messages and log statistics.

Testing the System
	1.	Simulate Eve listening for messages:

sudo tcpdump -i <Broadcast_Interface> udp port 12345 -A


	2.	Set up communication:
	•	On Alice:

nc -ul 12345


	•	On Bob:

nc -u -p 12345 <Alice_IP> 12345


	3.	Verify encrypted traffic and message logs.

References
	•	eBPF Developer Tutorial
	•	Diffie-Hellman Key Exchange
	•	Multipass Installation Guide
