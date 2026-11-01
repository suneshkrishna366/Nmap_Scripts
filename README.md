# Nmap Scripts

A collection of custom Nmap Scripting Engine (NSE) scripts developed to inspect network protocols and report protocol-level information.

## Scripts

### 1. NetSentinel MQTT Protocol Scanner

- Uses Nmap's MQTT library to connect to an MQTT broker.
- Examines the broker's connection response.
- Reports connection acceptance and session information.

### 2. NetSentinel SSH Algorithm Scanner

- Uses Nmap's SSH library to inspect advertised cryptographic algorithms.
- Collects key-exchange, host-key, encryption, MAC, and compression algorithms.
- Groups selected algorithms using custom classification rules.

## Requirements

- Nmap with the required NSE libraries.
- An authorized test environment.
- An MQTT broker or SSH server for testing the corresponding script.

## Usage

```bash
sudo nmap --script ./netsentinel-mqtt-v3.nse -p 1883 TARGET
sudo nmap --script ./ssh_scan.nse -p 22 TARGET
```

Replace `TARGET` with a system you own or have permission to test.

## Limitations

These scripts provide protocol information and basic algorithm classification. Their output should not be treated as proof that a target is secure or vulnerable.

## Author

Sunesh Krishna

# Original Nmap Reference Scripts

This directory contains the original Nmap NSE scripts used as reference implementations for the NetSentinel project.

The scripts are obtained from the official Nmap GitHub repository and are included for educational, research, and comparison purposes.

## Reference Scripts

### 1. MQTT Subscribe Script
- **Filename:** `mqtt-subscribe.nse`
- **Source:** https://github.com/nmap/nmap/blob/master/scripts/mqtt-subscribe.nse
- **Purpose:** Connects to MQTT brokers and retrieves published messages through topic subscriptions.

### 2. SSH Algorithm Enumeration Script
- **Filename:** `ssh2-enum-algos.nse`
- **Source:** https://github.com/nmap/nmap/blob/master/scripts/ssh2-enum-algos.nse
- **Purpose:** Identifies the cryptographic algorithms supported by SSH servers.

## Attribution

The original scripts are developed and maintained by the Nmap Project.

Official Repository: https://github.com/nmap/nmap

Official Website: https://nmap.org/

The original source code and applicable copyright and licensing notices are retained. The scripts in this directory are not modified versions of the enhanced NetSentinel implementations.

The enhanced scripts developed for this project are maintained separately in the main repository.

**Project:** NetSentinel – Nmap NSE Script Enhancements  
**Author:** Sunesh Krishna N
