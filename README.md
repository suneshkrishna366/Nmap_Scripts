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
