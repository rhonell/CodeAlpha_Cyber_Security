This project includes a basic packet sniffer written in Python and an intrusion detection system (IDS) configured using Suricata on Arch Linux. The IDS is equipped with custom rules to detect common network threats and suspicious activities.

## 📦 Contents

- Basic Packet Sniffer (Python)
- Suricata IDS Configuration
- Custom Suricata Rules
- Interface Setup
- Testing and Validation

---

## 🐍 Basic Packet Sniffer

A simple packet sniffer using Python and the `scapy` library to capture and print packet details from a network interface.

### Requirements

```bash
pip install scapy

Run Sniffer
sudo python3 sniffer.py

Suricata IDS Setup

Suricata is a high-performance, open-source network IDS, IPS, and network security monitoring (NSM) engine.
📍 Installation (Arch Linux)

sudo pacman -S suricata

🛠 Configuration

    Config file: /etc/suricata/suricata.yaml

    Interface: wlp0s20f3 (replace with yours if different)

Make sure this section is properly configured:

default-rule-path: /etc/suricata/rules

rule-files:
  - local.rules

Run Suricata

sudo suricata -c /etc/suricata/suricata.yaml -i wlp0s20f3

📜 Custom Rules in local.rules

You can define your own rules in /var/lib/suricata/rules/local.rules.
Example Rules

# Alert on ping (ICMP)
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)

# Detect suspicious DNS query
alert udp any any -> any 53 (msg:"Suspicious DNS Query"; content:"example.com"; sid:1000002; rev:1;)

# Alert on HTTP traffic containing 'malware'
alert http any any -> any any (msg:"Potential Malware Detected in HTTP"; content:"malware"; sid:1000003; rev:1;)

# SSH connection detection
alert tcp any any -> any 22 (msg:"SSH Connection Detected"; sid:1000004; rev:1;)

# FTP connection attempt
alert tcp any any -> any 21 (msg:"FTP Connection Attempt"; sid:1000005; rev:1;)

🧪 Testing

You can generate traffic using tools like:

ping 8.8.8.8
curl http://testsite.com/malware
dig example.com

Logs are stored in:

/var/log/suricata/

Check fast.log or eve.json for alerts and packet analysis.
