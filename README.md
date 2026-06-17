# Python-Intrusion-Detection-System-In-Progress-
About A Python-based intrusion detection system that monitors network traffic and detects suspicious activity in real time.

## Features

* Detects packet floods and DDoS spikes
* Identifies port scans and suspicious port access
* Detects brute force attempts
* Monitors SYN flood attacks
* Detects ARP spoofing
* Logs alerts and summaries

## How It Works

The program captures live network packets and analyzes them using simple rule-based detection.
When suspicious behavior is detected, it generates alerts and logs the activity.

## Requirements

* Python 3
* pyshark

Install dependencies:

```bash
pip install pyshark
```

## Usage

Run the program:

```bash
python main.py
```

Make sure your network interface is set correctly in `packet_capture.py`.

## Notes

* This is an educational project and is still in progress
* Detection is rule-based and may produce false positives
* Logs are saved locally and should not be uploaded to GitHub

## Future Improvements

* Configurable thresholds
* Expanded detection for additional attack types
* GUI dashboard
* Machine learning-based detection
* Support for multiple network interfaces
