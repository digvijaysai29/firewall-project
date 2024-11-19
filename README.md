# Python Firewall Project

A simple Python-based firewall that inspects network traffic and blocks specific IP addresses or ports based on predefined rules. This project uses **Scapy** for packet sniffing and filtering.

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Step-by-Step Installation](#step-by-step-installation)
- [Usage](#usage)
  - [Running the Firewall](#running-the-firewall)
  - [Example Firewall Rule](#example-firewall-rule)
  - [Logging](#logging)
- [Firewall Rules](#firewall-rules)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Features
- Sniffs network traffic using Scapy.
- Blocks or allows packets based on predefined IP rules.
- Logs blocked and allowed packets for later analysis.
- Easily configurable rules stored in JSON format.

## Technologies Used
- Python 3.x
- Scapy (for packet sniffing and manipulation)
- PyCharm (for development)

## Installation

### Prerequisites
Ensure you have the following installed:
1. **Python 3.x**: You can download it from [python.org](https://www.python.org/downloads/).
2. **Scapy**: Install it using pip:
   ```bash
   pip install scapy
