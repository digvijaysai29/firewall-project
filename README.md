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

Step-by-Step Installation
Clone this repository:
bash
git clone https://github.com/yourusername/firewall-project.git

Navigate into the project directory:
bash
cd firewall-project

Install the required dependencies:
bash
pip install -r requirements.txt

Ensure that you have root privileges to run the firewall (required for packet sniffing).
Usage
Running the Firewall
To start the firewall, run the following command with root privileges:
bash
sudo python3 firewall/firewall.py

The firewall will start sniffing packets on all available interfaces and apply the rules defined in the rules.json file.
Example Firewall Rule:
To block traffic from a specific IP address, add a rule in firewall/rules/rules.json like this:
json
[
    {
        "ip": "192.168.1.100",
        "action": "block"
    }
]

You can also allow traffic by changing "action": "allow".
Logging:
Blocked and allowed packets are logged in firewall/logs/firewall.log.
Firewall Rules
The firewall rules are stored in a JSON file located in firewall/rules/rules.json. Each rule consists of two fields:
ip: The IP address to block or allow.
action: The action to take (block or allow).
Example:
json
[
    {
        "ip": "192.168.1.100",
        "action": "block"
    },
    {
        "ip": "10.0.0.5",
        "action": "allow"
    }
]

Project Structure
Here’s an overview of the project structure:
text
firewall-project/
│
├── firewall/
│   ├── firewall.py          # Main script that runs the firewall and sniffs packets.
│   ├── rule_manager.py      # Script to manage adding/removing rules.
│   ├── logs/                # Directory to store log files.
│   │   └── firewall.log     # Log file for blocked/allowed packets.
│   └── rules/               # Directory to store firewall rules.
│       └── rules.json       # JSON file containing IP blocking/allowing rules.
├── .gitignore               # File specifying which files/folders to ignore in Git.
├── README.md                # Documentation file (this file).
└── requirements.txt         # List of dependencies required to run the project (Scapy).

Contributing
Contributions are welcome! If you'd like to contribute, please follow these steps:
Fork this repository.
Create a new branch (git checkout -b feature-name).
Make your changes.
Commit your changes (git commit -m 'Add some feature').
Push to the branch (git push origin feature-name).
Open a pull request.
License
This project is licensed under the MIT License - see the LICENSE file for details.
text
