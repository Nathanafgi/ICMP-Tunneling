# ICMP Tunneling Project
created by Matan Nafgi
This project demonstrates an ICMP tunneling technique, which allows data to be transmitted between two machines by encapsulating it within ICMP echo request and reply packets (commonly used by the ping command).

# Overview
ICMP tunneling is a technique that enables communication between two machines using ICMP (Internet Control Message Protocol) packets. This project contains two Python scripts:
Sender: Sends payload data embedded in ICMP echo requests(dedicated for bash commands).
Receiver: Listens for ICMP echo requests and extracts the payload from the packets, executes the command and sends back the output(if there is out put).
This method of tunneling can be used for stealth communication since ICMP packets are typically allowed through most firewalls and routers.

# Features
Implements an ICMP-based tunnel for communication between two machines.
Works on Linux-based systems using Python and the scapy library.
Scripts for both sending and receiving ICMP packets.
Allows data transmission hidden within legitimate-looking ICMP traffic.
# Requirements:
Python 3.x
scapy library (for packet manipulation)
Root privileges (required for sending raw ICMP packets)

# Setup
Clone the repository:
```
git clone https://github.com/Nathanafgi/ICMP-Tunneling.git
```
You can install the required library using pip:
```
pip install scapy
```
Ensure you have root access, as sending raw ICMP packets typically requires elevated privileges.

# Usage
Sender:
The sender script sends ICMP packets with a data payload to the receiver.

Command:
```
sudo python sender.py <target_ip> <data_to_send>
```
#Receiver
The receiver script listens for incoming ICMP packets and extracts the payload.
Command:
```
sudo python receiver.py
```
sidenote: I recommend running the receiver script before the sender script in order to avoid system errors
After running the receiver script, it will listen for ICMP packets and display the extracted data.

# Contributing
If you'd like to contribute to this project, feel free to fork the repository and submit a pull request with your changes.

Fork the repository
Create a new branch (git checkout -b feature-branch)
Make your changes
Commit your changes (git commit -m "Added new feature")
Push to the branch (git push origin feature-branch)
Create a pull request
License
This project is licensed under the MIT License - see the LICENSE file for details.



