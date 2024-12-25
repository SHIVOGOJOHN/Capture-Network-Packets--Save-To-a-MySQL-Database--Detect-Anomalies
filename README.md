## 💡 Overview
-In this project we use the **scapy** python library to capture network packets and analyze them at different layers(*Ethernet*, *IP*, *TCP* and *UDP*).

-This project aims to create a system that captures network packets, logs relevant information, save the information to a MySQL database and calculates important
network metrics such as throughput, latency, protocol usage and also tracks unique IP addresses and MAC addresses, and visualizes this data in graphs to aid in the analysis.

-The network information saved to the database shall be used to detect anomalies in the network using the **Isolation Forest** algorithm.

## 💡 Resources
**System Code**
Includes; packet capture and parsing, Logging system, Throughput and Latency calculation, Network Metrics calculation, Real-Time Statistics display and analysis, Visualization and Graceful Termination

**Anomaly Detection Notebook**
Data is fetched from a MySQL database and the Isolation forest algorithm is used to detect anomalies. The model uses **Ppacket size** (normalized) and encoded versions of **protocol** and **flags** for detecting anomalies in network traffic data.

**Sample Logfile**

