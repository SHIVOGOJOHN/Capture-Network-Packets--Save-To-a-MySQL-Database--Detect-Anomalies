import threading
from scapy.all import sniff, Ether, IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
import mysql.connector
plt.switch_backend('Agg')  # Switch to the non-interactive 'Agg' backend

connection=mysql.connector.connect(
    charset="utf8mb4",
    connection_timeout=10,
    database="###",
    host="mysql-f3601b9-jonesjorney-bd4e.f.aivencloud.com",
    password="###",
    port=21038,
    user="###"
)

cursor=connection.cursor()



# Initialize variables
throughput_data = defaultdict(int)
latency_data = {}
packet_counts = defaultdict(int)
unique_addresses = set()
average_packet_size = []
throughput_history = defaultdict(list)
latency_interval = 10  # seconds for latency display
stop_event = threading.Event()  # Event to signal threads to stop
all_latencies = []  # This list will store all latency values
unique_ips = set()  # Track unique IP addresses
protocol_latencies = defaultdict(list)  # Store latencies per protocol
interval=10


#1. LOGGING SYSTEM / PACKET CAPTURE AND PARSING

# Callback function to process each packet and log the extracted details
def packet_callbacks(packet):
    global latency_data
    # Open the log file in append mode
    # This ensures each new packet’s data is added to the file without overwriting the existing entries.
    #  Timestamp helps track when each packet was captured.
    with open("network_events.log", "a") as logfile:
        timestamp = datetime.now()  # Use the current timestamp
        size = len(packet)
        average_packet_size.append(size)
        protocol=src=dest=flags=None
        protocols=[]

        
        # Extract and log Ethernet layer details
        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dest_mac = packet[Ether].dst
            size = len(packet)
            protocol = "Ethernet"
            protocols.append("Ethernet")
            logfile.write(f"{timestamp} {protocol} {src_mac} {dest_mac} {size} bytes\n")
            unique_addresses.update([src_mac, dest_mac])
            update_event_data(protocol, size)  # Update throughput data
            packet_counts["Ethernet"] += 1  # Update packet count for Ethernet
            save_to_database(timestamp, protocol, src_mac, dest_mac, size, None)


        # Extract and log IP layer details
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            protocol = "IP"
            protocols.append("IP")
            logfile.write(f"{timestamp} {protocol} {src_ip} {dest_ip} {size} bytes\n")
            update_event_data(protocol, size)
            packet_counts["IP"] += 1  # Update packet count for IP
            unique_ips.update([src_ip, dest_ip])  # Track unique IPs
            track_latency(src_ip, dest_ip, timestamp, protocol)
            save_to_database(timestamp, protocol, src_ip, dest_ip, size, None)

        # Extract and log TCP layer details
        if packet.haslayer(TCP):
            if 'src_ip' in locals() and 'dest_ip' in locals():
                src_port = packet[TCP].sport
                dest_port = packet[TCP].dport
                flags = str(packet[TCP].flags)
                protocol = "TCP"
                protocols.append("TCP")
                logfile.write(f"{timestamp} {protocol} {src_ip}:{src_port} {dest_ip}:{dest_port} Flags: {flags} {size} bytes\n")
                update_event_data(protocol, size)
                packet_counts["TCP"] += 1  # Update packet count for TCP
                track_latency(src_ip, dest_ip, timestamp, protocol) 
                save_to_database(timestamp, protocol, f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}", size, flags)
                
        # Extract and log UDP layer details
        if packet.haslayer(UDP):
            if 'src_ip' in locals() and 'dest_ip' in locals():
                src_port = packet[UDP].sport
                dest_port = packet[UDP].dport
                protocol = "UDP"
                protocols.append("UDP")
                logfile.write(f"{timestamp} {protocol} {src_ip}:{src_port} {dest_ip}:{dest_port} {size} bytes\n")
                update_event_data(protocol, size)
                packet_counts["UDP"] += 1  # Update packet count for UDP
                track_latency(src_ip, dest_ip, timestamp, protocol)
                save_to_database(timestamp, protocol, f"{src_ip}:{src_port}", f"{dest_ip}:{dest_port}", size, None)

#save to database
def save_to_database(timestamp, protocol, src, dest, size, flags):
    """Save individual protocol information to the database."""
    query = """
        INSERT INTO events (timestamp, protocol, src, dest, size, flags)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    values = (timestamp, protocol, src, dest, size, flags)
    try:
        cursor.execute(query, values)
        connection.commit()
    except mysql.connector.errors.Error as err:
        print(f"Database Error: {err}")



# 3. THROUGHPUT CALCULATION

throughput_data = defaultdict(int)  #used to store throughput values for different network protocols

#update the throughput_data dictionary with the data size for each protocol.
def update_event_data(protocol, size):
    throughput_data[protocol] += size #increments the byte count in throughput_data for the specified protocol.


#calculate and displays the throughput in bits per second (bps) for each protocol every specified interval (default is 10 seconds).
def calculate_throughput(interval=10):
    while True:
        threading.Event().wait(interval)
        timestamp = datetime.now().strftime("%H:%M:%S")  # For plotting over time
        print("\n--- Throughput (bps) ---")
        
        # Calculate throughput for each protocol
        for protocol, bytes_count in list(throughput_data.items()):
            # Skip if no bytes have been recorded for this protocol in the interval
            if bytes_count == 0:
                continue
            
            throughput_bps = (bytes_count * 8) / interval
            print(f"{protocol}: {throughput_bps:.2f} bps")

            # Store throughput data for plotting
            throughput_history[protocol].append((timestamp, throughput_bps))

            # Reset counter for the next interval
            throughput_data[protocol] = 0


# 4. LATENCY MEASUREMENT

# Function to track latency
def track_latency(src_ip, dest_ip, timestamp, protocol):
    conn_key = (src_ip, dest_ip, protocol)
    if conn_key not in latency_data:
        # Mark the beginning of a new connection
        latency_data[conn_key] = {"start": timestamp}
    else:
    
    # Calculate latency if end timestamp is available
        latency_data[conn_key]["end"] = timestamp
        latency = (latency_data[conn_key]["end"] - latency_data[conn_key]["start"]).total_seconds() * 1000  # ms
        protocol_latencies[protocol].append(latency)  # Store latency by protocol
        all_latencies.append(latency)  # Store in global list for final statistics
        del latency_data[conn_key]  # Remove the connection entry after calculation

def calculate_latency(latency_interval=10):
    while not stop_event.is_set():
        stop_event.wait(latency_interval)
        if stop_event.is_set():
            break

        # Display protocol-specific average latencies
        for protocol, latencies in protocol_latencies.items():
            avg_protocol_latency = sum(latencies) / len(latencies) if latencies else 0
            print(f"\n--- Latency for {protocol} ---")
            print(f"Average Latency: {avg_protocol_latency:.2f} ms")
            # Clear latencies for next interval
            protocol_latencies[protocol].clear()

        # Calculate and display overall average latency
        total_latency = sum(all_latencies)
        count = len(all_latencies)
        overall_avg_latency = total_latency / count if count > 0 else 0
        print("\n--- Overall Latency ---")
        print(f"Average Latency across all protocols: {overall_avg_latency:.2f} ms")


# 5. NETWORK METRICS CALCULATION / REAL-TIME STATISTICS DISPLAY AND ANALYSIS

# Initialize variables to track metrics
new_connections_count = 0
connection_history = []  # Store timestamps of new connections

# Function to track new connections and update metrics
def track_new_connection(src_ip, dest_ip, timestamp):
    global new_connections_count
    conn_key = (src_ip, dest_ip)
    if conn_key not in latency_data:
        latency_data[conn_key] = {"start": timestamp}
        new_connections_count += 1
        connection_history.append(timestamp) #store timestamp 
    else:
        latency_data[conn_key]["end"] = timestamp


# Real-time statistics display every 30 seconds and network metrics display
def display_real_time_stats():
    while not stop_event.is_set():
        stop_event.wait(30)  # Display stats every 30 seconds
        if stop_event.is_set():
            break
        avg_packet_size = sum(average_packet_size) / len(average_packet_size) if average_packet_size else 0

        avg_packet_size_per = {protocol: throughput_data[protocol] / packet_counts[protocol]
                           for protocol in packet_counts if packet_counts[protocol] > 0}
        new_connection_rate = calculate_new_connection_rate()
        print("\n---------- Network Metrics --------------")
       
        #Network Metrics
        print(f"Average Packet Size: {avg_packet_size:.2f} bytes")
        print(f"Packets per Protocol: {dict(packet_counts)}")
        print(f"Rate Of New Connections: {new_connection_rate:.2f} connections/second")

        #Real-time Statistics
        print("\n----------- Real-Time Statistics ----------")
        print("Connections per Protocol:", dict(packet_counts))
        print("Average Packet Size per Protocol:", {k: f"{v:.2f} bytes" for k, v in avg_packet_size_per.items()})
        print(f"Unique MAC Addresses: {len(unique_addresses)}")
        print(f"Unique IPs: {len(unique_ips)}")

#Calculate the rate of new connections over time(Network Metrics)
def calculate_new_connection_rate():
    current_time = datetime.now()
    recent_connections = [t for t in connection_history if (current_time - t).total_seconds() <= 30]
    return len(recent_connections) / 30  # connections per second



# 8. VISUALIZATIONS(plot and save as .png no display)

# Throughput for each protocol over time(line plot)
def plot_throughput():
    if not throughput_history:
        print("No throughput data to plot.") #Debugging 
        return
    plt.figure(figsize=(12, 6))
    for protocol, data in throughput_history.items():
        if data:
            times, throughput_values = zip(*data)
            plt.plot(times, throughput_values, label=f"{protocol} Throughput (bps)")
    plt.xlabel("Time")
    plt.ylabel("Throughput (bps)")
    plt.title("Network Throughput Over Time")
    if len(throughput_history) > 0:
        plt.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("throughput_over_times.png")
    plt.close()

# Latency Distribution across all connections
def plot_latency_distribution():
    if not all_latencies:
        print("No latency data to plot.")
        return
    plt.hist(all_latencies, bins=20, color='blue', alpha=0.7)
    plt.xlabel("Latency (ms)")
    plt.ylabel("Frequency")
    plt.title("Latency Distribution")
    plt.savefig("latency_distribution.png")
    plt.close()

# Number Of packets per protocol
def plot_protocol_usage():
    if not packet_counts:
        print("No packet count data to plot.") # Debug
        return
    protocols, counts = zip(*packet_counts.items())
    plt.bar(protocols, counts, color='green', alpha=0.7)
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.title("Protocol Usage")
    plt.savefig("protocol_usages.png")
    plt.close()


# 9. MAIN FUNCTION WITH GRACEFUL TERMINATION(ctrl + c)
if __name__ == "__main__":
    
    try:
        # Start the threads for each function
        throughput_thread = threading.Thread(target=calculate_throughput, args=(interval,), daemon=True)
        throughput_thread.start()

        stats_thread = threading.Thread(target=display_real_time_stats, daemon=True)
        stats_thread.start()

        latency_thread = threading.Thread(target=calculate_latency, args=(latency_interval,), daemon=True)
        latency_thread.start()

        # Run sniff in the main thread
        print("Starting packet sniffing... Press Ctrl+C to stop.")
        sniff(prn=packet_callbacks, store=0, stop_filter=lambda x: stop_event.is_set())

    except KeyboardInterrupt:
        # Trigger stop event to terminate all threads
        print("\nGracefully terminating...")
        stop_event.set()
        cursor.close()
        connection.close()
    
    # Save the plots
    plot_throughput()
    plot_latency_distribution()
    plot_protocol_usage()

    # Display Final Statistics
    avg_packet_size_val = sum(average_packet_size) / len(average_packet_size) if average_packet_size else 0
    print(f"\n---------Final Statistics------------")
    print(f"Total Connections: {len(latency_data)}")
    print(f"Unique Addresses: {len(unique_addresses)}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"Average Packet Size: {avg_packet_size_val:.2f} bytes")
