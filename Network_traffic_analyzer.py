import sys
import logging
from scapy.all import *
import pandas as pd
from tabulate import tabulate
from tqdm import tqdm
import matplotlib.pyplot as plt
import numpy as np

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# 📌 Provide the PCAP file path here
PCAP_FILE_PATH = r"C:\Users\91836\Downloads\Network_traffic_analyzer-main\Network_traffic_analyzer-main\cature.pcapng"  # <-- Fixed path
PORT_SCAN_THRESHOLD = 100  # Set threshold value

def read_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except Scapy_Exception as e:
        logger.error(f"Error reading PCAP file: {e}")
        sys.exit(1)
    return packets

def extract_packet_data(packets):
    packet_data = []
    for packet in tqdm(packets, desc="Processing packets", unit="packet"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            size = len(packet)
            dst_port = None  # Initialize as None
            
            # Extract destination port if available
            if TCP in packet:
                dst_port = packet[TCP].dport
            elif UDP in packet:
                dst_port = packet[UDP].dport

            packet_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "size": size,
                "dst_port": dst_port  # Include port, even if None
            })
    
    return pd.DataFrame(packet_data)

def protocol_name(number):
    protocol_dict = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    return protocol_dict.get(number, f"Unknown({number})")

def analyze_packet_data(df):
    total_bandwidth = df["size"].sum()
    protocol_counts = df["protocol"].value_counts(normalize=True) * 100
    protocol_counts.index = protocol_counts.index.map(protocol_name)
    
    ip_communication = df.groupby(["src_ip", "dst_ip"]).size().sort_values(ascending=False)
    ip_communication_percentage = ip_communication / ip_communication.sum() * 100
    ip_communication_table = pd.concat([ip_communication, ip_communication_percentage], axis=1).reset_index()
    
    protocol_frequency = df["protocol"].value_counts()
    protocol_frequency.index = protocol_frequency.index.map(protocol_name)
    
    protocol_counts_df = pd.concat([protocol_frequency, protocol_counts], axis=1).reset_index()
    protocol_counts_df.columns = ["Protocol", "Count", "Percentage"]
    
    return total_bandwidth, protocol_counts_df, ip_communication_table, protocol_frequency

def detect_port_scanning(df, threshold):
    # Remove rows where dst_port is NaN (i.e., not TCP/UDP)
    df = df.dropna(subset=["dst_port"])

    # Convert dst_port to int (Scapy may store it as float if NaN values exist)
    df["dst_port"] = df["dst_port"].astype(int)

    port_scan_df = df.groupby(['src_ip', 'dst_port']).size().reset_index(name='count')
    unique_ports_per_ip = port_scan_df.groupby('src_ip').size().reset_index(name='unique_ports')
    potential_port_scanners = unique_ports_per_ip[unique_ports_per_ip['unique_ports'] >= threshold]
    
    ip_addresses = potential_port_scanners['src_ip'].unique()
    if len(ip_addresses) > 0:
        logger.warning(f"Potential port scanning detected from IP addresses: {', '.join(ip_addresses)}")

def print_results(total_bandwidth, protocol_counts_df, ip_communication_table):
    logger.info(f"Total bandwidth used: {total_bandwidth / 1e6:.2f} Mbps")
    logger.info("\nProtocol Distribution:\n")
    logger.info(tabulate(protocol_counts_df, headers=["Protocol", "Count", "Percentage"], tablefmt="grid"))
    logger.info("\nTop IP Address Communications:\n")
    logger.info(tabulate(ip_communication_table, headers=["Source IP", "Destination IP", "Count", "Percentage"], tablefmt="grid", floatfmt=".2f"))

def save_results_to_csv(df, filename):
    df.to_csv(filename, index=False)
    logger.info(f"Results saved to {filename}")

def main():
    packets = read_pcap(PCAP_FILE_PATH)  # <-- Directly using the PCAP file path
    df = extract_packet_data(packets)
    total_bandwidth, protocol_counts, ip_communication_table, protocol_frequency = analyze_packet_data(df)
    print_results(total_bandwidth, protocol_counts, ip_communication_table)
    
    security_df = df.copy()
    detect_port_scanning(security_df, PORT_SCAN_THRESHOLD)
    save_results_to_csv(df, "network_analysis.csv")

if __name__ == "__main__":
    main()
