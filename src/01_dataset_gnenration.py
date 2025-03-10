import pandas as pd
import numpy as np
import random

# Parameters
n_samples_per_class = 1000
attack_types = ["DDoS", "Spoofing", "Phishing", "Normal"]
n_samples = n_samples_per_class * len(attack_types)

# Define feature generation logic for each attack type
def generate_data_for_attack(attack_type, n_samples):
    data = {
        "Device_ID": [f"Device_{random.randint(1, 100)}" for _ in range(n_samples)],  # More devices
        "Packet_Size (bytes)": np.random.randint(64, 1518, n_samples),
        "Latency (ms)": np.random.uniform(1, 500, n_samples).round(2),
        "Throughput (Mbps)": np.random.uniform(0.1, 100, n_samples).round(2),
        "Protocol_Type": np.random.choice(["TCP", "UDP", "ICMP"], n_samples),
        "Source_Port": np.random.randint(1024, 65535, n_samples),
        "Destination_Port": np.random.randint(1, 1024, n_samples),
        "IP_Flag": np.random.choice(["SYN", "ACK", "FIN", "RST", "None"], n_samples),
        "Connection_Duration (ms)": np.random.uniform(10, 10000, n_samples).round(2),
        "Packet_Count": np.random.randint(1, 1000, n_samples),
        "Error_Rate": np.random.uniform(0, 0.1, n_samples).round(4),
        "Fragmentation_Flag": np.random.choice([0, 1], n_samples),
        "Payload_Size (bytes)": np.random.randint(0, 1500, n_samples),
        "Session_Status": np.random.choice(["Established", "Failed", "Pending"], n_samples),
    }

    # Apply specific rules for each attack type
    if attack_type == "DDoS":
        data["Packet_Count"] = np.random.randint(500, 1000, n_samples)
        data["Throughput (Mbps)"] = np.random.uniform(50, 100, n_samples).round(2)
        data["Error_Rate"] = np.random.uniform(0.05, 0.1, n_samples).round(4)
        data["Session_Status"] = np.random.choice(["Failed", "Pending"], n_samples)

    elif attack_type == "Spoofing":
        data["Source_Port"] = np.random.randint(1, 1024, n_samples)
        data["IP_Flag"] = np.random.choice(["RST", "FIN"], n_samples)
        data["Error_Rate"] = np.random.uniform(0.02, 0.08, n_samples).round(4)
        data["Session_Status"] = np.random.choice(["Failed", "Pending"], n_samples)

    elif attack_type == "Phishing":
        data["Packet_Size (bytes)"] = np.random.randint(64, 256, n_samples)
        data["Protocol_Type"] = "TCP"
        data["Error_Rate"] = np.random.uniform(0.01, 0.05, n_samples).round(4)
        data["Session_Status"] = np.random.choice(["Pending", "Failed"], n_samples)

    elif attack_type == "Normal":
        data["Packet_Count"] = np.random.randint(1, 500, n_samples)
        data["Throughput (Mbps)"] = np.random.uniform(0.1, 50, n_samples).round(2)
        data["Error_Rate"] = np.random.uniform(0, 0.02, n_samples).round(4)
        data["Session_Status"] = "Established"

    data["Attack_Type"] = [attack_type] * n_samples
    return pd.DataFrame(data)

# Combine data for all attack types
df_list = [generate_data_for_attack(attack, n_samples_per_class) for attack in attack_types]
df = pd.concat(df_list, ignore_index=True)

df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df.to_csv("balanced_synthetic_network_data.csv", index=False)

print("balanced synthetic dataset created successfully!")

