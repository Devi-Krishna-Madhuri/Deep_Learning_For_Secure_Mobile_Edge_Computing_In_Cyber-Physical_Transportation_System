import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib

# Load the trained model and scaler
model = load_model("cnn_network_attack_classifier.h5")
scaler = joblib.load("cnn_scaler.pkl")

# Assuming you have label_encoders saved (for categorical features)
label_encoders = joblib.load("cnn_label_encoders.pkl")  # If you saved them earlier

# Attack type mapping (from encoded class values back to original)
attack_type_mapping = {
    0: "DDoS",
    1: "Normal",
    2: "Phishing",
    3: "Spoofing"
}

# Define test input data (user input in a dictionary format)
test_data = [
    {"Device_ID": 35, "Packet_Size (bytes)": 132, "Latency (ms)": 3.81, "Throughput (Mbps)": 53.76,
     "Protocol_Type": "ICMP", "Source_Port": 668, "Destination_Port": 202, "IP_Flag": "RST",
     "Connection_Duration (ms)": 2342.35, "Packet_Count": 781, "Error_Rate": 0.0456, "Fragmentation_Flag": 0,
     "Payload_Size (bytes)": 113, "Session_Status": "Failed"},
    
    {"Device_ID": 43, "Packet_Size (bytes)": 237, "Latency (ms)": 278.44, "Throughput (Mbps)": 25.09,
     "Protocol_Type": "TCP", "Source_Port": 27137, "Destination_Port": 337, "IP_Flag": "ACK",
     "Connection_Duration (ms)": 7520.29, "Packet_Count": 659, "Error_Rate": 0.0108, "Fragmentation_Flag": 0,
     "Payload_Size (bytes)": 1146, "Session_Status": "Pending"},
    
    {"Device_ID": 35, "Packet_Size (bytes)": 213, "Latency (ms)": 329.52, "Throughput (Mbps)": 67.19,
     "Protocol_Type": "TCP", "Source_Port": 28940, "Destination_Port": 566, "IP_Flag": "ACK",
     "Connection_Duration (ms)": 8222.27, "Packet_Count": 486, "Error_Rate": 0.0133, "Fragmentation_Flag": 0,
     "Payload_Size (bytes)": 713, "Session_Status": "Failed"},
    
    {"Device_ID": 47, "Packet_Size (bytes)": 136, "Latency (ms)": 22.19, "Throughput (Mbps)": 44.89,
     "Protocol_Type": "TCP", "Source_Port": 42467, "Destination_Port": 556, "IP_Flag": "ACK",
     "Connection_Duration (ms)": 5681.34, "Packet_Count": 649, "Error_Rate": 0.0347, "Fragmentation_Flag": 1,
     "Payload_Size (bytes)": 1093, "Session_Status": "Failed"},
    
    {"Device_ID": 38, "Packet_Size (bytes)": 1312, "Latency (ms)": 31.78, "Throughput (Mbps)": 49.32,
     "Protocol_Type": "ICMP", "Source_Port": 9834, "Destination_Port": 181, "IP_Flag": "FIN",
     "Connection_Duration (ms)": 5763.6, "Packet_Count": 460, "Error_Rate": 0.0089, "Fragmentation_Flag": 0,
     "Payload_Size (bytes)": 53, "Session_Status": "Established"},
    
    {"Device_ID": 2, "Packet_Size (bytes)": 987, "Latency (ms)": 316.73, "Throughput (Mbps)": 75.37,
     "Protocol_Type": "ICMP", "Source_Port": 58388, "Destination_Port": 13, "IP_Flag": "None",
     "Connection_Duration (ms)": 7859.67, "Packet_Count": 902, "Error_Rate": 0.0612, "Fragmentation_Flag": 0,
     "Payload_Size (bytes)": 277, "Session_Status": "Pending"},
    
    {"Device_ID": 24, "Packet_Size (bytes)": 120, "Latency (ms)": 486.48, "Throughput (Mbps)": 28.84,
     "Protocol_Type": "ICMP", "Source_Port": 10677, "Destination_Port": 336, "IP_Flag": "SYN",
     "Connection_Duration (ms)": 264.5, "Packet_Count": 34, "Error_Rate": 0.0089, "Fragmentation_Flag": 0,
     "Payload_Size (bytes)": 191, "Session_Status": "Established"}
]

# Function to preprocess user input
def preprocess_input(user_input):
    # Convert user input into DataFrame
    df_input = pd.DataFrame(user_input)

    # Encode categorical features
    for col in ["Protocol_Type", "IP_Flag", "Session_Status", "Device_ID"]:
        try:
            # Ensure that only known categories are transformed
            df_input[col] = label_encoders[col].transform(df_input[col])
        except ValueError:
            # If unseen category, assign default value (0)
            df_input[col] = 0

    # Select feature columns (same as in training)
    feature_columns = [
        "Device_ID", "Packet_Size (bytes)", "Latency (ms)", "Throughput (Mbps)",
        "Protocol_Type", "Source_Port", "Destination_Port", "IP_Flag",
        "Connection_Duration (ms)", "Packet_Count", "Error_Rate",
        "Fragmentation_Flag", "Payload_Size (bytes)", "Session_Status"
    ]
    df_input = df_input[feature_columns]

    # Scale numerical features using the pre-trained scaler
    df_input_scaled = scaler.transform(df_input)
    return df_input_scaled

# Iterate through each test sample and make predictions
for sample in test_data:
    processed_input = preprocess_input([sample])
    prediction = model.predict(processed_input)
    predicted_class = np.argmax(prediction, axis=1)[0]
    predicted_attack_type = attack_type_mapping[predicted_class]

    # Output the result
    print(f"Input: {sample}")
    print(f"Predicted Attack Type: {predicted_attack_type}")
    print("-" * 50)
