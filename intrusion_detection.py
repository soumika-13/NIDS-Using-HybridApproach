import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
import re
import streamlit as st
import os
import json

# File to store detected anomalies
STORED_ANOMALIES_FILE = "stored_anomalies.json"

# Load stored anomalies if available
def load_stored_anomalies():
    if os.path.exists(STORED_ANOMALIES_FILE):
        with open(STORED_ANOMALIES_FILE, "r") as file:
            return json.load(file)
    return []

# Save new anomalies to the file
def save_stored_anomalies(stored_anomalies):
    with open(STORED_ANOMALIES_FILE, "w") as file:
        json.dump(stored_anomalies, file, indent=4)

# Load initial anomalies
stored_anomalies = load_stored_anomalies()

# Define signature patterns for detection
SIGNATURES = [
    r'(\bftp\b.*\broot\b)',           # Example: FTP root attempt
    r'(\bhttp\b.*\battack\b)',        # Example: HTTP request with suspicious content
    r'(\bSELECT\b.*\bFROM\b)',        # Common SQL data extraction pattern
    r'(\bDROP\b.*\bTABLE\b)',         # SQL Injection pattern for table deletion
    r'(\b<|>|\balert\b|\bscript\b)'   # Potential XSS pattern with HTML/JavaScript
]

# Step 1: Signature-Based Detection
def signature_based_detection(data, signatures):
    detected_attacks = []
    for index, row in data.iterrows():
        payload = row['service']  # Update this column based on your data's structure
        for signature in signatures:
            if re.search(signature, payload, re.IGNORECASE):
                detected_attacks.append({
                    'src_ip': f"192.168.1.{index % 255}",  # Placeholder IP address
                    'dst_ip': f"10.0.0.{index % 255}",     # Placeholder IP address
                    'payload': payload,
                    'attack_type': 'Signature-based attack'
                })
    return detected_attacks

# Step 2: Anomaly-Based Detection
def anomaly_based_detection(train_data, test_data):
    # Select numerical features for anomaly detection
    numeric_columns = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count']
    
    # Ensure numeric conversion and drop invalid rows for training and testing data
    for col in numeric_columns:
        train_data[col] = pd.to_numeric(train_data[col], errors='coerce')
        test_data[col] = pd.to_numeric(test_data[col], errors='coerce')
        
    train_data = train_data.dropna(subset=numeric_columns)
    test_data = test_data.dropna(subset=numeric_columns)
    
    # Features for training and testing
    X_train = train_data[numeric_columns].fillna(0)
    X_test = test_data[numeric_columns].fillna(0)
    
    # Train the Isolation Forest model on the training data
    isolation_forest = IsolationForest(contamination=0.1, random_state=42)
    isolation_forest.fit(X_train)
    
    # Predict anomalies on the test data
    predictions = isolation_forest.predict(X_test)

    detected_anomalies = []
    for i, prediction in enumerate(predictions):
        if prediction == -1:  # Anomaly detected
            detected_anomalies.append({
                'src_ip': f"192.168.1.{i % 255}",  # Placeholder IP address
                'dst_ip': f"10.0.0.{i % 255}",     # Placeholder IP address
                'payload': 'Anomalous data point',
                'attack_type': 'Anomaly-based attack'
            })
    return detected_anomalies

# Streamlit Web Interface
st.title("Intrusion Detection System")

# File Upload
uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])

if uploaded_file is not None:
    # Load the dataset
    data = pd.read_csv(uploaded_file)

    # Display the first few rows of the dataset for preview
    st.write("Dataset Preview:")
    st.write(data.head())

    # Split the data into training and testing sets (80% for training, 20% for testing)
    train_data, test_data = train_test_split(data, test_size=0.2, random_state=42)

    # Run the signature-based detection
    signature_attacks = signature_based_detection(data, SIGNATURES)

    # Run the anomaly-based detection
    anomaly_attacks = anomaly_based_detection(train_data, test_data)

    # Combine results
    all_attacks = signature_attacks + anomaly_attacks

    # Display detected attacks
    if all_attacks:
        st.write("Detected Intrusions:")
        for attack in all_attacks[:10]:  # Display up to 10 attacks
            st.write(
                f"Source IP: {attack['src_ip']}, "
                f"Destination IP: {attack['dst_ip']}, "
                f"Detection Type: {attack['attack_type']}, "
                f"Payload: {attack['payload']}"
            )
    else:
        st.write("No intrusions detected.")

    # Save detected anomalies
    save_stored_anomalies([attack['payload'] for attack in anomaly_attacks])

    # Optionally display more details or graphs (for example, feature importance or prediction results)
    st.write("Additional Information:")
    st.write(f"Total Signature-based attacks detected: {len(signature_attacks)}")
    st.write(f"Total Anomalies detected: {len(anomaly_attacks)}")
else:
    st.write("Please upload a CSV file to start the intrusion detection process.")
