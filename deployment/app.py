from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import csv
import sys
import os
sys.path.append(os.path.abspath("src"))
from alert import send_email_alert
import threading



app = Flask(__name__)
app.secret_key = "secret_key"  # Needed for session management

# Load the trained model, scaler, and label encoders
model = load_model("models/cnn_network_attack_classifier.h5")
scaler = joblib.load("models/scaler.pkl")
label_encoders = joblib.load("models/label_encoders.pkl")  

# Attack type mapping (from encoded class values back to original)
attack_type_mapping = {
    0: "DDoS",
    1: "Normal",  # Swapped
    2: "Phishing",
    3: "Spoofing",  # Swapped
}

BASE_DIR = os.path.abspath(os.path.dirname(__file__))  
DATABASE = os.path.join(BASE_DIR, "users.db") 
print(BASE_DIR)

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Create users table with unique constraint on device_id
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT NOT NULL,
        device_id TEXT UNIQUE NOT NULL,  -- Ensure uniqueness
        location TEXT NOT NULL  
    )''')

    # Create predictions table
    c.execute('''CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id TEXT NOT NULL,
        prediction TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )''')

    # Insert data from CSV while ensuring uniqueness
    with open('depolyment/user_info.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                c.execute('''INSERT OR IGNORE INTO users (name, email, phone, device_id, location)
                             VALUES (?, ?, ?, ?, ?)''', 
                          (row['name'], row['email'], row['phone'], row['device_id'], row['location']))
            except sqlite3.IntegrityError:
                pass  # Skip duplicate entries

    conn.commit()
    conn.close()


@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        phone = request.form["phone"]
        device_id = request.form["device_id"]
        location = request.form["location"]

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        # Check if email or device_id already exists
        c.execute("SELECT * FROM users WHERE email = ? OR device_id = ?", (email, device_id))
        existing_user = c.fetchone()

        if existing_user:
            conn.close()
            return render_template("register.html", error="Email or Device ID already exists!")

        try:
            c.execute("INSERT INTO users (name, email, phone, device_id, location) VALUES (?, ?, ?, ?, ?)",
                      (name, email, phone, device_id, location))
            conn.commit()
            conn.close()

            flash("You have successfully registered!", "success")
            return redirect(url_for("home"))

        except sqlite3.IntegrityError:
            return render_template("register.html", error="Email or Device ID already exists.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]

        if email == "admin@gmail.com":
            session["user"] = "admin"
            return redirect(url_for("admin_dashboard"))

        return render_template("login.html", error="Invalid email.")
    return render_template("login.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))

    return render_template("admin.html")

# Prediction Page
@app.route("/predict", methods=["GET", "POST"])
def predict():
    if "user" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        device_id = request.form["Device_ID"]

        # Connect to the database
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()

        # Check if the Device_ID exists in the user table
        c.execute("SELECT email FROM users WHERE device_id = ?", (device_id,))
        user_data = c.fetchone()

        if user_data is None:
            conn.close()
            return render_template("predict.html", error="Device Id is Invalid")
        
        email = user_data[0]

    
        # If Device_ID exists, proceed with prediction
        user_input = {
            "Device_ID": device_id,
            "Packet_Size (bytes)": request.form["Packet_Size"],
            "Latency (ms)": request.form["Latency"],
            "Throughput (Mbps)": request.form["Throughput"],
            "Protocol_Type": request.form["Protocol_Type"],
            "Source_Port": request.form["Source_Port"],
            "Destination_Port": request.form["Destination_Port"],
            "IP_Flag": request.form["IP_Flag"],
            "Connection_Duration (ms)": request.form["Connection_Duration"],
            "Packet_Count": request.form["Packet_Count"],
            "Error_Rate": request.form["Error_Rate"],
            "Fragmentation_Flag": request.form["Fragmentation_Flag"],
            "Payload_Size (bytes)": request.form["Payload_Size"],
            "Session_Status": request.form["Session_Status"]
        }

        # Preprocess input
        df_input = pd.DataFrame([user_input])

        # Encode categorical features using the saved label encoders
        for col in ["Protocol_Type", "IP_Flag", "Session_Status", "Device_ID"]:
            try:
                df_input[col] = label_encoders[col].transform(df_input[col])
            except ValueError:
                df_input[col] = 0  # Assign default value for unknown categories

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

        # Predict attack type
        prediction = model.predict(df_input_scaled)
        predicted_class = np.argmax(prediction, axis=1)[0]
        predicted_attack_type = attack_type_mapping[predicted_class]

        # Store prediction in database
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO predictions (device_id, prediction) VALUES (?, ?)",
                  (device_id, predicted_attack_type))
        conn.commit()
        conn.close()
         
        if predicted_attack_type != "Normal":  # Adjust condition as needed
            threading.Thread(
                target=send_email_alert,
                args=(email,predicted_attack_type,device_id)
            ).start()

        return render_template("predict.html", device_id=device_id, prediction=predicted_attack_type)

    return render_template("predict.html")

@app.route("/admin")
def admin():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))

    return render_template("admin.html")

@app.route("/previous_history")
def previous_history():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Fetch previous history (prediction records)
    c.execute("SELECT id, device_id, prediction, timestamp FROM predictions")
    history = c.fetchall()

    conn.close()
    return render_template("previous_history.html", history=history)


# Logout Route
@app.route("/logout")
def logout():
    session.clear()  # Clear all session data
    return redirect(url_for("home"))  # Redirect to home page


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
