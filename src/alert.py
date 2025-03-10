import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(receiver_email, attack_type, device_id):
    sender_email = "devikrishnamadhuri7@gmail.com"  # Your email
    sender_password = "dcbf qbea hmom gpnw"  # Your Gmail App Password
    

    subject = "🚨 MEC Device Attack Alert!"
    body = f"Alert!! \n      A {attack_type} attack has been detected on Device ID: {device_id}. Immediate action is required."

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        # Connect to Gmail SMTP server
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print(f"✅ Alert email sent successfully to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


