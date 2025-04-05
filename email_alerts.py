import os
import logging
import smtplib
import asyncore
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from smtpd import SMTPServer

class CustomSMTPServer(SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        logging.info(f"Received mail from: {mailfrom}")
        logging.info(f"Recipient(s): {rcpttos}")
        logging.info(f"Message: {data.decode('utf-8')}")
        return

class EmailAlertService:
    def __init__(self, host='localhost', port=2525):  # Changed default port to 2525
        self.from_email = "dragoneye.vapt@gmail.com"  # Set this first to avoid attribute error
        self.port = port
        try:
            self.smtp_server = CustomSMTPServer((host, port), None)
            self.server_thread = None
            logging.info(f"Local SMTP server initialized on {host}:{port}")
        except OSError as e:
            if e.errno == 98:  # Address already in use
                # Try alternate ports
                for alt_port in range(2525, 2535):
                    try:
                        self.smtp_server = CustomSMTPServer((host, alt_port), None)
                        self.port = alt_port
                        logging.info(f"Local SMTP server initialized on alternate port {host}:{alt_port}")
                        break
                    except OSError:
                        continue
            if not hasattr(self, 'smtp_server'):
                raise RuntimeError("Could not find available port for SMTP server")

    def start_server(self):
        try:
            logging.info(f"Starting local SMTP server on port {self.port}...")
            asyncore.loop(timeout=1)
        except Exception as e:
            logging.error(f"Failed to start SMTP server: {str(e)}")
            raise

    def send_alert(self, to_email, vulnerability_data):
        try:
            subject = f"Security Alert: {vulnerability_data['severity']} Vulnerability Detected"

            # Create HTML content
            html_content = f"""
            <h2>Security Vulnerability Alert</h2>
            <p><strong>Severity:</strong> {vulnerability_data['severity']}</p>
            <p><strong>Target:</strong> {vulnerability_data['target']}</p>
            <p><strong>Description:</strong> {vulnerability_data['description']}</p>
            <p><strong>Detected At:</strong> {vulnerability_data['timestamp']}</p>
            <p><strong>Recommended Action:</strong> {vulnerability_data['recommendation']}</p>
            """

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg.attach(MIMEText(html_content, 'html'))

            # Send using local SMTP server
            with smtplib.SMTP('localhost', self.port) as server:
                server.send_message(msg)

            logging.info(f"Alert email sent successfully to {to_email}")
            return True

        except Exception as e:
            logging.error(f"Failed to send alert email: {str(e)}")
            return False

    def test_connection(self, test_email=None):
        try:
            to_email = test_email if test_email else "test@example.com"
            logging.info(f"Testing email connection to {to_email}")

            msg = MIMEMultipart('alternative')
            msg['Subject'] = "DragonEye Security Scanner - Email Test"
            msg['From'] = self.from_email
            msg['To'] = to_email

            html_content = """
            <h1>Email Configuration Test</h1>
            <p>Your email alerts are configured correctly. This is a test email from DragonEye Security Scanner.</p>
            """
            msg.attach(MIMEText(html_content, 'html'))

            with smtplib.SMTP('localhost', self.port) as server:
                server.send_message(msg)

            logging.info("Local SMTP test successful")
            return True

        except Exception as e:
            logging.error(f"Local SMTP test failed: {str(e)}")
            return False