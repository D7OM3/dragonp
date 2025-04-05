import os
import logging
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

class EmailSender:
    def __init__(self):
        # Use dragoneye.vapt@gmail.com as sender since it's verified
        self.sender = Email("dragoneye.vapt@gmail.com")
        self.api_key = os.environ.get('SENDGRID_API_KEY')
        if not self.api_key:
            logging.error("SendGrid API key not found in environment variables")
            raise ValueError("SendGrid API key is required for email delivery")

    def send_report(self, recipient: str, report_content: str) -> None:
        try:
            # Format the content nicely
            content = (
                "Security Scan Report\n"
                "===================\n\n"
                f"{report_content}\n\n"
                "This report was generated automatically by the Security Scanner Tool."
            )

            message = Mail(
                from_email=self.sender,
                to_emails=To(recipient),
                subject='Security Scan Report',
                plain_text_content=Content("text/plain", content)
            )

            sg = SendGridAPIClient(self.api_key)
            response = sg.send(message)

            if response.status_code in [200, 201, 202]:
                logging.info(f"Report sent successfully to {recipient}")
            else:
                error_msg = f"SendGrid API returned status code: {response.status_code}"
                logging.error(error_msg)
                raise Exception(error_msg)

        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg:
                logging.error("Authentication failed. Please check if your SendGrid API key is valid")
            elif "403" in error_msg:
                logging.error("Permission denied. Please ensure your SendGrid API key has 'Mail Send' permission enabled")
            else:
                logging.error(f"Failed to send email: {error_msg}")

            print("\nNote: Email delivery failed. The scan report is displayed below for your reference.")
            print("=" * 50)
            print(report_content)
            print("=" * 50)
            raise