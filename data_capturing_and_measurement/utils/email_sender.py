from flask_mail import Message
import logging

logger = logging.getLogger(__name__)

def send_otp_email(mail, recipient, otp_code):
    try:
        msg = Message(
            subject="Your OTP Code - Data Capturing and Measurement",
            recipients=[recipient],
            body=f"""
Hello,

Your OTP code is: {otp_code}

This code will expire in 10 minutes.

If you did not request this code, please ignore this email.

Best regards,
Data Capturing and Measurement Team
            """
        )
        mail.send(msg)
        logger.info(f"OTP email sent to {recipient}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {recipient}: {str(e)}")
        return False

def send_password_reset_email(mail, recipient, otp_code):
    try:
        msg = Message(
            subject="Password Reset - Data Capturing and Measurement",
            recipients=[recipient],
            body=f"""
Hello,

You have requested to reset your password.

Your password reset OTP code is: {otp_code}

This code will expire in 10 minutes.

If you did not request this password reset, please ignore this email and your password will remain unchanged.

Best regards,
Data Capturing and Measurement Team
            """
        )
        mail.send(msg)
        logger.info(f"Password reset email sent to {recipient}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {recipient}: {str(e)}")
        return False
