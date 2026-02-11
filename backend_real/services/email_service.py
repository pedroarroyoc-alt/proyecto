import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class EmailDeliveryError(RuntimeError):
    """Error controlado para fallas de configuración o envío SMTP."""


def _validate_smtp_config() -> None:
    if not SMTP_SENDER:
        raise EmailDeliveryError("SMTP_SENDER no está configurado")
    if not SMTP_PASSWORD:
        raise EmailDeliveryError("SMTP_PASSWORD no está configurado")

def send_otp_email(to_email: str, otp: str):
    _validate_smtp_config()

    subject = "Verificación CryptoLock"
    body = f"""
    Hola,

    Tu código de verificación es:

    {otp}

    Este código expira en 5 minutos.
    """

    msg = MIMEMultipart()
    msg["From"] = SMTP_SENDER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
        server.starttls()
        server.login(SMTP_SENDER, SMTP_PASSWORD)
        server.sendmail(SMTP_SENDER, to_email, msg.as_string())
