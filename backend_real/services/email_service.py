import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_SENDER = os.getenv("SMTP_SENDER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


class EmailDeliveryError(RuntimeError):
    """Error controlado para fallas de configuración o envío SMTP."""


def _validate_smtp_config() -> None:
    if not SMTP_SERVER:
        raise EmailDeliveryError("SMTP_SERVER no está configurado")
    if not SMTP_PORT:
        raise EmailDeliveryError("SMTP_PORT no está configurado")
    if not SMTP_SENDER:
        raise EmailDeliveryError("SMTP_SENDER no está configurado")
    if not SMTP_PASSWORD:
        raise EmailDeliveryError("SMTP_PASSWORD no está configurado")

def send_otp_email(to_email: str, otp: str) -> None:
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

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(SMTP_SENDER, SMTP_PASSWORD)
            server.sendmail(SMTP_SENDER, to_email, msg.as_string())
    except smtplib.SMTPException as exc:
        raise EmailDeliveryError(f"No se pudo enviar el correo OTP: {exc}") from exc
