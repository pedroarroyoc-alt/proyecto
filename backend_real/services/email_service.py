import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

class EmailDeliveryError(RuntimeError):
    """Error controlado para fallas de configuración o envío SMTP."""


def _first_present_env(*keys: str) -> str:
    for key in keys:
        value = os.getenv(key)
        if value and value.strip():
            return value.strip()
    return ""


def _smtp_settings() -> tuple[str, int, str, str]:
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com").strip()
    smtp_port_raw = os.getenv("SMTP_PORT", "587").strip()

    # Compatibilidad con nombres de variables frecuentes en distintos entornos.
    smtp_sender = _first_present_env("SMTP_SENDER", "SMTP_USER", "EMAIL_USER", "GMAIL_USER")
    smtp_password = _first_present_env(
        "SMTP_PASSWORD",
        "SMTP_PASS",
        "EMAIL_PASSWORD",
        "GMAIL_APP_PASSWORD",
    )

    if not smtp_server:
        raise EmailDeliveryError("SMTP_SERVER no está configurado")
    
    try:
        smtp_port = int(smtp_port_raw)
    except ValueError as exc:
        raise EmailDeliveryError("SMTP_PORT no es un número válido") from exc

    if smtp_port <= 0:
        raise EmailDeliveryError("SMTP_PORT debe ser mayor a 0")

    if not smtp_sender:
        raise EmailDeliveryError(
            "SMTP sender no configurado. Define SMTP_SENDER (o SMTP_USER/EMAIL_USER/GMAIL_USER)."
        )

    if not smtp_password:
        raise EmailDeliveryError(
            "SMTP password no configurado. Define SMTP_PASSWORD (o SMTP_PASS/EMAIL_PASSWORD/GMAIL_APP_PASSWORD)."
        )

    return smtp_server, smtp_port, smtp_sender, smtp_password


def send_otp_email(to_email: str, otp: str) -> None:
    smtp_server, smtp_port, smtp_sender, smtp_password = _smtp_settings()

    subject = "Verificación CryptoLock"
    body = f"""
    Hola,

    Tu código de verificación es:

    {otp}

    Este código expira en 5 minutos.
    """

    msg = MIMEMultipart()
    msg["From"] = smtp_sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
            server.starttls()
            server.login(smtp_sender, smtp_password)
            server.sendmail(smtp_sender, to_email, msg.as_string())
    except smtplib.SMTPException as exc:
        raise EmailDeliveryError(f"No se pudo enviar el correo OTP: {exc}") from exc
    except OSError as exc:
        raise EmailDeliveryError(f"No se pudo conectar al servidor SMTP: {exc}") from exc
