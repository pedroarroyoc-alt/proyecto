import os
import smtplib
from email.utils import parseaddr
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


def _smtp_settings() -> tuple[str, int, str, str, str, bool]:
    smtp_server = _first_present_env("SMTP_SERVER", "SMTP_HOST") or "smtp.gmail.com"
    smtp_port_raw = os.getenv("SMTP_PORT", "587").strip()
    smtp_tls = os.getenv("SMTP_TLS", "1").strip().lower() not in {"0", "false", "no"}

    # Compatibilidad con nombres de variables frecuentes en distintos entornos.
    smtp_sender = _first_present_env("SMTP_SENDER", "SMTP_USER", "EMAIL_USER", "GMAIL_USER")
    smtp_user = _first_present_env("SMTP_USER", "EMAIL_USER", "GMAIL_USER")
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

    login_user = smtp_user or parseaddr(smtp_sender)[1]
    if not login_user:
        raise EmailDeliveryError(
            "SMTP user no configurado. Define SMTP_USER para la autenticación SMTP."
        )

    return smtp_server, smtp_port, smtp_sender, login_user, smtp_password, smtp_tls


def send_otp_email(to_email: str, otp: str) -> None:
    smtp_server, smtp_port, smtp_sender, login_user, smtp_password, smtp_tls = _smtp_settings()

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
            if smtp_tls:
                server.starttls()
            server.login(login_user, smtp_password)
            server.sendmail(login_user, to_email, msg.as_string())
    except smtplib.SMTPException as exc:
        raise EmailDeliveryError(f"No se pudo enviar el correo OTP: {exc}") from exc
    except OSError as exc:
        raise EmailDeliveryError(f"No se pudo conectar al servidor SMTP: {exc}") from exc
