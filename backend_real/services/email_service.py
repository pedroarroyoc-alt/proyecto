import os
import smtplib
import ssl
from dataclasses import dataclass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import parseaddr

class EmailDeliveryError(RuntimeError):
    """Error controlado para fallas de configuración o envío SMTP."""

@dataclass(frozen=True)
class SMTPConfig:
    host: str
    port: int
    sender_header: str
    envelope_from: str
    login_user: str
    password: str
    use_ssl: bool
    use_starttls: bool

def _first_present_env(*keys: str) -> str:
    for key in keys:
        value = os.getenv(key)
        if value and value.strip():
            return value.strip()
    return ""


def _smtp_settings() -> SMTPConfig:
    smtp_server = _first_present_env("SMTP_SERVER", "SMTP_HOST") or "smtp.gmail.com"
    smtp_port_raw = os.getenv("SMTP_PORT", "587").strip()
    smtp_tls = os.getenv("SMTP_TLS", "1").strip().lower() not in {"0", "false", "no"}
    smtp_ssl = os.getenv("SMTP_SSL", "0").strip().lower() in {"1", "true", "yes"}

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

    sender_address = parseaddr(smtp_sender)[1] or login_user
    if not sender_address:
        raise EmailDeliveryError(
            "No se pudo determinar el remitente SMTP. Revisa SMTP_SENDER o SMTP_USER."
        )

    # Si el puerto es 465 suele requerir SMTP_SSL aunque no se haya indicado explícitamente.
    if smtp_port == 465 and not smtp_ssl:
        smtp_ssl = True

    # STARTTLS y SMTP_SSL son excluyentes.
    if smtp_ssl and smtp_tls:
        smtp_tls = False

    return SMTPConfig(
        host=smtp_server,
        port=smtp_port,
        sender_header=smtp_sender,
        envelope_from=sender_address,
        login_user=login_user,
        password=smtp_password,
        use_ssl=smtp_ssl,
        use_starttls=smtp_tls,
    )


def send_otp_email(to_email: str, otp: str) -> None:
    config = _smtp_settings()

    subject = "Verificación CryptoLock"
    body = f"""
    Hola,

    Tu código de verificación es:

    {otp}

    Este código expira en 5 minutos.
    """

    msg = MIMEMultipart()
    msg["From"] = config.sender_header
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        tls_context = ssl.create_default_context()
        if config.use_ssl:
            with smtplib.SMTP_SSL(config.host, config.port, context=tls_context, timeout=20) as server:
                server.login(config.login_user, config.password)
                server.sendmail(config.envelope_from, to_email, msg.as_string())
        else:
            with smtplib.SMTP(config.host, config.port, timeout=20) as server:
                server.ehlo()
                if config.use_starttls:
                    server.starttls(context=tls_context)
                    server.ehlo()
                server.login(config.login_user, config.password)
                server.sendmail(config.envelope_from, to_email, msg.as_string())
    except smtplib.SMTPException as exc:
        raise EmailDeliveryError(f"No se pudo enviar el correo OTP: {exc}") from exc
    except OSError as exc:
        raise EmailDeliveryError(f"No se pudo conectar al servidor SMTP: {exc}") from exc
