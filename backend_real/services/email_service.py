import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

EMAIL_SENDER = "TU_CORREO@gmail.com"
EMAIL_PASSWORD = "TU_APP_PASSWORD"  # contraseña de aplicación

def send_otp_email(to_email: str, otp: str):
    subject = "Verificación CryptoLock"
    body = f"""
    Hola,

    Tu código de verificación es:

    {otp}

    Este código expira en 5 minutos.
    """

    msg = MIMEMultipart()
    msg["From"] = EMAIL_SENDER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(EMAIL_SENDER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_SENDER, to_email, msg.as_string())
