"""Envio de e-mail transacional (reset de senha / convite).

Configuração 100% por variáveis de ambiente — nada de credencial no código:
  SMTP_HOST, SMTP_PORT (587 padrão), SMTP_USER, SMTP_PASS,
  SMTP_FROM (remetente; cai para SMTP_USER), SMTP_TLS (true/false; STARTTLS),
  APP_PUBLIC_URL (base dos links nos e-mails).

Sem SMTP_HOST/remetente configurados, NÃO envia: registra o conteúdo no log
(fallback de desenvolvimento) e devolve sent=False. Assim o fluxo de reset
funciona e é testável mesmo antes de o SMTP estar provisionado.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage

from logger import logger


def public_base_url() -> str:
    """Base pública do front para montar links de e-mail (sem barra final)."""
    return os.getenv("APP_PUBLIC_URL", "http://192.168.0.10").strip().rstrip("/")


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip() and
                (os.getenv("SMTP_FROM", "").strip() or os.getenv("SMTP_USER", "").strip()))


def send_email(to: str, subject: str, body_text: str) -> dict:
    """Envia um e-mail de texto. Retorna {"sent": bool, "reason"?: str}."""
    host = os.getenv("SMTP_HOST", "").strip()
    sender = (os.getenv("SMTP_FROM", "") or os.getenv("SMTP_USER", "")).strip()
    if not host or not sender:
        logger.warning(
            "[mailer] SMTP nao configurado — e-mail NAO enviado. "
            "to=%s | subject=%s | corpo:\n%s", to, subject, body_text)
        return {"sent": False, "reason": "smtp_not_configured"}

    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "").strip()
    pwd = os.getenv("SMTP_PASS", "")
    use_tls = os.getenv("SMTP_TLS", "true").strip().lower() not in ("0", "false", "no")

    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body_text)

    try:
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=20) as s:
                if user:
                    s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.ehlo()
                if use_tls:
                    s.starttls(context=ctx)
                    s.ehlo()
                if user:
                    s.login(user, pwd)
                s.send_message(msg)
        logger.info("[mailer] e-mail enviado para %s (assunto: %s)", to, subject)
        return {"sent": True}
    except Exception as e:  # noqa: BLE001 — qualquer falha vira resultado, não 500
        logger.warning("[mailer] falha ao enviar para %s: %s", to, e)
        return {"sent": False, "reason": str(e)}
