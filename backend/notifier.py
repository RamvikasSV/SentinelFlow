"""
File: notifier.py
Ported & Upgraded from Lhedge (HPE CTY) — send_mail.py + DOCX report generation

Lhedge emailed a .docx attachment on every detection.
SentinelFlow upgrade:
  - Only fires after full remediation (detect → classify → investigate → respond → notify)
  - Generates a proper PDF report using reportlab (cross-platform, no Word needed)
  - HTML-formatted email body with full incident summary
  - Only triggers for HIGH or CRITICAL severity incidents (no spam for minor events)
  - Runs SMTP in a thread executor so it never blocks the async event loop
"""

import asyncio
import smtplib
import ssl
import os
from datetime import datetime
from email.message import EmailMessage
from io import BytesIO
from typing import Any, Dict, Optional

from backend.config import settings
from backend.broker import broker, Event


def _build_pdf_report(incident: Dict[str, Any]) -> Optional[bytes]:
    """
    Generates a styled PDF forensic report using reportlab.
    Returns raw PDF bytes, or None if reportlab is not installed.
    Ported from Lhedge's generate_styled_report() docx approach.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, black, white, red
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        DARK = HexColor("#0d1117")
        ACCENT = HexColor("#00f5ff")
        WARN = HexColor("#ff4444")
        GRAY = HexColor("#8b949e")

        title_style = ParagraphStyle("title", parent=styles["Heading1"],
                                     textColor=ACCENT, fontSize=20, spaceAfter=6)
        h2_style = ParagraphStyle("h2", parent=styles["Heading2"],
                                  textColor=WARN, fontSize=13, spaceAfter=4)
        body_style = ParagraphStyle("body", parent=styles["Normal"],
                                    fontSize=10, spaceAfter=3, textColor=black)
        label_style = ParagraphStyle("label", parent=styles["Normal"],
                                     fontSize=9, textColor=GRAY, spaceAfter=2)

        # ── Helpers ───────────────────────────────────────────────────────────
        def h(text, style=body_style): return Paragraph(text, style)
        def sp(n=0.3): return Spacer(1, n*cm)
        def hr(): return HRFlowable(width="100%", thickness=0.5, color=GRAY)

        # ── Incident data ─────────────────────────────────────────────────────
        ip          = incident.get("ip", "Unknown")
        category    = incident.get("category", "Unknown")
        severity    = incident.get("severity", "Unknown").upper()
        status      = incident.get("status", "Unknown").upper()
        actions     = incident.get("actions_taken", [])
        failures    = incident.get("failures", [])
        geo         = incident.get("geo_info", {})
        ts          = datetime.fromtimestamp(incident.get("timestamp", datetime.now().timestamp()))
        ts_str      = ts.strftime("%Y-%m-%d %H:%M:%S UTC")

        story = [
            h("🛡️  SentinelFlow — Forensic Incident Report", title_style),
            h(f"Generated: {ts_str} &nbsp;|&nbsp; Severity: {severity}", label_style),
            sp(),
            hr(),
            sp(0.4),

            # Executive Summary (matches Lhedge's report structure)
            h("Executive Summary", h2_style),
            h(f"SentinelFlow has automatically detected, investigated, and mitigated a "
              f"<b>{category}</b> attack originating from IP <b>{ip}</b>. "
              f"The incident has been resolved with status: <b>{status}</b>.", body_style),
            sp(0.5),

            # Attacker Details
            h("Attacker Details", h2_style),
        ]

        # Attacker info table
        geo_rows = [
            ["Field",       "Value"],
            ["Attacker IP", ip],
            ["Country",     geo.get("country", "Unknown")],
            ["City",        geo.get("city", "Unknown")],
            ["ISP",         geo.get("isp", "Unknown")],
            ["Org",         geo.get("org", "") or "—"],
            ["Coordinates", f"{geo.get('lat','?')}, {geo.get('lon','?')}"],
            ["Category",    category],
            ["Severity",    severity],
        ]
        t = Table(geo_rows, colWidths=[5*cm, 11*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), HexColor("#21262d")),
            ("TEXTCOLOR",   (0,0), (-1,0), white),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("GRID",        (0,0), (-1,-1), 0.25, GRAY),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [HexColor("#f6f8fa"), white]),
        ]))
        story += [t, sp(0.5)]

        # Actions taken
        story.append(h("Automated Response Actions", h2_style))
        if actions:
            for a in actions:
                story.append(h(f"✅ &nbsp; {a}", body_style))
        else:
            story.append(h("No automated actions were taken.", body_style))

        if failures:
            story.append(sp(0.3))
            story.append(h("Partial Failures", h2_style))
            for f in failures:
                story.append(h(f"⚠️  &nbsp; {f}", body_style))

        story += [
            sp(0.5), hr(), sp(0.3),
            h("This report was automatically generated by SentinelFlow — AI-Powered Multi-Agent Incident Response System.", label_style),
        ]

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        return None   # reportlab not installed — skip PDF attachment


from typing import List

def _send_email_sync(incident: Dict[str, Any], pdf_bytes: Optional[bytes], receivers: List[str]):
    """
    Synchronous SMTP send — called in a thread executor so it doesn't block asyncio.
    Ported from Lhedge's send_mail.py and upgraded with HTML body + PDF attachment.
    """
    sender   = settings.email_sender
    password = settings.email_password

    if not sender or not password or not receivers:
        return False, "Email credentials or recipients not configured"

    ip       = incident.get("ip", "Unknown")
    category = incident.get("category", "Unknown")
    severity = incident.get("severity", "Unknown").upper()
    status   = incident.get("status", "Unknown").upper()
    geo      = incident.get("geo_info", {})
    actions  = incident.get("actions_taken", [])
    ts_str   = datetime.fromtimestamp(
                    incident.get("timestamp", datetime.now().timestamp())
               ).strftime("%Y-%m-%d %H:%M:%S UTC")

    actions_html = "".join(f"<li>✅ {a}</li>" for a in actions) or "<li>None</li>"
    geo_str = (f"{geo.get('city','?')}, {geo.get('country','?')} "
               f"(ISP: {geo.get('isp','?')})") if geo else "Unknown"

    # HTML email body — inspired by Lhedge's forensic report structure
    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:20px">
      <div style="max-width:600px;margin:auto;background:#161b22;border-radius:8px;
                  border:1px solid #30363d;padding:24px">
        <h1 style="color:#00f5ff;margin-bottom:4px">🛡️ SentinelFlow Alert</h1>
        <p style="color:#8b949e;margin-top:0">Automated Forensic Incident Report</p>
        <hr style="border-color:#30363d">

        <table style="width:100%;border-collapse:collapse;margin:16px 0">
          <tr><td style="color:#8b949e;padding:6px 0">🕐 Timestamp</td>
              <td><b>{ts_str}</b></td></tr>
          <tr><td style="color:#8b949e;padding:6px 0">⚠️  Severity</td>
              <td><b style="color:#ff4444">{severity}</b></td></tr>
          <tr><td style="color:#8b949e;padding:6px 0">🎯 Category</td>
              <td><b>{category}</b></td></tr>
          <tr><td style="color:#8b949e;padding:6px 0">🌐 Attacker IP</td>
              <td><b>{ip}</b></td></tr>
          <tr><td style="color:#8b949e;padding:6px 0">📍 GeoIP</td>
              <td>{geo_str}</td></tr>
          <tr><td style="color:#8b949e;padding:6px 0">✅ Status</td>
              <td><b style="color:#3fb950">{status}</b></td></tr>
        </table>

        <h3 style="color:#f0883e">Automated Actions Taken</h3>
        <ul style="padding-left:20px">{actions_html}</ul>

        <hr style="border-color:#30363d">
        <p style="color:#8b949e;font-size:12px">
          SentinelFlow — AI Multi-Agent Incident Response System
        </p>
      </div>
    </body></html>
    """

    try:
        em = EmailMessage()
        em["From"]    = sender
        em["To"]      = ", ".join(receivers)
        em["Subject"] = f"[SentinelFlow] {severity} Alert — {category} from {ip}"
        em.set_content(f"SentinelFlow incident report: {category} from {ip} ({ts_str})")
        em.add_alternative(html_body, subtype="html")

        # Attach PDF if generated
        if pdf_bytes:
            filename = f"SentinelFlow_Report_{ip.replace('.', '_')}_{ts_str[:10]}.pdf"
            em.add_attachment(pdf_bytes, maintype="application",
                               subtype="pdf", filename=filename)

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context) as smtp:
            smtp.login(sender, password)
            smtp.sendmail(sender, receivers, em.as_string())

        return True, "Email sent successfully"

    except Exception as e:
        return False, str(e)


class ForensicNotifier:
    """
    Listens for completed remediation events and sends email forensic reports.
    Ported from Lhedge's send_mail.py — upgraded with HTML + PDF + async pipeline.
    Only fires for HIGH and CRITICAL incidents to avoid notification fatigue.
    """

    def __init__(self):
        self.running = False
        self._task = None
        self._notify_severities = {"high", "critical"}
        self._notified_ips = {}  # IP -> last notification timestamp (float)
        
        # Initialize user registry for multi-recipient notifications
        from backend.user_registry import UserRegistry
        self.registry = UserRegistry()

    async def start(self):
        if not settings.email_sender:
            await broker.publish(Event(
                event_type="agent_thought",
                source="notifier",
                data={"text": "Email notifier: no sender email configured in .env — email alerts disabled"}
            ))
            return

        self.running = True
        self._task = asyncio.create_task(self._listen())
        
        users = self.registry.get_users()
        recipient_info = f"{len(users)} registered recipients" if users else f"fallback recipient ({settings.email_receiver or 'none'})"
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="notifier",
            data={"text": f"Forensic Notifier active — will email {recipient_info} on HIGH/CRITICAL incidents"}
        ))

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()

    async def _listen(self):
        """Subscribes to remediation events and sends email reports."""
        queue = broker.subscribe("remediation")
        try:
            while self.running:
                event: Event = await queue.get()
                severity = (event.severity or "").lower()
                if severity in self._notify_severities:
                    asyncio.create_task(self._notify(event))
                queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            broker.unsubscribe("remediation", queue)

    async def _notify(self, event: Event):
        """Generates PDF + sends email in a thread executor."""
        import time
        ip = event.data.get("ip", "unknown")
        
        # Debounce duplicate notifications for the same IP within a 30-second window
        if ip != "unknown":
            now = time.time()
            if ip in self._notified_ips:
                last_time = self._notified_ips[ip]
                if now - last_time < 30.0:
                    await broker.publish(Event(
                        event_type="agent_thought",
                        source="notifier",
                        data={"text": f"Skipping duplicate email notification for IP {ip} (debounced within 30s window)."}
                    ))
                    return
            self._notified_ips[ip] = now

        incident = {**event.data, "severity": event.severity, "timestamp": event.timestamp}

        # Resolve email recipients
        registered_users = self.registry.get_users()
        receivers = [u["email"] for u in registered_users]
        
        if not receivers:
            if settings.email_receiver:
                receivers = [settings.email_receiver]
            else:
                await broker.publish(Event(
                    event_type="agent_thought",
                    source="notifier",
                    data={"text": "Email notifier warning: no registered users and no fallback EMAIL_RECEIVER in .env. Skipping email."}
                ))
                return

        receiver_names_str = ", ".join(receivers)
        await broker.publish(Event(
            event_type="agent_thought",
            source="notifier",
            data={"text": f"Generating forensic PDF report and emailing to {receiver_names_str}..."}
        ))

        loop = asyncio.get_event_loop()

        # Build PDF in thread (reportlab is sync)
        pdf_bytes = await loop.run_in_executor(None, _build_pdf_report, incident)

        # Send email in thread (smtplib is sync/blocking)
        ok, msg = await loop.run_in_executor(None, _send_email_sync, incident, pdf_bytes, receivers)

        await broker.publish(Event(
            event_type="agent_thought",
            source="notifier",
            data={"text": f"Email notifier: {'✅ ' + msg if ok else '⚠️ Failed — ' + msg}"}
        ))
