"""
File: watchdog_agent.py
Ported & Upgraded from Lhedge (HPE CTY) — detect_malware.py

Original Lhedge used Python watchdog to monitor a single user-specified directory
on Parrot OS and email a DOCX report on malware detection.

SentinelFlow upgrade:
  - Cross-platform: monitors Windows malware hotspots locally + Linux/SSH targets remotely
  - Covers all known malware drop zones on both Windows and Linux/Parrot OS
  - Feeds detections into the existing agent pipeline (Scanner → Classifier → Forensics → Response)
  - No email needed — live dashboard + auto-remediation handles the response
"""

import asyncio
import os
import sys
import threading
from pathlib import Path
from typing import List, Dict, Any

from backend.broker import broker, Event
from backend.config import settings

# ── Malware file indicators (cross-platform) ─────────────────────────────────
# Suspicious filenames / keywords
MALWARE_NAME_INDICATORS = [
    "backdoor", "shell", "webshell", "keylogger", "rat",
    "rootkit", "trojan", "exploit", "miner", "cryptominer",
    "stealer", "spyware", "ransom", "payload", "dropper",
    "stager", "loader", "implant", "c2", "beacon",
]

# Suspicious extensions in sensitive locations
MALWARE_EXTENSIONS = {
    # Scripts that should never appear in temp/system dirs
    ".php", ".phtml", ".phar",         # PHP web shells
    ".jsp", ".jspx",                   # Java web shells  
    ".aspx", ".asp",                   # ASP web shells
    ".sh", ".bash",                    # Bash scripts in unusual locations
    ".ps1", ".psm1", ".psd1",          # PowerShell scripts
    ".vbs", ".vbe",                    # VBScript
    ".hta",                            # HTML Application (common dropper)
    ".jar",                            # Java payloads
    ".elf",                            # Linux ELF binaries in web dirs
}

# ── Windows malware hotspot directories ──────────────────────────────────────
# These are the most common malware drop zones on Windows systems
def get_windows_watch_paths() -> List[str]:
    paths = []
    temp = os.environ.get("TEMP", "C:\\Windows\\Temp")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")
    systemroot = os.environ.get("SystemRoot", "C:\\Windows")

    candidates = [
        # Primary temp directories — most malware stages here first
        temp,
        "C:\\Windows\\Temp",
        os.path.join(localappdata, "Temp") if localappdata else "",

        # Startup persistence locations — malware writes here to survive reboot
        os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup") if appdata else "",
        os.path.join(localappdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup") if localappdata else "",
        os.path.join(systemroot, "System32", "GroupPolicy", "Machine", "Scripts", "Startup"),

        # Common download/drop locations
        os.path.join(userprofile, "Downloads") if userprofile else "",
        os.path.join(userprofile, "AppData", "Roaming") if userprofile else "",

        # ProgramData — legitimate apps use it, but so does malware for persistence
        "C:\\ProgramData",

        # Recycle bin staging (sometimes used by malware as a staging dir)
        "C:\\$Recycle.Bin",

        # Project logs directory (to catch simulated events in simulation mode)
        str(Path(__file__).resolve().parent.parent.parent / "logs"),
    ]

    for p in candidates:
        if p and os.path.exists(p):
            paths.append(p)

    return list(set(paths))  # deduplicate


# ── Linux / Parrot OS malware hotspot directories (monitored via SSH) ─────────
LINUX_WATCH_PATHS = [
    # Temp directories — universally used by malware for staging
    "/tmp",
    "/var/tmp",
    "/dev/shm",             # RAM-based filesystem — fileless malware favourite

    # Web roots — PHP/JSP web shell upload targets
    "/var/www",
    "/var/www/html",
    "/srv/http",
    "/usr/share/nginx/html",

    # Cron directories — persistence mechanism
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/var/spool/cron",

    # Startup / init scripts — persistence
    "/etc/init.d",
    "/etc/rc.local",
    "/etc/profile.d",

    # Binary directories — malware drops fake binaries here
    "/usr/local/bin",
    "/usr/local/sbin",
    "/usr/bin",

    # Home directories — user-level persistence / privilege escalation staging
    "/root",
    "/home",

    # Log directory (Parrot OS / Ubuntu)
    "/var/log",
]


def _is_suspicious(file_path: str) -> tuple[bool, str]:
    """
    Returns (is_suspicious, reason) for a given file path.
    Checks filename keywords and extension-in-sensitive-location combinations.
    """
    path_lower = file_path.lower()
    name_lower = os.path.basename(path_lower)
    ext = Path(file_path).suffix.lower()

    # Check name keywords
    for indicator in MALWARE_NAME_INDICATORS:
        if indicator in name_lower:
            return True, f"Suspicious filename keyword '{indicator}' detected"

    # Check extension in malware-relevant location
    if ext in MALWARE_EXTENSIONS:
        return True, f"Suspicious file type '{ext}' found in monitored location"

    # Hidden files starting with . in system directories
    if name_lower.startswith(".") and any(
        d in path_lower for d in ["/etc", "/usr", "/bin", "/sbin", "system32"]
    ):
        return True, f"Hidden file '{name_lower}' in sensitive system directory"

    # Executable scripts in web roots
    if ext in (".sh", ".php", ".py", ".pl") and "/var/www" in path_lower:
        return True, f"Executable script '{ext}' in web root"

    return False, ""


class WatchdogFilesystemAgent:
    """
    Cross-platform malware filesystem watcher.
    Ported and significantly upgraded from Lhedge's detect_malware.py.

    Windows mode : uses Python watchdog library for real-time inotify-style events
    SSH mode     : polls Linux target's filesystem every 60s via SSH adapter
    """

    def __init__(self, server=None):
        self.server = server
        self.running = False
        self._observer = None          # watchdog Observer (Windows local mode)
        self._ssh_poll_task = None     # asyncio Task (SSH mode)
        self._event_loop = None        # reference for thread-safe publishing

    async def start(self):
        self.running = True
        self._event_loop = asyncio.get_event_loop()

        await broker.publish(Event(
            event_type="agent_thought",
            source="watchdog_agent",
            data={"text": "Watchdog Filesystem Agent active. Scanning for malware hotspots across Windows + Linux paths..."}
        ))

        if settings.system_mode == "ssh" and self.server is not None:
            # SSH mode: poll Linux/Parrot OS directories remotely
            self._ssh_poll_task = asyncio.create_task(self._ssh_poll_loop())
        else:
            # Local mode: real-time watchdog on Windows directories
            self._start_local_watchdog()

    async def stop(self):
        self.running = False
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None
        if self._ssh_poll_task:
            self._ssh_poll_task.cancel()

    # ── Windows Local Watchdog (real-time via watchdog library) ──────────────
    def _start_local_watchdog(self):
        """Starts watchdog observers on all Windows malware hotspot directories."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler

            agent_ref = self  # capture for inner class

            class MalwareEventHandler(FileSystemEventHandler):
                def on_created(self, event):
                    if not event.is_directory:
                        agent_ref._on_file_event("created", event.src_path)

                def on_modified(self, event):
                    if not event.is_directory:
                        agent_ref._on_file_event("modified", event.src_path)

                def on_moved(self, event):
                    if not event.is_directory:
                        agent_ref._on_file_event("moved", event.dest_path)

            self._observer = Observer()
            watch_paths = get_windows_watch_paths()
            handler = MalwareEventHandler()
            scheduled = 0

            for path in watch_paths:
                try:
                    self._observer.schedule(handler, path, recursive=True)
                    scheduled += 1
                except Exception:
                    pass  # Skip paths we can't access (permissions, etc.)

            self._observer.start()

            # Publish startup confirmation in a thread-safe way
            asyncio.run_coroutine_threadsafe(
                broker.publish(Event(
                    event_type="agent_thought",
                    source="watchdog_agent",
                    data={"text": f"Watchdog monitoring {scheduled} Windows malware hotspot directories in real-time"}
                )),
                self._event_loop
            )

        except ImportError:
            # watchdog not installed yet — will be fixed by requirements update
            asyncio.run_coroutine_threadsafe(
                broker.publish(Event(
                    event_type="agent_thought",
                    source="watchdog_agent",
                    data={"text": "Watchdog library not installed. Run: pip install watchdog. Falling back to passive mode."}
                )),
                self._event_loop
            )

    def _on_file_event(self, event_type: str, file_path: str):
        """Called from watchdog thread — bridge to asyncio event loop."""
        if not self.running:
            return
        is_suspicious, reason = _is_suspicious(file_path)
        if is_suspicious:
            asyncio.run_coroutine_threadsafe(
                self._publish_malware_alert(file_path, event_type, reason, platform="windows"),
                self._event_loop
            )

    # ── SSH / Linux / Parrot OS Polling (remote via SSH adapter) ─────────────
    async def _ssh_poll_loop(self):
        """
        Polls Linux target's filesystem via SSH every 60 seconds.
        Checks all LINUX_WATCH_PATHS for recently created/modified files.
        Ported from Lhedge's detect_malware.py watchdog pattern — adapted for SSH.
        """
        await broker.publish(Event(
            event_type="agent_thought",
            source="watchdog_agent",
            data={"text": f"SSH Watchdog polling {len(LINUX_WATCH_PATHS)} Linux/Parrot OS malware hotspot directories every 60s"}
        ))

        poll_interval = 60  # seconds
        try:
            while self.running:
                await self._poll_linux_paths()
                await asyncio.sleep(poll_interval)
        except asyncio.CancelledError:
            pass

    async def _poll_linux_paths(self):
        """Checks each Linux watch path for files modified in the last 2 minutes."""
        try:
            for path in LINUX_WATCH_PATHS:
                try:
                    recent_files = await self.server.get_modified_files(path, minutes=2)
                    for file_meta in recent_files:
                        file_path = file_meta.get("path", "")
                        is_suspicious, reason = _is_suspicious(file_path)
                        if is_suspicious:
                            await self._publish_malware_alert(
                                file_path, "created/modified", reason, platform="linux"
                            )
                except Exception:
                    pass  # Path doesn't exist on this target — skip silently
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="watchdog_agent",
                data={"text": f"SSH filesystem poll error: {e}"}
            ))

    # ── Common alert publisher ────────────────────────────────────────────────
    async def _publish_malware_alert(self, file_path: str, event_type: str,
                                     reason: str, platform: str):
        """Publishes a malware detection as a log_alert into the agent pipeline."""
        msg = (
            f"[{platform.upper()}] Malware indicator {event_type}: "
            f"'{os.path.basename(file_path)}' — {reason}"
        )

        # Raw log line for the left panel stream
        await broker.publish(Event(
            event_type="log_line",
            source="host_watchdog",
            data={"line": f"[WATCHDOG] {msg}", "type": "watchdog"}
        ))

        # Alert into the pipeline: Scanner → Classifier → Forensics → Response
        await broker.publish(Event(
            event_type="log_alert",
            source="watchdog_agent",
            severity="high",
            data={
                "ip": "127.0.0.1",  # filesystem events are local
                "message": msg,
                "alert_type": "malware_file_detected",
                "details": {
                    "file_path": file_path,
                    "event_type": event_type,
                    "reason": reason,
                    "platform": platform,
                    "watch_paths": LINUX_WATCH_PATHS if platform == "linux" else get_windows_watch_paths()
                }
            }
        ))

        await broker.publish(Event(
            event_type="agent_thought",
            source="watchdog_agent",
            data={"text": f"🚨 Malware alert: {msg}. Forwarding to Threat Classifier."}
        ))
