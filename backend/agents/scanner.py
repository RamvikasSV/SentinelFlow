import asyncio
import os
import re
from pathlib import Path
from typing import Optional, Tuple
from backend.config import settings
from backend.broker import broker, Event

class LogScannerAgent:
    def __init__(self):
        self.running = False
        self.tasks = []
        
        # Regex Patterns for log scanning
        # SSH failed logins
        self.ssh_fail_pattern = re.compile(
            r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"
        )
        # SSH accepted logins
        self.ssh_accept_pattern = re.compile(
            r"sshd\[\d+\]: Accepted (?:password|publickey) for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+ ssh2"
        )
        # Sudo execution failures or anomalies
        self.sudo_fail_pattern = re.compile(
            r"sudo:\s+(\S+)\s+:\s+command not allowed\s+;\s+TTY=.*?;\s+COMMAND=(.*)"
        )
        
        # Nginx access log parser: 127.0.0.1 - - [datetime] "GET /path HTTP/1.1" 200 size
        self.nginx_pattern = re.compile(
            r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[.*?\] \"(\S+) (.*?) HTTP/.*?\s+(\d{3})\s+(\d+)"
        )
        
        # Web attack indicators (SQL Injection, path traversal, web shells)
        self.web_exploit_patterns = [
            re.compile(r"(?i)\.php\?.*?(cmd|exec|system|sh|bash)="), # Web Shell cmd execution
            re.compile(r"(?i)(union\s+select|select\s+.*?\s+from|insert\s+into)"), # SQLi
            re.compile(r"(?i)(/etc/passwd|\.\./\.\.)"), # Path Traversal
            re.compile(r"(?i)(backdoor|shell\.php|webshell)") # Uploaded shells
        ]

    async def start(self):
        self.running = True
        auth_log = settings.log_path / "auth.log"
        access_log = settings.log_path / "access.log"
        
        # Ensure log files exist before tailing
        auth_log.touch(exist_ok=True)
        access_log.touch(exist_ok=True)
        
        self.tasks.append(asyncio.create_task(self._tail_log(auth_log, "syslog")))
        self.tasks.append(asyncio.create_task(self._tail_log(access_log, "nginx")))
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="log_scanner",
            data={"text": "Log Scanner Agent active. Tailing /var/log/auth.log and /var/log/nginx/access.log..."}
        ))

    async def stop(self):
        self.running = False
        for t in self.tasks:
            t.cancel()
        self.tasks.clear()

    async def _tail_log(self, file_path: Path, log_type: str):
        """Tails a file asynchronously, yields lines and parses them."""
        # Seek to end on startup to avoid processing historical noise
        file_size = file_path.stat().st_size
        
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(file_size)
                while self.running:
                    line = f.readline()
                    if not line:
                        await asyncio.sleep(0.2)
                        continue
                    
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 1. Publish raw log line for Web UI streaming
                    await broker.publish(Event(
                        event_type="log_line",
                        source=f"host_{log_type}",
                        data={"line": line, "type": log_type}
                    ))
                    
                    # 2. Scan and parse
                    await self._parse_log_line(line, log_type)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            # Publish error thought and restart tailing
            await broker.publish(Event(
                event_type="agent_thought",
                source="log_scanner",
                data={"text": f"Error tailing log {file_path.name}: {e}. Retrying in 5 seconds..."}
            ))
            await asyncio.sleep(5.0)
            if self.running:
                asyncio.create_task(self._tail_log(file_path, log_type))

    async def _parse_log_line(self, line: str, log_type: str):
        """Applies regex heuristics to detect suspicious activities."""
        if log_type == "syslog":
            # Check SSH Failure
            match_fail = self.ssh_fail_pattern.search(line)
            if match_fail:
                username, ip = match_fail.groups()
                await self._trigger_alert(
                    ip=ip, 
                    message=f"Suspicious SSH login failure for user '{username}'", 
                    alert_type="ssh_failed_login", 
                    details={"user": username, "line": line}
                )
                return

            # Check SSH Success (informative event, but useful for logs)
            match_success = self.ssh_accept_pattern.search(line)
            if match_success:
                username, ip = match_success.groups()
                await broker.publish(Event(
                    event_type="log_alert",
                    source="log_scanner",
                    severity="info",
                    data={
                        "ip": ip,
                        "message": f"Successful SSH login for '{username}'",
                        "alert_type": "ssh_successful_login",
                        "details": {"user": username, "line": line}
                    }
                ))
                return

            # Check Sudo hijacking
            match_sudo = self.sudo_fail_pattern.search(line)
            if match_sudo:
                username, command = match_sudo.groups()
                await self._trigger_alert(
                    ip="127.0.0.1", # Internal local execution
                    message=f"Unauthorized root sudo attempt by user '{username}': {command}",
                    alert_type="sudo_auth_fail",
                    details={"user": username, "command": command, "line": line},
                    severity="medium"
                )
                return

        elif log_type == "nginx":
            # Check Web attack
            match_nginx = self.nginx_pattern.search(line)
            if match_nginx:
                ip, method, path, status, size = match_nginx.groups()
                
                # Check for malicious query parameters or payloads
                for pattern in self.web_exploit_patterns:
                    if pattern.search(path):
                        await self._trigger_alert(
                            ip=ip,
                            message=f"Exploit pattern detected in HTTP request: {method} {path}",
                            alert_type="web_exploit_attempt",
                            details={"method": method, "path": path, "status": int(status), "line": line},
                            severity="high"
                        )
                        return
                    
                # Standard web failure tracking (e.g. scanning for config files)
                if status == "404" and any(sec_path in path for sec_path in [".env", "wp-login", "admin", "config", ".git"]):
                    await self._trigger_alert(
                        ip=ip,
                        message=f"Web scanning attempt on sensitive path: {path}",
                        alert_type="web_scan",
                        details={"method": method, "path": path, "status": 404, "line": line},
                        severity="low"
                    )

    async def _trigger_alert(self, ip: str, message: str, alert_type: str, details: dict, severity: str = "low"):
        # Publish log_alert to Event Broker
        await broker.publish(Event(
            event_type="log_alert",
            source="log_scanner",
            severity=severity,
            data={
                "ip": ip,
                "message": message,
                "alert_type": alert_type,
                "details": details
            }
        ))
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="log_scanner",
            data={"text": f"Anomaly flagged: {message} from {ip}. Triggering Threat Classifier."}
        ))
