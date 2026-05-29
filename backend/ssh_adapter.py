import asyncio
import ipaddress
import re
from typing import List, Dict, Any, Set
import paramiko
from backend.config import settings
from backend.simulator import ServerAdapter

class SSHServerAdapter(ServerAdapter):
    def __init__(self):
        self.blocked_ips: Set[str] = set()

    def _get_ssh_client(self) -> paramiko.SSHClient:
        """Helper to create and authenticate a new Paramiko SSH Client."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if not settings.ssh_host:
            raise ValueError("SSH_HOST configuration is empty.")
            
        if settings.ssh_key_path:
            client.connect(
                hostname=settings.ssh_host,
                port=settings.ssh_port,
                username=settings.ssh_username,
                key_filename=settings.ssh_key_path,
                timeout=5
            )
        else:
            client.connect(
                hostname=settings.ssh_host,
                port=settings.ssh_port,
                username=settings.ssh_username,
                password=settings.ssh_password,
                timeout=5
            )
        return client

    def _sync_run_command(self, cmd: str) -> str:
        """Executes a command synchronously over SSH."""
        client = self._get_ssh_client()
        try:
            stdin, stdout, stderr = client.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            out = stdout.read().decode('utf-8', errors='ignore')
            err = stderr.read().decode('utf-8', errors='ignore')
            
            # Note: some commands returning non-zero is expected (e.g. grep finding nothing), 
            # so we only raise if stderr contains actual command errors or connection fails.
            if exit_status != 0 and err.strip():
                raise Exception(f"Command failed (exit code {exit_status}): {err}")
            return out
        finally:
            client.close()

    async def _run_command(self, cmd: str) -> str:
        """Executes a command asynchronously over SSH using a thread pool."""
        return await asyncio.to_thread(self._sync_run_command, cmd)

    # --- Sanitization Helpers ---
    def _sanitize_ip(self, ip: str) -> str:
        """Validates that the input is a valid IPv4 or IPv6 address to prevent command injection."""
        ip_clean = ip.strip()
        # Parse to trigger ValueError if invalid
        ip_obj = ipaddress.ip_address(ip_clean)
        return str(ip_obj)

    def _sanitize_pid(self, pid: int) -> int:
        """Validates PID is a positive integer."""
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError(f"Invalid process PID: {pid}")
        return pid

    def _sanitize_path(self, path: str) -> str:
        """Filters paths to prevent path traversal or shell concatenation injections."""
        cleaned = path.strip()
        # Disallow command separator characters
        if any(char in cleaned for char in [";", "&", "|", "$", "`", "<", ">", "\n", "\r"]):
            raise ValueError("Forbidden shell command characters in path.")
        return cleaned

    # --- Adapter Interface Implementation ---
    async def get_processes(self) -> List[Dict[str, Any]]:
        """Queries running processes using standard Linux ps tools."""
        cmd = "ps -eo pid,user,pcpu,pmem,args --no-headers"
        output = await self._run_command(cmd)
        
        processes = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            parts = re.split(r'\s+', line, maxsplit=4)
            if len(parts) >= 5:
                try:
                    processes.append({
                        "pid": int(parts[0]),
                        "user": parts[1],
                        "cpu": float(parts[2]),
                        "mem": float(parts[3]),
                        "cmd": parts[4]
                    })
                except ValueError:
                    # Skip header parsing failures or weird lines
                    continue
        return processes

    async def get_active_connections(self) -> List[Dict[str, Any]]:
        """Queries TCP socket connections using ss tool."""
        # Grab established and listening TCP sockets
        cmd = "ss -t -a -n"
        output = await self._run_command(cmd)
        
        connections = []
        lines = output.strip().split("\n")
        if not lines:
            return connections
            
        # Parse output headers: State Recv-Q Send-Q Local Address:Port Peer Address:Port
        # Skip header
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = re.split(r'\s+', line)
            if len(parts) >= 5:
                # ss outputs columns like: ESTAB 0 0 192.168.1.100:22 192.168.1.15:49500
                state = parts[0]
                local = parts[3]
                remote = parts[4]
                connections.append({
                    "proto": "tcp",
                    "local": local,
                    "remote": remote,
                    "state": state
                })
        return connections

    async def get_modified_files(self, path: str, minutes: int = 10) -> List[Dict[str, Any]]:
        """Finds recently modified files using the find utility."""
        clean_path = self._sanitize_path(path)
        # Use find to locate files modified in last X minutes and print: path|mtime|size|user
        cmd = f'find {clean_path} -type f -mmin -{minutes} -printf "%p|%T@|%s|%u\\n" 2>/dev/null'
        
        output = await self._run_command(cmd)
        
        files = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                try:
                    files.append({
                        "path": parts[0],
                        "mtime": float(parts[1]),
                        "size": int(parts[2]),
                        "user": parts[3]
                    })
                except ValueError:
                    continue
        return files

    async def block_ip(self, ip: str) -> bool:
        """Blocks IP address using host ufw or iptables rules."""
        clean_ip = self._sanitize_ip(ip)
        
        if clean_ip in self.blocked_ips:
            return False
            
        # Try UFW first, fall back to iptables
        try:
            await self._run_command(f"sudo ufw deny from {clean_ip}")
        except Exception:
            # Fallback to iptables
            await self._run_command(f"sudo iptables -A INPUT -s {clean_ip} -j DROP")
            
        self.blocked_ips.add(clean_ip)
        return True

    async def unblock_ip(self, ip: str) -> bool:
        """Unblocks IP address removing matching denial rules."""
        clean_ip = self._sanitize_ip(ip)
        
        if clean_ip not in self.blocked_ips:
            return False
            
        try:
            await self._run_command(f"sudo ufw delete deny from {clean_ip}")
        except Exception:
            # Fallback to iptables deletion
            await self._run_command(f"sudo iptables -D INPUT -s {clean_ip} -j DROP")
            
        self.blocked_ips.remove(clean_ip)
        return True

    async def kill_process(self, pid: int) -> bool:
        """Terminates process using sudo kill."""
        clean_pid = self._sanitize_pid(pid)
        try:
            await self._run_command(f"sudo kill -9 {clean_pid}")
            return True
        except Exception:
            return False

    async def delete_file(self, file_path: str) -> bool:
        """Quarantines file by moving it to /tmp/quarantine/ or removing it."""
        clean_path = self._sanitize_path(file_path)
        try:
            # Create quarantine folder first
            await self._run_command("sudo mkdir -p /tmp/quarantine")
            # Move to quarantine instead of outright deleting (safer!)
            filename = clean_path.split("/")[-1]
            await self._run_command(f"sudo mv {clean_path} /tmp/quarantine/{filename}_quarantined")
            return True
        except Exception:
            # Fallback to direct rm if mv fails
            try:
                await self._run_command(f"sudo rm -f {clean_path}")
                return True
            except Exception:
                return False
