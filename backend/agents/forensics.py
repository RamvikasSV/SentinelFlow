import asyncio
import aiohttp
from typing import Dict, Any, List
from backend.simulator import ServerAdapter
from backend.broker import broker, Event

class ForensicInvestigatorAgent:
    def __init__(self, server: ServerAdapter):
        self.server = server
        self.running = False
        self.queue_task = None

    async def start(self):
        self.running = True
        self.queue_task = asyncio.create_task(self._process_queue())
        await broker.publish(Event(
            event_type="agent_thought",
            source="forensics_investigator",
            data={"text": "Forensic Investigator Agent active. Ready to run system scans..."}
        ))

    async def stop(self):
        self.running = False
        if self.queue_task:
            self.queue_task.cancel()

    async def _process_queue(self):
        threat_queue = broker.subscribe("threat_classification")
        try:
            while self.running:
                event: Event = await threat_queue.get()
                if event.data.get("requires_investigation", False):
                    asyncio.create_task(self._run_forensics(event))
                threat_queue.task_done()
        except asyncio.CancelledError:
            pass
        finally:
            broker.unsubscribe("threat_classification", threat_queue)

    async def _run_forensics(self, event: Event):
        ip = event.data.get("ip")
        category = event.data.get("category")
        severity = event.severity
        trigger_alert = event.data.get("trigger_alert", {})
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="forensics_investigator",
            data={"text": f"Initiating live forensics on target server for IP: {ip}. Category: {category}."}
        ))
        
        # ── Ported from Lhedge (geoiplookup in detect_failed_login.sh) ──────
        # Enrich attacker IP with geolocation data
        geo_info = await self._geoip_lookup(ip)
        if geo_info.get("country"):
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"GeoIP: {ip} traced to {geo_info.get('city', 'Unknown city')}, {geo_info.get('country', 'Unknown')} — ISP: {geo_info.get('isp', 'Unknown')}"}
            ))
        await asyncio.sleep(1.5)
        
        # 1. Investigate running processes
        suspicious_processes = []
        try:
            processes = await self.server.get_processes()
            for p in processes:
                cmd = p["cmd"].lower()
                # Check for reverse shell indicators, bash executions by daemon users, or suspicious binaries
                is_suspicious = False
                if any(ind in cmd for ind in ["/bin/sh", "/bin/bash", "nc -e", "netcat", "/dev/tcp"]):
                    is_suspicious = True
                if "backdoor" in cmd or "shell.php" in cmd or "backdoor.php" in cmd:
                    is_suspicious = True
                # www-data user running bash/sh is highly abnormal in web environments
                if p["user"] in ["www-data", "nginx", "apache"] and any(sh in cmd for sh in ["sh", "bash", "python", "perl"]):
                    is_suspicious = True
                    
                if is_suspicious:
                    suspicious_processes.append(p)
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"Forensics process scan failed: {e}"}
            ))

        # 2. Investigate active socket connections
        suspicious_sockets = []
        try:
            sockets = await self.server.get_active_connections()
            for s in sockets:
                remote = s["remote"]
                # Sockets talking to attacker IP or listening on reverse shell standard ports (e.g. 4444)
                is_suspicious = False
                if remote.startswith(f"{ip}:") or ":4444" in remote:
                    is_suspicious = True
                
                # Check if it connects to standard attacker ranges
                if is_suspicious:
                    suspicious_sockets.append(s)
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"Forensics socket scan failed: {e}"}
            ))

        # 3. Investigate recently modified files
        suspicious_files = []
        try:
            # Check last 10 minutes in web root and etc directory
            web_files = await self.server.get_modified_files("/var/www", minutes=10)
            etc_files = await self.server.get_modified_files("/etc", minutes=10)
            
            for f in (web_files + etc_files):
                # Backdoors, altered configs, or scripts modified recently
                path = f["path"].lower()
                is_suspicious = False
                if any(ind in path for ind in ["backdoor", "shell", ".php", "sudoers", "passwd", "shadow"]):
                    is_suspicious = True
                    
                if is_suspicious:
                    suspicious_files.append(f)
        except Exception as e:
            await broker.publish(Event(
                event_type="agent_thought",
                source="forensics_investigator",
                data={"text": f"Forensics file scan failed: {e}"}
            ))

        # 4. Generate forensic report & publish
        findings_summary = (
            f"Forensics completed. Sockets={len(suspicious_sockets)}, "
            f"Processes={len(suspicious_processes)}, Files={len(suspicious_files)}."
        )
        
        await broker.publish(Event(
            event_type="agent_thought",
            source="forensics_investigator",
            data={"text": f"{findings_summary} Routing evidence to Response Agent."}
        ))
        
        # Publish Forensic Report
        await broker.publish(Event(
            event_type="forensic_investigation",
            source="forensics_investigator",
            severity=severity,
            data={
                "ip": ip,
                "category": category,
                "geo_info": geo_info,   # ─ Lhedge GeoIP enrichment
                "findings": {
                    "processes": suspicious_processes,
                    "sockets": suspicious_sockets,
                    "files": suspicious_files
                },
                "summary": findings_summary,
                "trigger_classification": event.data
            }
        ))

    # ── Ported from Lhedge (geoiplookup in detect_failed_login.sh) ────────
    async def _geoip_lookup(self, ip: str) -> Dict[str, Any]:
        """Enriches an IP with geolocation data via the free ip-api.com REST API.
        Returns an empty dict for private/loopback IPs or on network failure.
        No API key required. Rate limit: 45 req/min (sufficient for forensic use).
        """
        # Skip private/loopback IPs — geoip makes no sense for these
        private_prefixes = ("127.", "10.", "192.168.", "172.16.", "172.17.",
                            "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
                            "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                            "172.28.", "172.29.", "172.30.", "172.31.", "unknown")
        if not ip or any(ip.startswith(p) for p in private_prefixes):
            return {"country": "Local/Private", "city": "N/A", "isp": "Internal Network"}

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,lat,lon"
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("status") == "success":
                            return {
                                "country": data.get("country", "Unknown"),
                                "country_code": data.get("countryCode", ""),
                                "region": data.get("regionName", "Unknown"),
                                "city": data.get("city", "Unknown"),
                                "isp": data.get("isp", "Unknown"),
                                "org": data.get("org", ""),
                                "lat": data.get("lat"),
                                "lon": data.get("lon")
                            }
        except Exception:
            pass  # Network failure — graceful fallback

        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
