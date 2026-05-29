import asyncio
import sys
from pathlib import Path

# Add root folder to python path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from backend.config import settings
from backend.broker import broker, Event
from backend.simulator import SimulatedServer, LogGenerator
from backend.agents.scanner import LogScannerAgent
from backend.agents.classifier import ThreatClassifierAgent
from backend.agents.forensics import ForensicInvestigatorAgent
from backend.agents.response import ResponseAgent

async def run_integration_test():
    print("[TEST] Starting End-to-End Incident Response Integration Test...")
    
    # Force simulation mode for testing
    settings.system_mode = "simulation"
    
    # 1. Initialize server and agents
    server = SimulatedServer()
    log_gen = LogGenerator(server)
    
    scanner = LogScannerAgent()
    classifier = ThreatClassifierAgent()
    forensics = ForensicInvestigatorAgent(server)
    response = ResponseAgent(server)
    
    # 2. Subscribe to broker to track pipeline progression
    flow_tracker = {
        "log_alert": False,
        "threat_classification": False,
        "forensic_investigation": False,
        "remediation": False
    }
    
    event_queue = broker.subscribe("*")
    
    # Start agents
    await scanner.start()
    await classifier.start()
    await forensics.start()
    await response.start()
    await log_gen.start()
    
    print("[TEST] All agents started. Injected standard noise...")
    await asyncio.sleep(2)
    
    # 3. Trigger SSH Brute Force Attack
    print("[TEST] Triggering SSH Brute Force Attack simulation...")
    await log_gen.trigger_attack("ssh_brute_force")
    
    # 4. Monitor broker events with a timeout of 15 seconds
    timeout = 15.0
    start_time = asyncio.get_event_loop().time()
    
    try:
        while True:
            current_time = asyncio.get_event_loop().time()
            if current_time - start_time > timeout:
                print("[TEST] Timeout: The incident response pipeline did not complete in 15 seconds.")
                break
                
            try:
                # Wait for next event with short timeout to check loop condition
                event: Event = await asyncio.wait_for(event_queue.get(), timeout=1.0)
                
                # Check for agent thoughts to log test progress
                if event.event_type == "agent_thought":
                    print(f"   [Agent Thought - {event.source}]: {event.data.get('text')}")
                    
                # Track pipeline stages
                if event.event_type in flow_tracker:
                    flow_tracker[event.event_type] = True
                    print(f"[TEST] Captured pipeline stage: {event.event_type.upper()}")
                    
                event_queue.task_done()
            except asyncio.TimeoutError:
                pass
                
            # If all stages completed and IP is blocked, we can stop
            if all(flow_tracker.values()) and len(server.blocked_ips) > 0:
                print("[TEST] Success: End-to-end incident response pipeline completed successfully!")
                break
    finally:
        # Cleanup
        broker.unsubscribe("*", event_queue)
        await log_gen.stop()
        await scanner.stop()
        await classifier.stop()
        await forensics.stop()
        await response.stop()
        
    # 5. Assert final results
    print("\n--- Final Test Audit Report ---")
    print(f"Log Alerts Created:      {'Yes' if flow_tracker['log_alert'] else 'No'}")
    print(f"Threats Classified:      {'Yes' if flow_tracker['threat_classification'] else 'No'}")
    print(f"Forensics Run:           {'Yes' if flow_tracker['forensic_investigation'] else 'No'}")
    print(f"Remediation Triggered:   {'Yes' if flow_tracker['remediation'] else 'No'}")
    print(f"Blocked IPs in Firewall: {list(server.blocked_ips)}")
    
    if all(flow_tracker.values()) and len(server.blocked_ips) > 0:
        print("\n[TEST] INTEGRATION TEST PASSED!")
        return True
    else:
        print("\n[TEST] INTEGRATION TEST FAILED!")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_integration_test())
    sys.exit(0 if success else 1)
