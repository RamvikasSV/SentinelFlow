import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.config import settings
from backend.broker import broker, Event
from backend.simulator import SimulatedServer, LogGenerator
from backend.agents.scanner import LogScannerAgent
from backend.agents.classifier import ThreatClassifierAgent
from backend.agents.forensics import ForensicInvestigatorAgent
from backend.agents.response import ResponseAgent
from backend.agents.coordinator import CrewCoordinatorAgent
from backend.agents.watchdog_agent import WatchdogFilesystemAgent  # Ported from Lhedge
from backend.notifier import ForensicNotifier                       # Ported from Lhedge
from backend.user_registry import UserRegistry

# Initialize shared components
server = None
log_generator = None
scanner_agent = None
classifier_agent = None
forensics_agent = None
response_agent = None
coordinator_agent = None
watchdog_agent = None    # Lhedge: real-time filesystem malware monitor
notifier = None          # Lhedge: email forensic report notifier
user_registry = None

active_websockets: List[WebSocket] = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manages the startup and shutdown cycles of the security agent crew.
    """
    global server, log_generator, scanner_agent, classifier_agent, forensics_agent, response_agent, coordinator_agent, watchdog_agent, notifier, user_registry
    
    # Initialize User Registry
    user_registry = UserRegistry()

    # 1. Initialize host server connection adapter
    if settings.system_mode == "ssh":
        try:
            from backend.ssh_adapter import SSHServerAdapter
            server = SSHServerAdapter()
            # Test connection
            await server.get_processes()
            print(f"Connected to remote target server via SSH: {settings.ssh_host}")
        except Exception as e:
            print(f"Error connecting to SSH host: {e}. Falling back to Simulated Server Mode.")
            server = SimulatedServer()
            settings.system_mode = "simulation"
    else:
        server = SimulatedServer()
        log_generator = LogGenerator(server)

    # 2. Instantiate agents
    scanner_agent    = LogScannerAgent()
    classifier_agent = ThreatClassifierAgent()
    forensics_agent  = ForensicInvestigatorAgent(server)
    response_agent   = ResponseAgent(server)
    coordinator_agent = CrewCoordinatorAgent(server)
    watchdog_agent   = WatchdogFilesystemAgent(server)  # Lhedge: malware filesystem watcher
    notifier         = ForensicNotifier()               # Lhedge: email report notifier

    # 3. Start background processes
    await scanner_agent.start()
    await classifier_agent.start()
    await forensics_agent.start()
    await response_agent.start()
    await watchdog_agent.start()  # Lhedge: filesystem malware watcher
    await notifier.start()        # Lhedge: email forensic report notifier
    
    if settings.system_mode == "simulation" and log_generator:
        await log_generator.start()

    # 4. Spawn background worker to push broker events to all active WebSockets
    ws_broadcast_task = asyncio.create_task(broadcast_broker_events())
    
    print("==================================================")
    print(f"Cyber Agent Incident Response System successfully armed!")
    print(f"Server Adapter Mode: {settings.system_mode.upper()}")
    print(f"Access the UI at: http://localhost:{settings.port}")
    print("==================================================")

    yield

    # Shutdown sequence
    print("Disarming Cyber Agent Incident Response System...")
    ws_broadcast_task.cancel()
    
    if settings.system_mode == "simulation" and log_generator:
        await log_generator.stop()
        
    await scanner_agent.stop()
    await classifier_agent.stop()
    await forensics_agent.stop()
    await response_agent.stop()
    await watchdog_agent.stop()   # Lhedge: filesystem watcher
    await notifier.stop()         # Lhedge: email notifier
    print("Incident Response Crew shut down cleanly.")


app = FastAPI(lifespan=lifespan, title="Cyber Agent - Multi-Agent Incident Response")

# WebSocket broadcaster
async def broadcast_broker_events():
    """Listens to the broker wildcard channel and pushes all events to active WebSockets."""
    event_queue = broker.subscribe("*")
    try:
        while True:
            event: Event = await event_queue.get()
            # Push to all connected websockets
            if active_websockets:
                payload = event.model_dump()
                # Run concurrent sends
                await asyncio.gather(
                    *[send_ws_json(ws, payload) for ws in active_websockets],
                    return_exceptions=True
                )
            event_queue.task_done()
    except asyncio.CancelledError:
        pass
    finally:
        broker.unsubscribe("*", event_queue)

async def send_ws_json(ws: WebSocket, payload: dict):
    try:
        await ws.send_json(payload)
    except Exception:
        # Client likely disconnected, will be cleaned up by WebSocket handler
        pass

# REST Endpoints
@app.get("/api/state")
async def get_state():
    """Returns the current target host server state metrics."""
    global server
    if not server:
        raise HTTPException(status_code=503, detail="Server adapter not initialized")
    
    try:
        processes = await server.get_processes()
        connections = await server.get_active_connections()
        blocked_ips = list(server.blocked_ips) if hasattr(server, "blocked_ips") else []
        return {
            "mode": settings.system_mode,
            "blocked_ips": blocked_ips,
            "processes": processes,
            "connections": connections
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/firewall/unblock/{ip}")
async def post_unblock_ip(ip: str):
    """API endpoint to manually unblock an IP from the firewall."""
    global server
    if not server:
        raise HTTPException(status_code=503, detail="Server adapter not initialized")
    
    try:
        success = await server.unblock_ip(ip)
        if success:
            return {"status": "success", "message": f"IP {ip} unblocked successfully"}
        else:
            return {"status": "error", "message": f"IP {ip} is not currently blocked"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/simulate/{attack_type}")
async def post_simulate_attack(attack_type: str):
    """API endpoint to trigger simulated cyber attack events."""
    global log_generator
    if settings.system_mode != "simulation" or not log_generator:
        raise HTTPException(status_code=400, detail="Attack simulation is only available in SIMULATION mode.")
    
    valid_attacks = ["ssh_brute_force", "web_shell", "sudo_hijack"]
    if attack_type not in valid_attacks:
        raise HTTPException(status_code=400, detail=f"Invalid attack type. Choose from: {valid_attacks}")
    
    await log_generator.trigger_attack(attack_type)
    return {"status": "success", "message": f"Launched attack simulation: {attack_type}"}

class UserRegistrationSchema(BaseModel):
    name: str
    email: str

@app.get("/api/users")
async def get_users():
    """Returns the list of registered notification recipients."""
    global user_registry
    if not user_registry:
        raise HTTPException(status_code=503, detail="User registry not initialized")
    return user_registry.get_users()

@app.post("/api/users")
async def post_register_user(user: UserRegistrationSchema):
    """Registers a new notification recipient."""
    global user_registry
    if not user_registry:
        raise HTTPException(status_code=503, detail="User registry not initialized")
    
    success = user_registry.add_user(user.email, user.name)
    if success:
        return {"status": "success", "message": f"Successfully registered {user.name} ({user.email})"}
    else:
        raise HTTPException(status_code=400, detail="Invalid email address or recipient already registered")

@app.delete("/api/users/{email}")
async def delete_register_user(email: str):
    """Deletes a registered recipient by email."""
    global user_registry
    if not user_registry:
        raise HTTPException(status_code=503, detail="User registry not initialized")
    
    success = user_registry.remove_user(email)
    if success:
        return {"status": "success", "message": f"Successfully removed recipient: {email}"}
    else:
        raise HTTPException(status_code=404, detail="Recipient not found")

# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    global coordinator_agent
    await websocket.accept()
    active_websockets.append(websocket)
    
    # Broadcast current state upon client connection
    try:
        # Feed recent log files cache if in simulation mode
        history = await broker.get_history(limit=50)
        for event in history:
            await websocket.send_json(event.model_dump())
            
        while True:
            # Handle incoming WebSocket commands from chat panel
            data = await websocket.receive_json()
            if data.get("action") == "chat_command":
                user_msg = data.get("message", "")
                if user_msg:
                    # Coordinate user queries in a background task so it doesn't block the socket loop
                    asyncio.create_task(coordinator_agent.handle_user_message(user_msg))
                    
    except WebSocketDisconnect:
        active_websockets.remove(websocket)
    except Exception as e:
        print(f"WebSocket Error: {e}")
        if websocket in active_websockets:
            active_websockets.remove(websocket)


# Mount UI static folder (Mount this at root but after specific API/WS routes)
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
else:
    print(f"Warning: Frontend directory not found at {frontend_dir}. Web UI will be unavailable.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=settings.host, port=settings.port, reload=False)
