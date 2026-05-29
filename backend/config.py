import os
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load .env file
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

class AppSettings(BaseModel):
    system_mode: str = Field(default="simulation", pattern="^(simulation|ssh)$")
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    
    # Gemini Configuration
    gemini_api_key: str = Field(default="")
    
    # SSH Server Target configuration (optional, validated if mode is 'ssh')
    ssh_host: str = Field(default="")
    ssh_port: int = Field(default=22)
    ssh_username: str = Field(default="")
    ssh_password: str = Field(default="")
    ssh_key_path: str = Field(default="")

    # ── Ported from Lhedge (send_mail.py) ── Email notification settings ──────
    email_sender:   str = Field(default="")       # e.g. yourname@gmail.com
    email_password: str = Field(default="")       # Gmail App Password (16 chars)
    email_receiver: str = Field(default="")       # where to send reports (can be same as sender)
    smtp_host:      str = Field(default="smtp.gmail.com")
    smtp_port:      int = Field(default=465)      # SSL port
    
    # Logs directory
    log_dir: str = Field(default="logs")

    @property
    def log_path(self) -> Path:
        p = Path(self.log_dir)
        if not p.is_absolute():
            p = Path(__file__).resolve().parent.parent / p
        return p

# Instantiate settings
settings = AppSettings(
    system_mode=os.getenv("SYSTEM_MODE", "simulation"),
    host=os.getenv("HOST", "127.0.0.1"),
    port=int(os.getenv("PORT", "8000")),
    gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
    ssh_host=os.getenv("SSH_HOST", ""),
    ssh_port=int(os.getenv("SSH_PORT", "22")),
    ssh_username=os.getenv("SSH_USERNAME", ""),
    ssh_password=os.getenv("SSH_PASSWORD", ""),
    ssh_key_path=os.getenv("SSH_KEY_PATH", ""),
    log_dir=os.getenv("LOG_DIR", "logs"),
    # Lhedge email notifier
    email_sender=os.getenv("EMAIL_SENDER", ""),
    email_password=os.getenv("EMAIL_PASSWORD", ""),
    email_receiver=os.getenv("EMAIL_RECEIVER", ""),
    smtp_host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
    smtp_port=int(os.getenv("SMTP_PORT", "465")),
)

# Ensure logs directory exists
settings.log_path.mkdir(parents=True, exist_ok=True)
