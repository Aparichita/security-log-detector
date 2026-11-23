"""Runtime configuration for source paths and rule thresholds."""
from __future__ import annotations
import os
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATASETS_DIR = BASE_DIR / "datasets"

@dataclass(frozen=True)
class Settings:
    source: str = os.getenv("LOG_SOURCE", "synthetic").lower()
    openssh_path: Path = Path(os.getenv("OPENSSH_LOG_PATH", str(DATASETS_DIR / "openssh" / "OpenSSH_2k.log")))
    openssh_year: int = int(os.getenv("OPENSSH_YEAR", "2025"))
    nasa_july_path: Path = Path(os.getenv("NASA_JULY_LOG_PATH", str(DATASETS_DIR / "nasa" / "NASA_access_log_Jul95")))
    nasa_august_path: Path = Path(os.getenv("NASA_AUGUST_LOG_PATH", str(DATASETS_DIR / "nasa" / "NASA_access_log_Aug95")))
    failed_threshold: int = int(os.getenv("FAILED_LOGIN_THRESHOLD", "5"))
    failed_window: timedelta = timedelta(seconds=int(os.getenv("FAILED_LOGIN_WINDOW_SECONDS", "120")))
    request_threshold: int = int(os.getenv("REQUEST_BURST_THRESHOLD", "100"))
    request_window: timedelta = timedelta(seconds=int(os.getenv("REQUEST_BURST_WINDOW_SECONDS", "60")))

settings = Settings()
