"""
Configuration de l'application PCAP Analyzer Pro
Gestion centralisée des variables d'environnement avec Pydantic Settings
"""

import os
from pathlib import Path
from typing import Any
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator, field_validator
from functools import lru_cache


class Settings(BaseSettings):
    """Configuration de l'application avec validation Pydantic"""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application
    app_name: str = "PCAP Analyzer Pro"
    app_version: str = "1.0.0"
    debug: bool = False
    cors_origins: list[str] = ["http://localhost:8000"]
    cors_allow_credentials: bool = False
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 5
    
    # File limits
    max_file_size: int = 3221225472  # 3GB en bytes
    analysis_timeout: int = 3600  # 1 heure en secondes
    allowed_extensions: set = {".pcap", ".pcapng", ".cap"}
    
    # Redis & Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"
    
    # Logging
    log_level: str = "INFO"
    
    # Paths - Valeurs par défaut valides pour Docker et local
    upload_dir: Path = Path("/app/uploads")
    results_dir: Path = Path("/app/results")

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug_bool(cls, value: Any) -> bool:
        """Accepte des valeurs booléennes élargies pour DEBUG."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on", "debug"}:
                return True
            if lowered in {"0", "false", "no", "off", "release", "prod", "production"}:
                return False
        return bool(value)
    
    @model_validator(mode='after')
    def setup_directories(self) -> 'Settings':
        """Crée les répertoires s'ils n'existent pas après validation"""
        if os.getenv('PCAP_STORAGE') == 'vercel':
            self.upload_dir = Path('/tmp/pcap-cloud-worker/uploads')
            self.results_dir = Path('/tmp/pcap-cloud-worker/results')
            self.max_file_size = 100 * 1024 * 1024
            self.upload_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir.mkdir(parents=True, exist_ok=True)
            return self

        in_docker = Path("/.dockerenv").exists() or os.getenv("DOCKER_ENV") == "1"

        # En local, éviter les chemins /app/* qui ne sont pas accessibles.
        if str(self.upload_dir).startswith("/app") and not in_docker:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.upload_dir = base_dir / "uploads"
            self.results_dir = base_dir / "results"
        elif not self.upload_dir.exists() and not str(self.upload_dir).startswith("/app"):
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.upload_dir = base_dir / "uploads"
            self.results_dir = base_dir / "results"
        
        # Créer les répertoires avec gestion des permissions
        try:
            self.upload_dir.mkdir(parents=True, exist_ok=True)
            self.results_dir.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            # En mode lecture seule, ignorer (les répertoires existent déjà dans Docker)
            pass
        
        return self


@lru_cache()
def get_settings() -> Settings:
    """Retourne l'instance de configuration (singleton caché)"""
    return Settings()


settings = get_settings()
