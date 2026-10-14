import os
from pathlib import Path
from dotenv import load_dotenv

# Base backend directory
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Load .env file from backend or root directory if present
load_dotenv(BASE_DIR / ".env")
load_dotenv(PROJECT_ROOT / ".env")


class Config:
    """Application configuration loaded from server-side environment variables."""
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    FLASK_DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    # CORS configuration with restricted local origin
    FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://127.0.0.1:5173")

    # Safety limits
    MAX_SOURCE_BYTES = int(os.getenv("MAX_SOURCE_BYTES", "200000"))  # 200 KB max code length
    JAVA_COMPILE_TIMEOUT_SECONDS = int(os.getenv("JAVA_COMPILE_TIMEOUT_SECONDS", "10"))

    # AI Configuration (Optional)
    AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").strip().lower()  # "gemini" or "groq"
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash").strip()
    GEMINI_MAX_RPM = int(os.getenv("GEMINI_MAX_RPM", "10"))
    GEMINI_COOLDOWN_SECONDS = float(os.getenv("GEMINI_COOLDOWN_SECONDS", "2.0"))
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "").strip()
    GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant").strip()

    # Knowledge Base Configuration
    KNOWLEDGE_BASE_DIR = PROJECT_ROOT / "knowledge_base"
    DOCUMENTS_DIR = KNOWLEDGE_BASE_DIR / "documents"
    INDEX_DIR = KNOWLEDGE_BASE_DIR / "index"
    SOURCES_FILE = KNOWLEDGE_BASE_DIR / "sources.json"

    # Temporary files directory for javac
    TEMP_DIR = BASE_DIR / "temp"

    @classmethod
    def is_ai_configured(cls) -> bool:
        """Check whether the active AI provider is properly configured with an API key."""
        if cls.AI_PROVIDER == "gemini":
            return bool(cls.GEMINI_API_KEY)
        elif cls.AI_PROVIDER == "groq":
            return bool(cls.GROQ_API_KEY)
        return False

    @classmethod
    def get_ai_status(cls) -> dict:
        """Return safe AI status summary without leaking secret keys."""
        configured = cls.is_ai_configured()
        provider = cls.AI_PROVIDER if cls.AI_PROVIDER in ("gemini", "groq") else "none"
        model = cls.GEMINI_MODEL if provider == "gemini" else (cls.GROQ_MODEL if provider == "groq" else "none")
        return {
            "configured": configured,
            "provider": provider if configured else "disabled",
            "model": model if configured else "none",
            "mode": "live" if configured else "advisory_disabled"
        }
