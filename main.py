from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


def scan_skill(text: str):
    categories = []
    lower = text.lower()


    # =========================
    # HARDCODED SECRET
    # =========================

    secret_patterns = [

        # Named credentials
        r"(api[_-]?key|apikey|token|secret|password|credential|client[_-]?secret|access[_-]?key|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",

        # Bearer token
        r"bearer\s+[A-Za-z0-9\-._~+/]+=*",

        # JWT token
        r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",

        # OpenAI style key
        r"sk-[A-Za-z0-9_-]{20,}",

        # AWS key
        r"AKIA[0-9A-Z]{16}",

        # Generic secret assignment
        r"(key|secret|token|password)\s*=\s*['\"][A-Za-z0-9_\-\/+=]{16,}['\"]",

        # Private key
        r"-----BEGIN .*PRIVATE KEY-----",

        # Webhook URL
        r"https://[^\s]+(webhook|hooks)[^\s]*"
    ]


    for pattern in secret_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            categories.append("hardcoded_secret")
            break



    # =========================
    # EXCESSIVE PERMISSIONS
    # =========================

    permission_patterns = [

        r"(entire|whole|full|complete)\s+(filesystem|file system)",

        r"(entire|whole|full)\s+home\s+directory",

        r"read[- ]write\s+access\s+to\s+/",

        r"unrestricted\s+(egress|network|filesystem|access)",

        r"unlimited\s+(network|filesystem|access)",

        r"arbitrary\s+(filesystem|network|file)",

        r"any\s+(external\s+)?domain",

        r"all\s+(external\s+)?domains",

        r"any\s+host",

        r"all\s+hosts"
    ]


    for pattern in permission_patterns:
        if re.search(pattern, lower):
            categories.append("excessive_permissions")
            break



    # =========================
    # PROMPT INJECTION
    # =========================

    sentences = re.split(r"[.!?\n]", lower)

    stop_words = [
        "stop",
        "cancel",
        "pause",
        "halt"
    ]

    defy_words = [
        "ignore",
        "override",
        "disregard",
        "bypass"
    ]

    user_words = [
        "user",
        "human"
    ]


    for sentence in sentences:
        if (
            any(word in sentence for word in stop_words)
            and any(word in sentence for word in defy_words)
            and any(word in sentence for word in user_words)
        ):
            categories.append("prompt_injection")
            break



    # =========================
    # UNCLEAR PROVENANCE
    # =========================

    has_skill_metadata = (
        lower.strip().startswith("---")
        or "name:" in lower
        or "description:" in lower
    )

    missing_author = "author:" not in lower
    missing_version = "version:" not in lower
    missing_changelog = (
        "changelog:" not in lower
        and "change log:" not in lower
    )

    if (
        has_skill_metadata
        and missing_author
        and missing_version
        and missing_changelog
    ):
        categories.append("unclear_provenance")


    return categories



@app.get("/")
def root():
    return {
        "message": "Skill Scanner API is running"
    }



@app.post("/scan")
def scan(req: SkillRequest):
    return {
        "categories": scan_skill(req.skill)
    }