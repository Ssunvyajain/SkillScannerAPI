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

        # Named secrets
        r"(api[_-]?key|apikey|token|secret|password|credential|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",

        # Environment variable style
        r"[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=\s*['\"][^'\"]{8,}['\"]",

        # Bearer tokens
        r"bearer\s+[A-Za-z0-9\-._~+/]+=*",

        # JWT
        r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",

        # OpenAI style
        r"sk-[A-Za-z0-9_-]{20,}",

        # AWS
        r"AKIA[0-9A-Z]{16}",

        # Generic secret assignment
        r"(key|secret|token|password)\s*=\s*['\"][A-Za-z0-9_\-\/+=]{16,}['\"]",

        # Private keys
        r"-----BEGIN .*PRIVATE KEY-----",

        # Webhooks containing credentials
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

        r"(entire|whole|full|complete|unrestricted|unlimited|arbitrary)\s+(filesystem|file\s*system|home\s+directory|files)",

        r"read[- ]write\s+access\s+to\s+/",

        r"(unrestricted|unlimited)\s+(egress|network|outbound|access)",

        r"(any|all)\s+(external\s+)?(domain|domains|host|hosts)",

        r"egress\s+(allowed|permitted)\s+to\s+(any|all)",

        r"access\s+to\s+the\s+(entire|whole|full)\s+(filesystem|home|files)"
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