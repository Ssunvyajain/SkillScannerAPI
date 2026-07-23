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
        r"(api[_-]?key|apikey|token|secret|password|credential)\s*[:=]\s*['\"][^'\"]{8,}['\"]",

        # OpenAI style keys
        r"sk-[A-Za-z0-9_-]{20,}",

        # AWS keys
        r"AKIA[0-9A-Z]{16}",

        # Private keys
        r"-----BEGIN .*PRIVATE KEY-----",

        # Webhook URLs containing secrets
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
    # Only check actual skill metadata/frontmatter.
    # Do NOT flag normal text.

    looks_like_skill = (
        "name:" in lower
        or "description:" in lower
        or "---" in lower
    )

    missing_provenance = (
        "author:" not in lower
        or "version:" not in lower
    )

    if looks_like_skill and missing_provenance:
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