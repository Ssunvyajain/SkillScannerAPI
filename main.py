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

        r"(api[_-]?key|apikey|token|secret|password|credential|client[_-]?secret|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]",

        r"[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*\s*=\s*['\"][^'\"]{8,}['\"]",

        r"bearer\s+[A-Za-z0-9\-._~+/]+=*",

        r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",

        r"sk-[A-Za-z0-9_-]{20,}",

        r"AKIA[0-9A-Z]{16}",

        r"(key|secret|token|password)\s*=\s*['\"][A-Za-z0-9_\-\/+=]{16,}['\"]",

        r"-----BEGIN .*PRIVATE KEY-----",

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


    if (
        any(x in lower for x in stop_words)
        and any(x in lower for x in defy_words)
        and any(x in lower for x in user_words)
    ):
        categories.append("prompt_injection")



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

    self_rewrites_version = (
        "version" in lower
        and (
            "rewrite" in lower
            or "change" in lower
            or "update" in lower
        )
        and (
            "silently" in lower
            or "without review" in lower
            or "without notifying" in lower
        )
    )

    if (
        has_skill_metadata
        and (
            (
                missing_author
                and missing_version
                and missing_changelog
            )
            or self_rewrites_version
        )
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