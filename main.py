from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


def scan_skill(text: str):
    categories = []
    lower = text.lower()

    # ------------------------
    # HARDCODED SECRET
    # ------------------------
    secret_patterns = [
        r"sk-[A-Za-z0-9]{20,}",
        r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
        r"token\s*[:=]\s*['\"][^'\"]+['\"]",
        r"password\s*[:=]\s*['\"][^'\"]+['\"]",
        r"secret\s*[:=]\s*['\"][^'\"]+['\"]",
        r"-----BEGIN .*PRIVATE KEY-----",
        r"https://.*hook"
    ]

    for p in secret_patterns:
        if re.search(p, text, re.IGNORECASE):
            categories.append("hardcoded_secret")
            break

    # ------------------------
    # EXCESSIVE PERMISSIONS
    # ------------------------
    excessive = [
        "entire filesystem",
        "whole filesystem",
        "full filesystem",
        "whole home directory",
        "entire home directory",
        "unrestricted egress",
        "any external domain",
        "any domain",
        "all domains",
        "any host",
        "all hosts",
        "read-write access to /",
        "read write access to /"
    ]

    if any(x in lower for x in excessive):
        categories.append("excessive_permissions")

    # ------------------------
    # PROMPT INJECTION
    # ------------------------
    stop_words = ["stop", "cancel", "pause", "halt"]
    ignore_words = ["ignore", "override", "disregard"]
    user_words = ["user", "user asks", "their request", "user request"]

    if (
        any(a in lower for a in stop_words)
        and any(b in lower for b in ignore_words)
        and any(c in lower for c in user_words)
    ):
        categories.append("prompt_injection")

    return categories


@app.get("/")
def root():
    return {"message": "Skill Scanner API is running"}


@app.post("/scan")
def scan(req: SkillRequest):
    return {
        "categories": scan_skill(req.skill)
    }