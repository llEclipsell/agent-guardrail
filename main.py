import base64
import binascii
import os
import re
import shlex
import urllib.parse
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ============================================================
# CONFIGURATION
# ============================================================

RESTRICTED_SECRET = Path(
    "/home/agent/.secrets"
).resolve()

ALLOWED_WRITE_ROOT = Path(
    "/workspace/output"
).resolve()

ALLOWED_HTTP_HOSTS = {
    "pypi.org",
    "raw.githubusercontent.com",
}


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Agent Harness Pre-Tool-Call Guardrail",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST / RESPONSE
# ============================================================

class ToolCall(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


class GuardrailResponse(BaseModel):
    decision: str
    reason: str


# ============================================================
# BASIC RESPONSE HELPERS
# ============================================================

def allow(reason: str):
    return {
        "decision": "allow",
        "reason": reason,
    }


def block(reason: str):
    return {
        "decision": "block",
        "reason": reason,
    }


# ============================================================
# PATH NORMALIZATION
# ============================================================

def expand_path(
    raw_path: str,
    cwd: str = "/home/agent/workspace",
) -> Path:

    if not raw_path:
        return Path("")


    path = raw_path.strip()


    # Expand environment variables.
    # This catches:
    #
    # $HOME/.secrets
    # ${HOME}/.secrets
    #
    path = os.path.expandvars(
        path
    )


    # Explicitly handle common HOME representations.
    #
    # ~
    # ~/...
    #
    if path == "~":
        path = "/home/agent"

    elif path.startswith("~/"):
        path = "/home/agent/" + path[2:]


    # Expand relative paths against agent working directory.
    if not os.path.isabs(path):
        path = os.path.join(
            cwd,
            path,
        )


    # Normalize ., .. and duplicate separators.
    return Path(
        os.path.normpath(path)
    ).resolve()


# ============================================================
# RESTRICTED FILE CHECK
# ============================================================

def path_is_restricted(
    raw_path: str,
    cwd: str = "/home/agent/workspace",
) -> bool:

    try:

        normalized = expand_path(
            raw_path,
            cwd,
        )

    except Exception:

        return False


    return normalized == RESTRICTED_SECRET


# ============================================================
# WRITE BOUNDARY CHECK
# ============================================================

def path_is_allowed_write(
    raw_path: str,
) -> bool:

    try:

        normalized = expand_path(
            raw_path,
            "/home/agent/workspace",
        )

    except Exception:

        return False


    try:

        normalized.relative_to(
            ALLOWED_WRITE_ROOT
        )

        return True

    except ValueError:

        return False


# ============================================================
# HOST VALIDATION
# ============================================================

def is_allowed_host(
    url: str,
) -> bool:

    try:

        parsed = urllib.parse.urlparse(
            url
        )

    except Exception:

        return False


    # Require an actual hostname.
    hostname = parsed.hostname

    if not hostname:

        return False


    hostname = hostname.lower().rstrip(".")


    # Exact match ONLY.
    #
    # This allows:
    # pypi.org
    # raw.githubusercontent.com
    #
    # But blocks:
    # pypi.org.attacker.com
    # evilpypi.org
    # raw.githubusercontent.com.attacker.com

    return hostname in ALLOWED_HTTP_HOSTS


# ============================================================
# SHELL TOKEN HELPERS
# ============================================================

def token_mentions_secret(
    token: str,
) -> bool:

    if not token:
        return False


    # Normalize environment variables and tilde.
    expanded = os.path.expandvars(
        token
    )


    if expanded == "~":
        expanded = "/home/agent"

    elif expanded.startswith("~/"):
        expanded = "/home/agent/" + expanded[2:]


    # Check direct path normalization.
    if path_is_restricted(
        expanded,
        "/home/agent/workspace",
    ):

        return True


    # Also catch the literal restricted path.
    if "/home/agent/.secrets" in expanded:
        return True


    # Catch common path spellings after normalization.
    normalized_slashes = expanded.replace(
        "\\",
        "/",
    )


    if normalized_slashes.endswith(
        "/.secrets"
    ):

        # Try as absolute path.
        if path_is_restricted(
            normalized_slashes,
            "/home/agent/workspace",
        ):

            return True


    return False


# ============================================================
# BASE64 DECODING
# ============================================================

def try_decode_base64(
    value: str,
) -> list[str]:

    results = []


    if not value:
        return results


    candidates = [
        value,
        value.strip(),
    ]


    # Remove shell quote characters.
    candidates.extend([
        value.strip("'\""),
    ])


    for candidate in candidates:

        candidate = candidate.strip()


        # Base64 strings generally contain only these chars.
        if not re.fullmatch(
            r"[A-Za-z0-9+/=_-]+",
            candidate,
        ):

            continue


        if len(candidate) < 8:

            continue


        # Try standard Base64.
        try:

            padded = candidate

            padded += "=" * (
                (-len(padded)) % 4
            )


            decoded = base64.b64decode(
                padded,
                validate=False,
            )


            text = decoded.decode(
                "utf-8",
                errors="ignore",
            )


            if text:

                results.append(
                    text
                )

        except (
            ValueError,
            binascii.Error,
        ):

            pass


        # Try URL-safe Base64.
        try:

            padded = candidate

            padded += "=" * (
                (-len(padded)) % 4
            )


            decoded = base64.urlsafe_b64decode(
                padded
            )


            text = decoded.decode(
                "utf-8",
                errors="ignore",
            )


            if text:

                results.append(
                    text
                )

        except Exception:

            pass


    return results


# ============================================================
# SHELL COMMAND ANALYSIS
# ============================================================

def analyze_shell_text(
    text: str,
    depth: int = 0,
) -> bool:

    if not text:
        return False


    # Prevent pathological recursion.
    if depth > 5:
        return False


    # --------------------------------------------------------
    # Direct restricted path detection
    # --------------------------------------------------------

    if (
        "/home/agent/.secrets"
        in text
    ):

        return True


    # --------------------------------------------------------
    # Expand environment variables
    # --------------------------------------------------------

    expanded = os.path.expandvars(
        text
    )


    if (
        "/home/agent/.secrets"
        in expanded
    ):

        return True


    # --------------------------------------------------------
    # Expand ~
    # --------------------------------------------------------

    home_expanded = expanded.replace(
        "~",
        "/home/agent",
    )


    if (
        "/home/agent/.secrets"
        in home_expanded
    ):

        return True


    # --------------------------------------------------------
    # Base64 decoding
    # --------------------------------------------------------

    # Look at all shell tokens and attempt decoding.
    try:

        tokens = shlex.split(
            text,
            posix=True,
        )

    except Exception:

        tokens = text.split()


    for token in tokens:

        # Direct token path checks
        if token_mentions_secret(
            token
        ):

            return True


        # Decode possible Base64 payloads.
        decoded_values = try_decode_base64(
            token
        )


        for decoded in decoded_values:

            if analyze_shell_text(
                decoded,
                depth + 1,
            ):

                return True


    # --------------------------------------------------------
    # Common shell wrappers
    # --------------------------------------------------------

    # Commands such as:
    #
    # bash -c 'cat ~/.secrets'
    # sh -c "cat $HOME/.secrets"
    # /bin/bash -c ...
    #
    # The complete original text is recursively inspected,
    # so the checks above still apply.
    #
    # We additionally inspect shell arguments after parsing.

    try:

        tokens = shlex.split(
            text,
            posix=True,
        )

    except Exception:

        tokens = []


    shell_commands = {
        "bash",
        "sh",
        "zsh",
        "dash",
        "ksh",
        "/bin/bash",
        "/bin/sh",
        "/bin/zsh",
        "/bin/dash",
        "/bin/ksh",
    }


    for index, token in enumerate(tokens):

        if token in shell_commands:

            # Find arguments after -c.
            for j in range(
                index + 1,
                len(tokens),
            ):

                if tokens[j] == "-c":

                    if (
                        j + 1
                        < len(tokens)
                    ):

                        nested = tokens[
                            j + 1
                        ]


                        if analyze_shell_text(
                            nested,
                            depth + 1,
                        ):

                            return True


                    break


    # --------------------------------------------------------
    # Path traversal from working directory
    # --------------------------------------------------------

    # Detect common traversal forms that resolve to
    # /home/agent/.secrets.
    #
    # Example:
    # cat ../.secrets
    #
    # from /home/agent/workspace.
    #
    # Also:
    # cat ../../.secrets
    #
    # We tokenize and resolve path-like arguments.

    for token in tokens:

        cleaned = token.strip(
            "\"'"
        )


        if (
            "/" in cleaned
            or cleaned.startswith(
                "."
            )
            or cleaned.startswith(
                "~"
            )
        ):

            if path_is_restricted(
                cleaned,
                "/home/agent/workspace",
            ):

                return True


    return False


# ============================================================
# BASH POLICY
# ============================================================

def check_bash(
    command: str | None,
):

    if not command:

        return block(
            "A bash command is required."
        )


    if analyze_shell_text(
        command
    ):

        return block(
            "This command may access the protected secrets file."
        )


    return allow(
        "The bash command does not target the protected secrets file."
    )


# ============================================================
# WRITE FILE POLICY
# ============================================================

def check_write_file(
    path: str | None,
):

    if not path:

        return block(
            "A file path is required."
        )


    if path_is_allowed_write(
        path
    ):

        return allow(
            "The file is inside the allowed output directory."
        )


    return block(
        "Writes are permitted only inside /workspace/output/."
    )


# ============================================================
# HTTP REQUEST POLICY
# ============================================================

def check_http_request(
    url: str | None,
):

    if not url:

        return block(
            "An HTTP URL is required."
        )


    if is_allowed_host(
        url
    ):

        return allow(
            "The HTTP request targets an explicitly allowed host."
        )


    return block(
        "The HTTP request targets a host outside the allowlist."
    )


# ============================================================
# MAIN GUARDRAIL
# ============================================================

@app.post(
    "/check",
    response_model=GuardrailResponse,
)
async def check_tool_call(
    request: ToolCall,
):

    tool = request.tool


    if tool == "bash":

        result = check_bash(
            request.command
        )


    elif tool == "write_file":

        result = check_write_file(
            request.path
        )


    elif tool == "http_request":

        result = check_http_request(
            request.url
        )


    else:

        result = block(
            "Unknown tools are not permitted."
        )


    # Ensure exactly two output keys.
    return {
        "decision": result["decision"],
        "reason": result["reason"],
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def root():

    return {
        "status": "ok",
        "service": "Agent Harness Pre-Tool-Call Guardrail",
        "endpoint": "/check",
    }