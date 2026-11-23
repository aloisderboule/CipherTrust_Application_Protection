"""Helper utilities for CipherTrust MCP Server."""

import json
from pathlib import Path
from typing import Any


def format_json_output(data: Any, indent: int = 2) -> str:
    """Format data as pretty-printed JSON.
    
    Args:
        data: Data to format
        indent: Number of spaces for indentation
        
    Returns:
        Formatted JSON string
    """
    if isinstance(data, str):
        try:
            # Try to parse as JSON first
            parsed = json.loads(data)
            return json.dumps(parsed, indent=indent)
        except json.JSONDecodeError:
            # Return as-is if not JSON
            return data
    return json.dumps(data, indent=indent)


def sanitize_command_args(args: list[str]) -> list[str]:
    """Sanitize command arguments for logging.
    
    Removes sensitive information like passwords from command arguments.
    
    Args:
        args: Command arguments
        
    Returns:
        Sanitized arguments safe for logging
    """
    sensitive_flags = ["--password", "--pword", "--jwt", "--refresh-token", "--bind-password",
                       "--test-password", "--client-secret", "--conn-password", "--bkpassword"]
    sanitized = []
    skip_next = False
    
    for arg in args:
        if skip_next:
            sanitized.append("***")
            skip_next = False
        elif arg in sensitive_flags:
            sanitized.append(arg)
            skip_next = True
        else:
            sanitized.append(arg)
    
    return sanitized


def merged_properties(*models: Any) -> dict[str, Any]:
    """JSON schema properties of several pydantic models, merged (first wins).

    For grouped tools whose actions each have their own parameter model: the
    tool's schema must list every action's parameters, or MCP clients never
    send them.
    """
    props: dict[str, Any] = {}
    for model in models:
        for name, prop in model.model_json_schema().get("properties", {}).items():
            props.setdefault(name, prop)
    return props


def read_secret_file(path: str) -> str:
    """Read a secret (password, client secret) from a local file, stripped.

    Lets a caller pass a file path instead of the secret itself, so the secret
    never appears in the MCP tool call or the conversation.
    """
    secret = Path(path).expanduser().read_text(encoding="utf-8").strip()
    if not secret:
        raise ValueError(f"secret file is empty: {path}")
    return secret
