"""Thin LLM client: one function, OpenAI-compatible chat endpoint, env-configured.

Defaults target the user's local Ollama. No API key is hardcoded. If the
endpoint is unreachable or returns garbage, `complete()` raises LLMError and
callers degrade gracefully (see explain.py). Stdlib only, so importing this
module never pulls a network dependency.

Env:
  LLM_BASE_URL  default http://127.0.0.1:11434/v1
  LLM_MODEL     default qwen3:30b-a3b-instruct-2507-q4_K_M
  LLM_API_KEY   default ollama   (Ollama ignores it; a hosted provider uses it)
"""
import json
import os
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    """Raised when the LLM endpoint is unreachable or returns an unusable reply."""


def complete(prompt, system=None, temperature=0.2, timeout=120):
    """Send one chat completion and return the assistant text. Raises LLMError."""
    base_url = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434/v1")
    model = os.environ.get("LLM_MODEL", "qwen3:30b-a3b-instruct-2507-q4_K_M")
    api_key = os.environ.get("LLM_API_KEY", "ollama")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    body = json.dumps(
        {"model": model, "messages": messages,
         "temperature": temperature, "stream": False}
    ).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise LLMError(f"LLM endpoint unreachable at {base_url}: {e}") from e
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as e:
        raise LLMError(f"Unexpected LLM response shape: {data!r}") from e
