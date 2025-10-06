"""
LLM Backend abstraction layer for code review.

Supports multiple LLM backends:
- Ollama (local models: qwen3, llama3, codellama, etc.)
- Databricks Foundation Models (serving endpoints)
- OpenAI (future)
- Anthropic (future)
"""

import json
import os
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple

import requests


class LLMBackend(ABC):
    """Abstract base class for LLM backends."""

    @abstractmethod
    def generate(
        self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1
    ) -> str:
        """
        Generate a response from the LLM.

        Args:
            prompt: The prompt to send to the LLM
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            Generated text response
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the backend is available and configured."""
        pass


class OllamaBackend(LLMBackend):
    """
    Ollama backend for local LLM models.

    Supports any model installed in Ollama: qwen3, llama3, codellama, etc.
    """

    def __init__(
        self,
        model: str = "qwen3",
        endpoint: str = "http://localhost:11434",
        timeout: int = 120,
    ):
        """
        Initialize Ollama backend.

        Args:
            model: Model name (qwen3, llama3, codellama, etc.)
            endpoint: Ollama API endpoint
            timeout: Request timeout in seconds
        """
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout

    def generate(
        self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1
    ) -> str:
        """Generate response using Ollama API."""
        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data.get("response", "").strip()
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API request failed: {e}")
        except (KeyError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Failed to parse Ollama response: {e}")

    def is_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        try:
            # Check if Ollama is running
            response = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            response.raise_for_status()
            models = response.json().get("models", [])

            # Check if our model is installed
            model_names = [m.get("name", "") for m in models]
            return any(self.model in name for name in model_names)
        except Exception:
            return False


def _normalize_workspace_url(url: Optional[str]) -> str:
    """Ensure Databricks workspace URLs have https scheme and no trailing slash."""

    if not url:
        return ""
    cleaned = url.strip()
    if not cleaned:
        return ""
    if not cleaned.startswith("http"):
        cleaned = f"https://{cleaned}"
    return cleaned.rstrip("/")


def _resolve_runtime_credentials() -> Tuple[Optional[str], Optional[str], str]:
    """Attempt to fetch host/token from Databricks runtime helpers."""

    # Try Databricks SDK config first (available in Apps and Workflows runtimes)
    try:
        from databricks.sdk import Config  # type: ignore

        try:
            cfg = Config()
            if cfg.host or cfg.token:
                return cfg.host, cfg.token, "databricks.sdk.Config"
        except Exception:
            pass
    except Exception:
        pass

    # Fallback: try dbutils context if exposed
    for candidate in ("databricks.sdk.runtime", "dbutils"):
        try:
            runtime = __import__(candidate, fromlist=["dbutils"])  # type: ignore
            dbutils = getattr(runtime, "dbutils", runtime)
        except Exception:
            continue
        try:
            entry = dbutils.notebook.entry_point.getDbutils()  # type: ignore[attr-defined]
            ctx = entry.notebook().getContext()
            host = None
            token = None
            try:
                api_url = ctx.apiUrl()
                host = api_url.get() if hasattr(api_url, "get") else api_url
            except Exception:
                pass
            try:
                api_token = ctx.apiToken()
                token = api_token.get() if hasattr(api_token, "get") else api_token
            except Exception:
                pass
            if host or token:
                return host, token, f"{candidate}.dbutils"
        except Exception:
            continue

    return None, None, ""


class DatabricksBackend(LLMBackend):
    """
    Databricks Foundation Models backend.

    Uses Databricks serving endpoints for model inference.
    """

    def __init__(
        self,
        endpoint_name: Optional[str] = None,
        workspace_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 120,
    ):
        """
        Initialize Databricks backend.

        Args:
            endpoint_name: Databricks serving endpoint name
            workspace_url: Databricks workspace URL
            token: Databricks personal access token
            timeout: Request timeout in seconds

        Environment variables (if args not provided):
            DATABRICKS_HOST: Workspace URL
            DATABRICKS_HOSTNAME: Workspace hostname (Databricks Apps)
            DATABRICKS_TOKEN / DATABRICKS_APP_TOKEN / DATABRICKS_BEARER_TOKEN: Access token
            SERVING_ENDPOINT or DATABRICKS_LLM_ENDPOINT: Endpoint name

        Runtime fallback:
            - Databricks SDK config (if available)
            - Databricks dbutils context (Apps/Notebooks)
        """
        runtime_host, runtime_token, runtime_source = _resolve_runtime_credentials()

        self.endpoint_name = (
            endpoint_name
            or os.getenv("SERVING_ENDPOINT")
            or os.getenv("DATABRICKS_LLM_ENDPOINT")
        )

        resolved_workspace_url = _normalize_workspace_url(
            workspace_url
            or os.getenv("DATABRICKS_HOST")
            or os.getenv("DATABRICKS_HOSTNAME")
            or runtime_host
        )

        token_candidates = [
            token,
            os.getenv("DATABRICKS_TOKEN"),
            os.getenv("DATABRICKS_APP_TOKEN"),
            os.getenv("DATABRICKS_BEARER_TOKEN"),
            runtime_token,
        ]
        resolved_token = next((t for t in token_candidates if t), None)

        self.workspace_url = resolved_workspace_url
        self.token = resolved_token
        self.timeout = timeout

        if not all([self.endpoint_name, self.workspace_url, self.token]):
            # Debug: show what's actually set
            debug_info = (
                f"endpoint_name={bool(self.endpoint_name)}, workspace_url={bool(self.workspace_url)}, "
                f"token={bool(self.token)}, hostname_fallback={bool(os.getenv('DATABRICKS_HOSTNAME'))}, "
                f"runtime_source={runtime_source or 'none'}"
            )
            raise ValueError(
                f"Databricks backend requires endpoint_name, workspace_url, and token. "
                f"Current state: {debug_info}. "
                "Provide via constructor or environment variables: "
                "DATABRICKS_HOST (or DATABRICKS_HOSTNAME), DATABRICKS_TOKEN, SERVING_ENDPOINT"
            )

    def generate(
        self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1
    ) -> str:
        """Generate response using Databricks serving endpoint."""
        url = f"{self.workspace_url}/serving-endpoints/{self.endpoint_name}/invocations"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        payload = {
            "inputs": {"prompt": [prompt]},
            "params": {
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        }

        try:
            response = requests.post(
                url, headers=headers, json=payload, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()

            # Handle different response formats from Databricks models
            if "predictions" in data:
                return data["predictions"][0].strip()
            elif "choices" in data:
                return data["choices"][0].get("text", "").strip()
            else:
                raise RuntimeError(f"Unexpected Databricks response format: {data}")

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Databricks API request failed: {e}")
        except (KeyError, json.JSONDecodeError, IndexError) as e:
            raise RuntimeError(f"Failed to parse Databricks response: {e}")

    def is_available(self) -> bool:
        """Check if Databricks endpoint is accessible."""
        # For Databricks Apps, we assume endpoint is available if credentials are set
        # The actual endpoint check may fail due to permissions/network in Apps runtime
        if self.endpoint_name and self.workspace_url and self.token:
            return True

        # Fallback: try to check endpoint accessibility
        try:
            url = f"{self.workspace_url}/api/2.0/serving-endpoints/{self.endpoint_name}"
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception:
            return False


def create_backend(backend_type: str = "ollama", **kwargs) -> LLMBackend:
    """
    Factory function to create LLM backend.

    Args:
        backend_type: Type of backend ("ollama", "databricks")
        **kwargs: Backend-specific configuration

    Returns:
        Initialized LLM backend

    Examples:
        >>> backend = create_backend("ollama", model="qwen3")
        >>> backend = create_backend("ollama", model="llama3")
        >>> backend = create_backend("databricks", endpoint_name="my-llama-endpoint")
    """
    backends = {
        "ollama": OllamaBackend,
        "databricks": DatabricksBackend,
    }

    if backend_type not in backends:
        raise ValueError(
            f"Unknown backend type: {backend_type}. "
            f"Available: {', '.join(backends.keys())}"
        )

    return backends[backend_type](**kwargs)


def get_default_backend() -> LLMBackend:
    """
    Get default LLM backend based on environment.

    Priority:
    1. DATABRICKS_HOST set -> Databricks backend
    2. Ollama running -> Ollama backend (qwen3)
    3. Fallback -> Ollama backend (may fail if not running)

    Returns:
        Default LLM backend
    """
    # Check for Databricks configuration
    if os.getenv("DATABRICKS_HOST") and os.getenv("DATABRICKS_TOKEN"):
        try:
            return create_backend("databricks")
        except ValueError:
            pass  # Missing endpoint name, try Ollama

    # Default to Ollama
    model = os.getenv("OLLAMA_MODEL", "qwen3")
    endpoint = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434")
    return create_backend("ollama", model=model, endpoint=endpoint)
