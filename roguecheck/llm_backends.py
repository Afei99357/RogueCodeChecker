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
from typing import Dict, Optional

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
            DATABRICKS_TOKEN: Access token
            SERVING_ENDPOINT or DATABRICKS_LLM_ENDPOINT: Endpoint name
        """
        self.endpoint_name = (
            endpoint_name
            or os.getenv("SERVING_ENDPOINT")
            or os.getenv("DATABRICKS_LLM_ENDPOINT")
        )
        self.workspace_url = (workspace_url or os.getenv("DATABRICKS_HOST", "")).rstrip(
            "/"
        )
        self.token = token or os.getenv("DATABRICKS_TOKEN")
        self.timeout = timeout

        if not all([self.endpoint_name, self.workspace_url, self.token]):
            raise ValueError(
                "Databricks backend requires endpoint_name, workspace_url, and token. "
                "Provide via constructor or environment variables: "
                "DATABRICKS_HOST, DATABRICKS_TOKEN, SERVING_ENDPOINT"
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
