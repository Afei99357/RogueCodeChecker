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

try:
    from mlflow.deployments import get_deploy_client

    MLFLOW_AVAILABLE = True
except ImportError:
    MLFLOW_AVAILABLE = False


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

    Uses Databricks serving endpoints for model inference via MLflow deployments.
    Automatically authenticates using workspace context when running in Databricks Apps.
    """

    def __init__(
        self,
        endpoint_name: Optional[str] = None,
        timeout: int = 120,
    ):
        """
        Initialize Databricks backend.

        Args:
            endpoint_name: Databricks serving endpoint name
            timeout: Request timeout in seconds

        Environment variables (if endpoint_name not provided):
            SERVING_ENDPOINT or DATABRICKS_LLM_ENDPOINT: Endpoint name
        """
        if not MLFLOW_AVAILABLE:
            raise ImportError(
                "MLflow is required for Databricks backend. "
                "Install with: pip install mlflow"
            )

        self.endpoint_name = (
            endpoint_name
            or os.getenv("SERVING_ENDPOINT")
            or os.getenv("DATABRICKS_LLM_ENDPOINT")
        )
        self.timeout = timeout

        if not self.endpoint_name:
            raise ValueError(
                "Databricks backend requires endpoint_name. "
                "Provide via constructor or environment variable: SERVING_ENDPOINT"
            )

        # Get MLflow deploy client (handles authentication automatically in Databricks Apps)
        try:
            self.client = get_deploy_client("databricks")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Databricks deploy client: {e}")

    def generate(
        self, prompt: str, max_tokens: int = 2000, temperature: float = 0.1
    ) -> str:
        """Generate response using Databricks serving endpoint via MLflow."""
        # Convert prompt to chat messages format expected by Databricks endpoints
        messages = [{"role": "user", "content": prompt}]

        try:
            response = self.client.predict(
                endpoint=self.endpoint_name,
                inputs={
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
            )

            # Handle different response formats from Databricks models
            # Agent/chat endpoints return "messages"
            if "messages" in response:
                return response["messages"][-1]["content"].strip()

            # Foundation models return "choices"
            elif "choices" in response:
                choice_message = response["choices"][0]["message"]
                content = choice_message.get("content", "")

                # Handle list content format
                if isinstance(content, list):
                    combined = "".join(
                        part.get("text", "")
                        for part in content
                        if part.get("type") == "text"
                    )
                    return combined.strip()

                # Handle string content format
                if isinstance(content, str):
                    return content.strip()

            raise RuntimeError(f"Unexpected Databricks response format: {response}")

        except Exception as e:
            raise RuntimeError(f"Databricks API request failed: {e}")

    def is_available(self) -> bool:
        """Check if Databricks endpoint is accessible."""
        # If we have an endpoint name and client initialized, assume available
        # The client handles authentication automatically in Databricks Apps
        return bool(self.endpoint_name and self.client)


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
    1. SERVING_ENDPOINT set -> Databricks backend
    2. Ollama running -> Ollama backend (qwen3)
    3. Fallback -> Ollama backend (may fail if not running)

    Returns:
        Default LLM backend
    """
    # Check for Databricks configuration
    if os.getenv("SERVING_ENDPOINT") or os.getenv("DATABRICKS_LLM_ENDPOINT"):
        try:
            return create_backend("databricks")
        except (ValueError, ImportError, RuntimeError):
            pass  # Missing endpoint name or MLflow, try Ollama

    # Default to Ollama
    model = os.getenv("OLLAMA_MODEL", "qwen3")
    endpoint = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434")
    return create_backend("ollama", model=model, endpoint=endpoint)
