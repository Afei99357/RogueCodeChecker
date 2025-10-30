"""
LLM Backend abstraction layer for code review.

Supports:
- Databricks Foundation Models (serving endpoints)
"""

import os
from abc import ABC, abstractmethod
from typing import Optional

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


def create_backend(backend_type: str = "databricks", **kwargs) -> LLMBackend:
    """
    Factory function to create LLM backend.

    Args:
        backend_type: Type of backend ("databricks")
        **kwargs: Backend-specific configuration

    Returns:
        Initialized LLM backend

    Examples:
        >>> backend = create_backend("databricks", endpoint_name="my-llama-endpoint")
    """
    backends = {
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

    Reads from SERVING_ENDPOINT or DATABRICKS_LLM_ENDPOINT environment variable.

    Returns:
        Default Databricks LLM backend

    Raises:
        ValueError: If no endpoint is configured
    """
    return create_backend("databricks")
