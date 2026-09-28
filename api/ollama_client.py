import json
import os
import socket
from dataclasses import dataclass
from typing import Any, Optional
from urllib import error, request


class OllamaClientError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 503):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class OllamaGenerateResult:
    model: str
    response: str
    raw: dict[str, Any]


MOJIBAKE_REPLACEMENTS = {
    "Ã¡": "á",
    "Ã ": "à",
    "Ã¢": "â",
    "Ã£": "ã",
    "Ã©": "é",
    "Ãª": "ê",
    "Ã­": "í",
    "Ã³": "ó",
    "Ã´": "ô",
    "Ãµ": "õ",
    "Ãº": "ú",
    "Ã¼": "ü",
    "Ã§": "ç",
    "Ã‰": "É",
    "ÃŠ": "Ê",
    "Ã‡": "Ç",
    "Âº": "º",
    "Âª": "ª",
    "Â°": "°",
    "Â·": "·",
    "Â": "",
    "â€“": "-",
    "â€”": "-",
    "â€œ": '"',
    "â€": '"',
    "â€˜": "'",
    "â€™": "'",
}


def repair_common_mojibake(text: str) -> str:
    if not isinstance(text, str) or not any(marker in text for marker in ("Ã", "Â", "â€", "â€“", "â€”")):
        return text

    plain_replacements = {
        "Ã¡": "á",
        "Ã ": "à",
        "Ã¢": "â",
        "Ã£": "ã",
        "Ã©": "é",
        "Ãª": "ê",
        "Ã­": "í",
        "Ã³": "ó",
        "Ã´": "ô",
        "Ãµ": "õ",
        "Ãº": "ú",
        "Ã¼": "ü",
        "Ã§": "ç",
        "Ã‰": "É",
        "ÃŠ": "Ê",
        "Ã‡": "Ç",
        "Âº": "º",
        "Âª": "ª",
        "Â°": "°",
        "Â·": "·",
        "â€“": "-",
        "â€”": "-",
        "â€œ": '"',
        "â€": '"',
        "â€˜": "'",
        "â€™": "'",
    }

    repaired = text
    for broken, fixed in MOJIBAKE_REPLACEMENTS.items():
        repaired = repaired.replace(broken, fixed)
    for broken, fixed in plain_replacements.items():
        repaired = repaired.replace(broken, fixed)
    return repaired


class OllamaClient:
    def __init__(
        self,
        *,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout_sec: Optional[float] = None,
    ):
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://host.docker.internal:11434")).rstrip("/")
        self.model = model or os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
        self.timeout_sec = float(timeout_sec or os.environ.get("OLLAMA_TIMEOUT_SEC", "180"))
        self.keep_alive = (os.environ.get("OLLAMA_KEEP_ALIVE", "10m").strip() or None)
        raw_num_gpu = os.environ.get("OLLAMA_NUM_GPU", "").strip()
        try:
            self.num_gpu = int(raw_num_gpu) if raw_num_gpu and raw_num_gpu.lower() not in {"auto", "default", "none"} else None
        except ValueError:
            self.num_gpu = None

    def generate(
        self,
        *,
        system: str,
        prompt: str,
        model: Optional[str] = None,
        temperature: float = 0.2,
        num_predict: Optional[int] = None,
    ) -> OllamaGenerateResult:
        payload = {
            "model": model or self.model,
            "system": system,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }
        if self.keep_alive:
            payload["keep_alive"] = self.keep_alive
        if num_predict is not None:
            payload["options"]["num_predict"] = int(num_predict)
        if self.num_gpu is not None:
            payload["options"]["num_gpu"] = int(self.num_gpu)

        req = request.Request(
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with request.urlopen(req, timeout=self.timeout_sec) as response:
                raw_body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise OllamaClientError(
                f"O Ollama retornou erro HTTP {exc.code}: {body or exc.reason}",
                status_code=502,
            ) from exc
        except error.URLError as exc:
            raise OllamaClientError(
                "O Ollama não está disponível no endpoint configurado. Verifique OLLAMA_BASE_URL e se o serviço local está em execução.",
                status_code=503,
            ) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise OllamaClientError(
                "O tempo limite de resposta do Ollama foi excedido.",
                status_code=504,
            ) from exc

        try:
            data = json.loads(raw_body)
        except json.JSONDecodeError as exc:
            raise OllamaClientError(
                "O Ollama retornou uma resposta inválida para o NetGuard.",
                status_code=502,
            ) from exc

        content = repair_common_mojibake(str(data.get("response") or "").strip())
        if not content:
            raise OllamaClientError(
                "O Ollama respondeu sem conteúdo útil para a solicitação.",
                status_code=502,
            )

        return OllamaGenerateResult(
            model=str(data.get("model") or payload["model"]),
            response=content,
            raw=data,
        )
