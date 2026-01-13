import abc
from typing import Any, Dict

import requests


class BaseAPIClient(abc.ABC):
    """Interfaz base para cualquier API que ejecute payloads.

    Para soportar una API concreta, crea una clase que herede de
    `BaseAPIClient` e implemente los dos métodos abstractos.
    """

    @abc.abstractmethod
    def ejecutar_payload(self, target: str, payload: Dict[str, Any]) -> requests.Response:
        """Envía el payload al `target` usando la API y devuelve la respuesta HTTP."""
        raise NotImplementedError

    @abc.abstractmethod
    def analizar_respuesta(self, response: requests.Response, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Analiza la respuesta HTTP y devuelve un dict con el resultado de la detección."""
        raise NotImplementedError


class GenericHTTPAPIClient(BaseAPIClient):
    """Cliente genérico basado en HTTP para APIs tipo REST **sin
    necesidad de modificarlas**.

    El comportamiento se controla a través de metadatos dentro de cada
    payload. Un payload de ejemplo podría verse así:

        {
          "id": "cypher-id-001",
          "description": "...",
          "severity": "medium",
          "payload": "Spongebob' OR 1=1",
          "request": {
            "method": "GET",
            "path": "/login-inseguro",
            "injection": {
              "location": "query",      # query | path | body-json | body-form | header
              "param": "password",      # nombre del parámetro a inyectar
              "template": "{payload}"   # opcional, cómo insertar el payload
            },
            "query_params": {             # opcional, parámetros fijos
              "otro_param": "valor"
            },
            "success_criteria": {         # cómo detectar vulnerabilidad
              "status_code": 200,
              "contains": "admin"       # texto que debe aparecer en la respuesta
            }
          }
        }

    De esta forma, el cliente puede trabajar con cualquier API existente
    (mientras los payloads describan cómo llamar al endpoint vulnerable).
    """

    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _build_url(self, path: str | None) -> str:
        if not path:
            return self.base_url
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base_url}{path}"

    def ejecutar_payload(self, target: str, payload: Dict[str, Any]) -> requests.Response:
        meta = payload.get("request") or {}

        method = str(meta.get("method", "GET")).upper()
        path = meta.get("path") or "/"
        url = self._build_url(path)

        injection = meta.get("injection") or {}
        location = str(injection.get("location", "query")).lower()
        param_name = injection.get("param")
        template = injection.get("template", "{payload}")

        query_params: Dict[str, Any] = dict(meta.get("query_params") or {})
        json_body: Dict[str, Any] | None = None
        form_body: Dict[str, Any] | None = None
        headers: Dict[str, str] = dict(meta.get("headers") or {})

        raw_payload = payload.get("payload", "")
        injected_value = template.replace("{payload}", str(raw_payload))

        # Aplicamos la inyección según la ubicación configurada
        if location == "query" and param_name:
            query_params[param_name] = injected_value
        elif location == "body-json":
            json_body = dict(meta.get("json_body") or {})
            if param_name:
                json_body[param_name] = injected_value
        elif location == "body-form":
            form_body = dict(meta.get("form_body") or {})
            if param_name:
                form_body[param_name] = injected_value
        elif location == "header" and param_name:
            headers[param_name] = injected_value

        return requests.request(
            method=method,
            url=url,
            params=query_params or None,
            json=json_body,
            data=form_body,
            headers=headers or None,
            timeout=self.timeout,
        )

    def analizar_respuesta(self, response: requests.Response, payload: Dict[str, Any]) -> Dict[str, Any]:
        meta = payload.get("request") or {}
        criteria = meta.get("success_criteria") or {}

        resultado: Dict[str, Any] = {
            "payload_id": payload.get("id"),
            "status_code": response.status_code,
            "vulnerable": False,
            "detalle": "",
        }

        # Si el payload no define criterios de éxito, asumimos que NO podemos
        # determinar vulnerabilidad. En lugar de marcar True por defecto,
        # dejamos vulnerable=False y devolvemos un mensaje claro.
        if not criteria:
            resultado["detalle"] = "Sin success_criteria definidos en el payload; no se puede evaluar vulnerabilidad"
            return resultado

        body_text: str
        try:
            body_text = response.text or ""
        except Exception:  # pragma: no cover - muy raro que falle .text
            body_text = ""

        # Criterio por código de estado
        status_ok = True
        if "status_code" in criteria:
            try:
                expected_status = int(criteria["status_code"])
                status_ok = response.status_code == expected_status
            except (TypeError, ValueError):
                status_ok = False

        # Criterio por contenido en el cuerpo
        contains_ok = True
        if "contains" in criteria:
            expected = criteria["contains"]
            if isinstance(expected, list):
                contains_ok = all(str(item) in body_text for item in expected)
            else:
                contains_ok = str(expected) in body_text

        vulnerable = status_ok and contains_ok

        resultado["vulnerable"] = vulnerable
        if not vulnerable:
            resultado["detalle"] = "Criterios de vulnerabilidad no cumplidos"
        else:
            resultado["detalle"] = "Criterios de vulnerabilidad cumplidos"

        return resultado
