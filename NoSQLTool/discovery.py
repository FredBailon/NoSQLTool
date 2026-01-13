from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

import requests

from .deteccion import cargar_payloads

# Rutas candidatas mínimas (puedes ampliarlas en tu repo de wordlists)
DEFAULT_PATHS: Tuple[str, ...] = (
    "/",
    "/usuarios",
    "/productos",
    "/pedidos",
    "/buscar-productos",
    "/buscar-usuarios-inseguro",
    "/busqueda-productos-insegura",
    "/login-inseguro",
)

# Nombres de parámetros típicos donde intentar inyectar
DEFAULT_PARAMS: Tuple[str, ...] = (
    "q",
    "search",
    "nombre",
    "password",
    "extra",
    "filter",
    "id",
)


def _join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def discover_endpoints(
    api_base_url: str,
    paths: Iterable[str] | None = None,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """Descubre endpoints válidos probando una wordlist de rutas.

    No garantiza encontrar *todos* los endpoints, pero identifica rutas que no
    devuelven un 404 claro.
    """

    if paths is None:
        paths = DEFAULT_PATHS

    encontrados: List[Dict[str, Any]] = []

    for path in paths:
        url = _join_url(api_base_url, path)
        try:
            resp = requests.get(url, timeout=timeout)
        except Exception:
            # Si la petición falla (timeout, conexión, etc.), ignoramos esta ruta
            continue

        if resp.status_code != 404:
            encontrados.append(
                {
                    "path": path,
                    "status_code": resp.status_code,
                    "length": len(resp.text or ""),
                }
            )

    return encontrados


def _eval_diff(base_resp: requests.Response, inj_resp: requests.Response) -> Tuple[bool, str]:
    """Evalúa si hay indicios de vulnerabilidad comparando base vs inyectado."""

    base_code = base_resp.status_code
    inj_code = inj_resp.status_code

    base_body = base_resp.text or ""
    inj_body = inj_resp.text or ""

    base_len = len(base_body)
    inj_len = len(inj_body)

    # 1) Errores de servidor solo con payload (posible inyección)
    if inj_code >= 500 and base_code < 500:
        if any(s in inj_body for s in ["Neo.ClientError", "Neo.TransientError", "syntax error", "Invalid input"]):
            return True, "Error de sintaxis/Neo4j solo con payload"
        return True, "Error 5xx solo con payload"

    # 2) Misma respuesta para base e inyectado -> no hay señal clara
    if base_code == inj_code and base_body == inj_body:
        return False, "Base e inyectado devuelven exactamente lo mismo"

    # 3) Respuesta inyectada mucho más grande que la base (posible OR 1=1)
    if base_code == inj_code == 200 and base_len > 0:
        if inj_len > base_len * 1.5 and inj_len - base_len > 100:
            return True, "Respuesta mucho más grande con payload (posible OR 1=1)"

    # 4) Aparición de contenido sensible solo con payload
    sospechosos = ["admin", "Usuario", "Pedido", "Producto"]
    for token in sospechosos:
        if token in inj_body and token not in base_body:
            return True, f"Contenido sensible '{token}' solo con payload"

    return False, "Sin diferencias significativas entre base e inyectado"


def detectar_caja_negra(
    api_base_url: str,
    engine: str = "neo4j",
    mode: str = "detection",
    paths: Iterable[str] | None = None,
    param_names: Iterable[str] | None = None,
    timeout: float = 5.0,
) -> List[Dict[str, Any]]:
    """Realiza detección "a ciegas" sin conocer los endpoints exactos.

    Estrategia:
      1. Descubrir endpoints probando una wordlist de rutas.
      2. Para cada endpoint y para varios nombres de parámetros típicos,
         enviar una petición base y otra con payload de inyección.
      3. Comparar base vs inyectado con heurísticas (_eval_diff).
    """

    if paths is None:
        paths = DEFAULT_PATHS
    if param_names is None:
        param_names = DEFAULT_PARAMS

    payloads = cargar_payloads(engine=engine, mode=mode)
    endpoints = discover_endpoints(api_base_url, paths=paths, timeout=timeout)

    resultados: List[Dict[str, Any]] = []

    for ep in endpoints:
        path = ep["path"]
        for param in param_names:
            base_url = _join_url(api_base_url, path)

            # Petición base con valor inocuo
            try:
                base_resp = requests.get(base_url, params={param: "baseline"}, timeout=timeout)
            except Exception as exc:
                resultados.append(
                    {
                        "engine": engine,
                        "mode": mode,
                        "endpoint": path,
                        "param": param,
                        "payload": None,
                        "vulnerable": False,
                        "detalle": f"Error en petición base: {exc}",
                        "baseline_status": None,
                        "inj_status": None,
                        "baseline_len": None,
                        "inj_len": None,
                    }
                )
                continue

            for p in payloads:
                value = p.get("payload", "")
                try:
                    inj_resp = requests.get(base_url, params={param: value}, timeout=timeout)
                except Exception as exc:
                    resultados.append(
                        {
                            "engine": engine,
                            "mode": mode,
                            "endpoint": path,
                            "param": param,
                            "payload": p,
                            "vulnerable": False,
                            "detalle": f"Error ejecutando payload: {exc}",
                            "baseline_status": base_resp.status_code,
                            "inj_status": None,
                            "baseline_len": len(base_resp.text or ""),
                            "inj_len": None,
                        }
                    )
                    continue

                vulnerable, motivo = _eval_diff(base_resp, inj_resp)

                resultados.append(
                    {
                        "engine": engine,
                        "mode": mode,
                        "endpoint": path,
                        "param": param,
                        "payload": p,
                        "vulnerable": vulnerable,
                        "detalle": motivo,
                        "baseline_status": base_resp.status_code,
                        "inj_status": inj_resp.status_code,
                        "baseline_len": len(base_resp.text or ""),
                        "inj_len": len(inj_resp.text or ""),
                    }
                )

    return resultados
