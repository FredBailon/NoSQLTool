import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from .config import GITHUB_RAW_BASE, CACHE_DIR, FETCH_TIMEOUT
from .payloads.resolver import resolve_payload_url
from .payloads.cache import download_if_updated
from .payloads.loader import load_payloads


@dataclass
class Endpoint:
    path: str
    method: str
    query_params: List[str]
    body_fields: List[str]


@dataclass
class TestCase:
    endpoint: Endpoint
    param_name: str
    payload: str
    param_location: str  # "query" o "body"


@dataclass
class ResponseInfo:
    status_code: int
    body: str
    elapsed: float


@dataclass
class TestResult:
    endpoint: Endpoint
    param_name: str
    payload: str
    vulnerable: bool
    reason: Optional[str]
    baseline: ResponseInfo
    injected: ResponseInfo


def load_swagger_from_file(swagger_path: str) -> Dict[str, Any]:
    with open(swagger_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _build_base_url(spec: Dict[str, Any]) -> str:
    # OpenAPI 3.x style
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = servers[0].get("url")
        if isinstance(url, str) and url:
            return url.rstrip("/")

    # Swagger 2.0 style
    scheme = "https"
    schemes = spec.get("schemes")
    if isinstance(schemes, list) and schemes:
        scheme = schemes[0]

    host = spec.get("host", "")
    base_path = spec.get("basePath", "").rstrip("/")

    if host:
        return f"{scheme}://{host}{base_path}"

    raise ValueError("No se pudo determinar la URL base de la API desde el swagger.json")


def _extract_body_fields_from_schema(schema: Dict[str, Any]) -> List[str]:
    """Extrae nombres de campos de primer nivel del cuerpo JSON.

    Se centra en esquemas tipo object y propiedades simples (string, number, etc.).
    """
    fields: List[str] = []

    if not isinstance(schema, dict):
        return fields

    if schema.get("type") == "object" and isinstance(schema.get("properties"), dict):
        for name, prop in schema["properties"].items():
            if not isinstance(prop, dict):
                continue
            prop_type = prop.get("type")
            if prop_type in {"string", "number", "integer", "boolean", None}:
                fields.append(name)

    return fields


def extract_endpoints(spec: Dict[str, Any], target_path: Optional[str] = None) -> List[Endpoint]:
    paths = spec.get("paths", {})
    endpoints: List[Endpoint] = []

    for path, methods in paths.items():
        if target_path and path != target_path:
            continue

        if not isinstance(methods, dict):
            continue

        for method, meta in methods.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch"}:
                continue

            params = meta.get("parameters", [])
            query_params = [
                p["name"]
                for p in params
                if p.get("in") == "query" and isinstance(p.get("name"), str)
            ]

            # Swagger 2.0: cuerpo en parametros "in": "body"
            body_fields: List[str] = []
            for p in params:
                if p.get("in") == "body" and isinstance(p.get("schema"), dict):
                    body_fields.extend(_extract_body_fields_from_schema(p["schema"]))

            # OpenAPI 3.x: requestBody -> content -> application/json
            if isinstance(meta, dict) and isinstance(meta.get("requestBody"), dict):
                rb = meta["requestBody"]
                content = rb.get("content", {})
                if isinstance(content, dict):
                    json_media = None
                    if "application/json" in content:
                        json_media = content["application/json"]
                    else:
                        # tomar el primero que parezca JSON
                        for k, v in content.items():
                            if "json" in k:
                                json_media = v
                                break
                    if isinstance(json_media, dict) and isinstance(json_media.get("schema"), dict):
                        body_fields.extend(_extract_body_fields_from_schema(json_media["schema"]))

            if not query_params and not body_fields:
                continue

            endpoints.append(
                Endpoint(
                    path=path,
                    method=method.upper(),
                    query_params=query_params,
                    body_fields=list(dict.fromkeys(body_fields)),  # sin duplicados
                )
            )

    return endpoints


def _send_request(
    base_url: str,
    endpoint: Endpoint,
    params: Dict[str, str],
    json_body: Optional[Dict[str, Any]] = None,
) -> ResponseInfo:
    url = f"{base_url}{endpoint.path}"
    start = time.time()
    try:
        resp = requests.request(
            endpoint.method,
            url,
            params=params,
            json=json_body,
            timeout=FETCH_TIMEOUT,
        )
        elapsed = time.time() - start
        return ResponseInfo(status_code=resp.status_code, body=resp.text or "", elapsed=elapsed)
    except requests.RequestException as e:
        elapsed = time.time() - start
        return ResponseInfo(status_code=0, body=str(e), elapsed=elapsed)


def _analyze_responses(baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
    # Error-based: el payload provoca errores de servidor claros
    if baseline.status_code < 500 <= injected.status_code:
        return True, "Posible inyeccion NoSQL (error-based: 5xx en respuesta inyectada)"

    # Cambios importantes en longitud de respuesta
    base_len = len(baseline.body)
    inj_len = len(injected.body)

    if base_len == 0 and inj_len > 0:
        return True, "Posible inyeccion NoSQL (respuesta vacia vs no vacia)"

    if base_len > 0 and inj_len / base_len > 1.5:
        return True, "Posible inyeccion NoSQL (respuesta significativamente mas grande)"

    # Cambios de codigo HTTP relevantes
    if baseline.status_code != injected.status_code:
        return True, "Posible inyeccion NoSQL (cambio de codigo HTTP)"

    return False, None


def _run_single_test_case(base_url: str, test_case: TestCase) -> TestResult:
    # valores base genericos
    baseline_params = {name: "test" for name in test_case.endpoint.query_params}
    baseline_body = {name: "test" for name in test_case.endpoint.body_fields}

    # peticion base sin payload malicioso
    baseline_resp = _send_request(base_url, test_case.endpoint, baseline_params, baseline_body or None)

    # peticion con payload en el parametro especifico
    injected_params = baseline_params.copy()
    injected_body = baseline_body.copy()

    if test_case.param_location == "query":
        injected_params[test_case.param_name] = test_case.payload
    else:
        injected_body[test_case.param_name] = test_case.payload

    injected_resp = _send_request(base_url, test_case.endpoint, injected_params, injected_body or None)

    vulnerable, reason = _analyze_responses(baseline_resp, injected_resp)

    return TestResult(
        endpoint=test_case.endpoint,
        param_name=test_case.param_name,
        payload=test_case.payload,
        vulnerable=vulnerable,
        reason=reason,
        baseline=baseline_resp,
        injected=injected_resp,
    )


def _load_payloads_for_engine(engine: str, mode: str) -> List[str]:
    url = resolve_payload_url(GITHUB_RAW_BASE, engine, mode)
    cache_file = f"{CACHE_DIR}/{engine}_{mode}.json"
    etag_file = f"{cache_file}.etag"

    download_if_updated(url, cache_file, etag_file, FETCH_TIMEOUT)

    data = load_payloads(cache_file)

    # Se espera una lista de strings; si son objetos, intentar extraer campo "payload"
    payloads: List[str] = []
    for item in data:
        if isinstance(item, str):
            payloads.append(item)
        elif isinstance(item, dict):
            value = item.get("payload")
            if isinstance(value, str):
                payloads.append(value)

    return payloads


def build_test_cases(endpoints: List[Endpoint], payloads: List[str]) -> List[TestCase]:
    cases: List[TestCase] = []
    for ep in endpoints:
        # parametros en query
        for param in ep.query_params:
            for payload in payloads:
                cases.append(
                    TestCase(
                        endpoint=ep,
                        param_name=param,
                        payload=payload,
                        param_location="query",
                    )
                )

        # campos en body JSON
        for field in ep.body_fields:
            for payload in payloads:
                cases.append(
                    TestCase(
                        endpoint=ep,
                        param_name=field,
                        payload=payload,
                        param_location="body",
                    )
                )
    return cases


def run_detection(
    swagger_path: str,
    engine: str = "neo4j",
    mode: str = "detection",
    target_path: Optional[str] = None,
    max_workers: int = 10,
    base_url_override: Optional[str] = None,
) -> List[TestResult]:
    """Ejecuta la deteccion de posibles inyecciones NoSQL.

    - swagger_path: ruta local al archivo swagger.json
    - engine: motor NoSQL (mongo, couchdb, neo4j, ...)
    - mode: tipo de payloads (detection / exploitation)
    - target_path: si se indica, solo prueba ese endpoint (por ejemplo, "/users")
    - max_workers: numero maximo de hilos en paralelo
    - base_url_override: si se indica, se usara esta URL base
      en lugar de la definida en el swagger (ej. "http://localhost:3000")
    """

    spec = load_swagger_from_file(swagger_path)
    if base_url_override:
        base_url = base_url_override.rstrip("/")
    else:
        base_url = _build_base_url(spec)

    endpoints = extract_endpoints(spec, target_path=target_path)
    if not endpoints:
        raise ValueError("No se encontraron endpoints con parametros query/body para probar")

    payloads = _load_payloads_for_engine(engine, mode)
    if not payloads:
        raise ValueError("No se cargaron payloads para el motor/modo especificados")

    test_cases = build_test_cases(endpoints, payloads)

    results: List[TestResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_case = {
            executor.submit(_run_single_test_case, base_url, case): case
            for case in test_cases
        }

        for future in as_completed(future_to_case):
            result = future.result()
            results.append(result)

    return results


def summarize_vulnerabilities(results: List[TestResult]) -> Dict[str, Dict[str, List[str]]]:
    """Agrupa resultados vulnerables por endpoint y parametro.

    Devuelve un dict de la forma:
    {
      "GET /users": {
          "filter": ["payload1", "payload2"]
      }
    }
    """
    summary: Dict[str, Dict[str, List[str]]] = {}

    for r in results:
        if not r.vulnerable:
            continue

        key = f"{r.endpoint.method} {r.endpoint.path}"
        if key not in summary:
            summary[key] = {}

        if r.param_name not in summary[key]:
            summary[key][r.param_name] = []

        if r.payload not in summary[key][r.param_name]:
            summary[key][r.param_name].append(r.payload)

    return summary
