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

DEFAULT_DETECTION_TYPES = ("error_based", "time_based", "boolean_based")
TIME_BASED_MIN_DELAY_SECONDS = 1.0
TIME_BASED_MIN_FACTOR = 2.0
BOOLEAN_BASED_DIFF_RATIO = 0.35
ERROR_KEYWORDS = (
    "neo4j",
    "cypher",
    "syntaxerror",
    "exception",
    "stack trace",
    "databaseerror",
)
ERROR_HINTS = (
    "error",
    "errors",
    "traceback",
    "failed",
    "invalid input",
    "query cannot be",
    "unexpected",
)


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
    payload_source: str


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
    payload_source: str
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


def _infer_boolean_intent(payload: str) -> Optional[str]:
    normalized = payload.lower().replace(" ", "")
    true_markers = ("or1=1", "'1'='1", "true")
    false_markers = ("or1=0", "'1'='0", "false")

    if any(marker in normalized for marker in true_markers):
        return "true"
    if any(marker in normalized for marker in false_markers):
        return "false"
    return None


def _relative_body_diff(base_len: int, inj_len: int) -> float:
    denominator = max(base_len, 1)
    return abs(inj_len - base_len) / denominator


def _extract_error_score(response: ResponseInfo) -> int:
    score = 0

    if response.status_code >= 500:
        score += 5
    elif response.status_code >= 400:
        score += 2
    elif response.status_code == 0:
        score += 1

    text = (response.body or "").lower()

    for keyword in ERROR_KEYWORDS:
        if keyword in text:
            score += 2

    for hint in ERROR_HINTS:
        if hint in text:
            score += 1

    # Si la respuesta parece JSON de error, sumar evidencia extra.
    try:
        parsed = json.loads(response.body)
        if isinstance(parsed, dict):
            error_keys = {"error", "errors", "exception", "message", "stack", "stacktrace", "code"}
            matched = error_keys.intersection({k.lower() for k in parsed.keys()})
            if matched:
                score += 2
    except (TypeError, ValueError, json.JSONDecodeError):
        pass

    return score


def _analyze_error_based(baseline: ResponseInfo, injected: ResponseInfo) -> Tuple[bool, Optional[str]]:
    # Regla fuerte 1: error interno nuevo tras inyeccion.
    if baseline.status_code < 500 <= injected.status_code:
        return True, "Posible inyeccion NoSQL (error-based: 5xx nuevo en respuesta inyectada)"

    base_score = _extract_error_score(baseline)
    inj_score = _extract_error_score(injected)
    score_delta = inj_score - base_score

    # Regla fuerte 2: salto consistente de evidencia de error.
    if inj_score >= 7 and score_delta >= 3:
        return True, "Posible inyeccion NoSQL (error-based: fuerte evidencia de error de BD tras payload)"

    # Regla fuerte 3: misma clase HTTP pero aparece texto de error de base de datos.
    base_text = (baseline.body or "").lower()
    inj_text = (injected.body or "").lower()
    inj_has_db_error = any(k in inj_text for k in ERROR_KEYWORDS)
    base_has_db_error = any(k in base_text for k in ERROR_KEYWORDS)
    if inj_has_db_error and not base_has_db_error:
        return True, "Posible inyeccion NoSQL (error-based: mensaje de error de motor/consulta)"

    # Fallback robusto (no generico): diferencia material de error aunque no haya 5xx.
    if score_delta >= 5:
        return True, "Posible inyeccion NoSQL (error-based: incremento material de señales de error)"

    return False, None


def _analyze_responses(
    baseline: ResponseInfo,
    injected: ResponseInfo,
    payload_source: str,
    payload: str,
) -> Tuple[bool, Optional[str]]:
    source = (payload_source or "").lower()

    # Heuristica especifica: error-based
    if source == "error_based":
        return _analyze_error_based(baseline, injected)

    # Heuristica especifica: time-based
    if source == "time_based":
        if baseline.status_code != 0 and injected.status_code != 0:
            delta = injected.elapsed - baseline.elapsed
            if delta >= max(TIME_BASED_MIN_DELAY_SECONDS, baseline.elapsed * TIME_BASED_MIN_FACTOR):
                return True, "Posible inyeccion NoSQL (time-based: incremento anomalo de latencia)"

    # Heuristica especifica: boolean-based
    if source == "boolean_based":
        base_len = len(baseline.body)
        inj_len = len(injected.body)
        diff_ratio = _relative_body_diff(base_len, inj_len)
        intent = _infer_boolean_intent(payload)

        if baseline.status_code != injected.status_code:
            return True, "Posible inyeccion NoSQL (boolean-based: cambio de codigo HTTP)"

        if intent == "true" and base_len > 0 and inj_len >= int(base_len * 1.2):
            return True, "Posible inyeccion NoSQL (boolean-based: condicion TRUE altera el resultado)"

        if intent == "false" and base_len > 0 and inj_len <= int(base_len * 0.8):
            return True, "Posible inyeccion NoSQL (boolean-based: condicion FALSE altera el resultado)"

        if diff_ratio >= BOOLEAN_BASED_DIFF_RATIO:
            return True, "Posible inyeccion NoSQL (boolean-based: diferencia relevante en respuesta)"

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

    vulnerable, reason = _analyze_responses(
        baseline_resp,
        injected_resp,
        test_case.payload_source,
        test_case.payload,
    )

    return TestResult(
        endpoint=test_case.endpoint,
        param_name=test_case.param_name,
        payload=test_case.payload,
        payload_source=test_case.payload_source,
        vulnerable=vulnerable,
        reason=reason,
        baseline=baseline_resp,
        injected=injected_resp,
    )


def _load_payloads_for_engine(engine: str, mode: str, payload_file: Optional[str] = None) -> List[str]:
    url = resolve_payload_url(GITHUB_RAW_BASE, engine, mode, payload_file=payload_file)

    if payload_file:
        safe_name = payload_file.replace(".json", "").strip()
        cache_file = f"{CACHE_DIR}/{engine}_{mode}_{safe_name}.json"
    else:
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


def _load_payload_sets(
    engine: str,
    mode: str,
    payload_file: Optional[str] = None,
    detection_types: Optional[List[str]] = None,
) -> Dict[str, List[str]]:
    if payload_file:
        source = payload_file.replace(".json", "").strip()
        return {source: _load_payloads_for_engine(engine, mode, payload_file=payload_file)}

    if mode.lower() == "detection":
        selected_types = detection_types or list(DEFAULT_DETECTION_TYPES)
        payload_sets: Dict[str, List[str]] = {}

        for detection_type in selected_types:
            normalized = detection_type.replace(".json", "").strip()
            payload_sets[normalized] = _load_payloads_for_engine(
                engine,
                mode,
                payload_file=normalized,
            )

        return payload_sets

    # Compatibilidad con modos donde exista un solo archivo por modo
    return {"default": _load_payloads_for_engine(engine, mode, payload_file=None)}


def build_test_cases(endpoints: List[Endpoint], payload_sets: Dict[str, List[str]]) -> List[TestCase]:
    cases: List[TestCase] = []
    for ep in endpoints:
        for payload_source, payloads in payload_sets.items():
            # parametros en query
            for param in ep.query_params:
                for payload in payloads:
                    cases.append(
                        TestCase(
                            endpoint=ep,
                            param_name=param,
                            payload=payload,
                            param_location="query",
                            payload_source=payload_source,
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
                            payload_source=payload_source,
                        )
                    )
    return cases


def run_detection(
    swagger_path: str,
    engine: str = "neo4j",
    mode: str = "detection",
    payload_file: Optional[str] = None,
    detection_types: Optional[List[str]] = None,
    target_path: Optional[str] = None,
    max_workers: int = 10,
    base_url_override: Optional[str] = None,
) -> List[TestResult]:
    """Ejecuta la deteccion de posibles inyecciones NoSQL.

    - swagger_path: ruta local al archivo swagger.json
    - engine: motor NoSQL (mongo, couchdb, neo4j, ...)
    - mode: tipo de payloads (detection / exploitation)
        - payload_file: nombre del json dentro de engine/mode (ej. "error_based" o "error_based.json")
            Si se indica, solo se usa ese archivo.
        - detection_types: lista de tipos de deteccion a usar cuando mode="detection"
            (por defecto: error_based, time_based, boolean_based).
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

    payload_sets = _load_payload_sets(
        engine,
        mode,
        payload_file=payload_file,
        detection_types=detection_types,
    )

    if not payload_sets or not any(payload_sets.values()):
        raise ValueError("No se cargaron payloads para el motor/modo especificados")

    test_cases = build_test_cases(endpoints, payload_sets)

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

        payload_label = r.payload
        if r.payload_source and r.payload_source != "default":
            payload_label = f"[{r.payload_source}] {r.payload}"

        if payload_label not in summary[key][r.param_name]:
            summary[key][r.param_name].append(payload_label)

    return summary
