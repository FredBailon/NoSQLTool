from typing import Any, Dict, List

from api_client import BaseAPIClient, GenericHTTPAPIClient
from .config import GITHUB_RAW_BASE, REPO_COMMIT, CACHE_DIR, FETCH_TIMEOUT
from .payloads.cache import download_if_updated
from .payloads.loader import load_payloads
from .payloads.resolver import resolve_payload_url


def cargar_payloads(engine: str, mode: str = "detection") -> List[Dict[str, Any]]:
    """Descarga (si hace falta) y carga los payloads para un engine/mode.

    - `engine`: motor NoSQL (por ejemplo: "neo4j", "mongodb", "couchdb").
    - `mode`: normalmente "detection" o "exploitation".
    """
    url = resolve_payload_url(GITHUB_RAW_BASE, REPO_COMMIT, engine, mode)

    cache_file = f"{CACHE_DIR}/{engine}_{mode}.json"
    etag_file = f"{cache_file}.etag"

    download_if_updated(url, cache_file, etag_file, FETCH_TIMEOUT)

    return load_payloads(cache_file)


def detectar_vulnerabilidades(
    engine: str,
    target: str,
    api_client: BaseAPIClient,
    mode: str = "detection",
) -> List[Dict[str, Any]]:
    """Ejecuta los payloads de detección contra un target usando cualquier API.

    Esta función es agnóstica a la API concreta. Solo necesita un objeto
    `api_client` que implemente la interfaz `BaseAPIClient`.
    """
    payloads = cargar_payloads(engine=engine, mode=mode)

    resultados: List[Dict[str, Any]] = []

    for payload in payloads:
        try:
            response = api_client.ejecutar_payload(target, payload)
            analisis = api_client.analizar_respuesta(response, payload)
        except Exception as exc:  # capturamos para registrar el fallo sin abortar todo
            analisis = {
                "payload_id": payload.get("id"),
                "status_code": None,
                "vulnerable": False,
                "detalle": f"Error ejecutando payload: {exc}",
            }

        resultados.append(
            {
                "engine": engine,
                "mode": mode,
                "target": target,
                "payload": payload,
                "analisis": analisis,
            }
        )

    return resultados


def detectar_con_api(
        api_base_url: str,
        engine: str = "neo4j",
        mode: str = "detection",
) -> List[Dict[str, Any]]:
        """Conveniencia: ejecuta la detección sabiendo solo la URL de la API.

        - `api_base_url`: dirección completa de la API (por ejemplo,
            "http://localhost:3000" o "http://api-neo4j:3000").
        - `engine`: motor NoSQL (por defecto "neo4j").
        - `mode`: normalmente "detection".

        Internamente crea un `GenericHTTPAPIClient` con esa URL y lanza todos los
        payloads de detección contra los endpoints descritos en cada payload.
        """

        client = GenericHTTPAPIClient(base_url=api_base_url)
        # Usamos la propia URL de la API como "target" lógico para el reporte
        return detectar_vulnerabilidades(engine=engine, target=api_base_url, api_client=client, mode=mode)
