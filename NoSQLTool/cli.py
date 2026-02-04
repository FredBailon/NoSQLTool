import typer
from typing import Optional, List
from .config import *

from .payloads.resolver import resolve_payload_url
from .payloads.cache import download_if_updated
from .payloads.loader import load_payloads

app = typer.Typer(add_completion=False, help="NoSQLTool - CLI estilo sqlmap (uso autorizado).")


def _parse_headers(headers: Optional[List[str]]) -> dict:
    out = {}
    if not headers:
        return out
    for h in headers:
        if ":" not in h:
            raise typer.BadParameter(f"Header inválido: {h}. Usa 'K: V'")
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def _load_default_payloads(engine: str, mode: str):
    url = resolve_payload_url(GITHUB_RAW_BASE, engine, mode)

    cache_file = f"{CACHE_DIR}/{engine}_{mode}.json"
    etag_file = f"{cache_file}.etag"

    updated = download_if_updated(url, cache_file, etag_file, FETCH_TIMEOUT)
    print("Cache actualizado desde GitHub" if updated else "Cache sin cambios (ETag válido)")

    payloads = load_payloads(cache_file)
    print(f"Cargados {len(payloads)} payloads para {engine}/{mode}")
    return payloads


def _scan_url(target_url: str, payloads: list, headers: dict, timeout: int, batch: bool):
    """
    Aquí conectas tu motor real de ejecución.
    Por ahora es un scaffold seguro (no implementa lógica ofensiva).
    """
    print(f"\n[+] Escaneando URL: {target_url}")
    print(f"[+] Headers: {headers if headers else '{}'}")
    print(f"[+] Timeout: {timeout}s | Batch: {batch}")

    # Placeholder: recorre payloads y llama a tu cliente HTTP/analizador
    for p in payloads[:3]:
        print(f" - (demo) payload id={p.get('id','N/A')} listo para ejecutar")
    if len(payloads) > 3:
        print(f" ... ({len(payloads)-3} payloads más)")


def _scan_swagger(swagger_ref: str, payloads: list, headers: dict, timeout: int, batch: bool):
    """
    Placeholder: aquí luego integras el parser OpenAPI/Swagger.
    """
    print(f"\n[+] Swagger/OpenAPI recibido: {swagger_ref}")
    print("[*] Pendiente: parsear spec, generar endpoints y llamar _scan_url() por cada target.")


@app.command("scan")
def scan(
    url: Optional[str] = typer.Option(None, "-u", "--url", help="Target URL para escaneo directo."),
    swagger: Optional[str] = typer.Option(None, "-s", "--swagger", help="Swagger/OpenAPI (URL o ruta local)."),
    engine: str = typer.Option("mongo", "--engine", help="Motor: mongo|neo4j|couchdb..."),
    mode: str = typer.Option("detection", "--mode", help="Modo: detection|exploitation (si aplica)."),
    header: Optional[List[str]] = typer.Option(None, "--header", help="Header repetible 'K: V'."),
    timeout: int = typer.Option(15, "--timeout", help="Timeout HTTP (seg)."),
    batch: bool = typer.Option(False, "--batch", help="Modo no interactivo."),
):
    # Validación: exactamente una fuente de targets
    if (url is None and swagger is None) or (url is not None and swagger is not None):
        raise typer.BadParameter("Debes usar EXACTAMENTE uno: -u URL o -s SWAGGER")

    headers = _parse_headers(header)

    # Carga payloads por default (tu flujo actual)
    payloads = _load_default_payloads(engine, mode)

    # Ejecuta según modo
    if url:
        _scan_url(url, payloads, headers, timeout, batch)
    else:
        _scan_swagger(swagger, payloads, headers, timeout, batch)
