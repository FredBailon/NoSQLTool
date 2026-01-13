"""CLI principal de la herramienta NoSQLTool.

Inspirado en el flujo de herramientas como NoSQLMap:

- Modo "targeted":
	Ejecuta todos los payloads de detección contra una API conocida,
	usando los metadatos `request` de cada payload (si existen).

- Modo "blind" (caja negra):
	Solo conociendo host y puerto de la API, intenta descubrir
	endpoints y parámetros candidatos y lanza inyecciones comparando
	respuestas base vs inyectadas.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from typing import Any, Dict, Iterable, List

from .deteccion import detectar_con_api
from .discovery import detectar_caja_negra


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="NoSQLTool - detección de vulnerabilidades NoSQL")

	parser.add_argument(
		"--api",
		dest="api_base_url",
		required=True,
		help="URL base de la API objetivo (por ejemplo, http://localhost:3000)",
	)

	parser.add_argument(
		"--engine",
		default="neo4j",
		help="Motor NoSQL a usar para seleccionar payloads (por defecto: neo4j)",
	)

	parser.add_argument(
		"--mode",
		choices=["targeted", "blind"],
		default="targeted",
		help="Modo de detección: targeted (dirigido) o blind (caja negra)",
	)

	return parser.parse_args(list(argv) if argv is not None else None)


def _print_targeted(results: List[Dict[str, Any]]) -> None:
	print("[NoSQLTool] Resultados modo targeted:")
	for r in results:
		pid = r["payload"].get("id")
		analisis = r["analisis"]
		print(
			f"  - payload {pid}: "
			f"status={analisis['status_code']} "
			f"vulnerable={analisis['vulnerable']} "
			f"detalle={analisis['detalle']}"
		)


def _print_blind(results: List[Dict[str, Any]]) -> None:
	print("[NoSQLTool] Resultados modo blind (caja negra):")

	# Agrupamos por endpoint/parámetro para dar una visión parecida a NoSQLMap
	grouped: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
	for r in results:
		key = (r["endpoint"], r["param"])
		grouped[key].append(r)

	for (endpoint, param), items in grouped.items():
		vulns = [it for it in items if it["vulnerable"]]
		if not vulns:
			# Solo mostramos un resumen no vulnerable si no hubo ninguna señal
			sample = items[0]
			print(
				f"  [OK] {endpoint}?{param}=* "
				f"(baseline={sample['baseline_status']}, sin indicios claros)"
			)
			continue

		print(f"  [VULN] {endpoint}?{param}=* - {len(vulns)} payload(s) sospechosos:")
		for v in vulns[:5]:  # mostramos solo los primeros 5 para no saturar
			pid = v["payload"]["id"] if v["payload"] else "-"
			print(
				f"       - {pid}: "
				f"baseline={v['baseline_status']} inj={v['inj_status']} "
				f"detalle={v['detalle']}"
			)


def main(argv: Iterable[str] | None = None) -> None:
	args = _parse_args(argv)

	api_base_url: str = args.api_base_url
	engine: str = args.engine
	mode: str = args.mode

	print(f"[NoSQLTool] Objetivo: {api_base_url} | engine={engine} | mode={mode}")

	if mode == "targeted":
		results = detectar_con_api(api_base_url=api_base_url, engine=engine)
		_print_targeted(results)
	else:
		results = detectar_caja_negra(api_base_url=api_base_url, engine=engine)
		_print_blind(results)


if __name__ == "__main__":
	import sys

	main(sys.argv[1:])
