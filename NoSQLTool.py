import sys

from deteccion import cargar_payloads_deteccion, detectar_vulnerabilidades


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # Para simplificar, el primer argumento será el "target" a analizar
    target = argv[0] if argv else "target_de_ejemplo"

    print(f"[NoSQLTool] Iniciando detección de vulnerabilidades en: {target}")

    # Ejemplo 1: solo obtener y mostrar los payloads de detección
    payloads_deteccion = cargar_payloads_deteccion()
    print(f"[NoSQLTool] Payloads de detección obtenidos: {len(payloads_deteccion)}")

    # Ejemplo 2: ejecutar una detección (lógica por implementar en detalle)
    resultados = detectar_vulnerabilidades(target)

    print("[NoSQLTool] Resultados de detección (ejemplo):")
    for r in resultados:
        pid = r["payload"].get("id")
        print(f"  - payload id={pid}, resultado={r['resultado']}")


if __name__ == "__main__":
    main()
