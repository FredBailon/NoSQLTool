from .detection import run_detection, summarize_vulnerabilities


def main() -> None:
    # Configuracion para tu entorno de pruebas
    swagger_path = r"C:\Users\naelb\OneDrive\Documents\NoSQLTool\API-e-commerce\API_Neo4j\swagger.json"
    base_url = "http://localhost:3000"

    engine = "neo4j"      # debe coincidir con los payloads disponibles
    mode = "detection"    # o "exploitation" si tienes ese json

    # target_path = "/ruta" para probar solo un endpoint concreto
    target_path = None      # None = todos los endpoints del swagger

    print("Iniciando deteccion de posibles inyecciones NoSQL...")

    results = run_detection(
        swagger_path=swagger_path,
        engine=engine,
        mode=mode,
        target_path=target_path,
        max_workers=10,
        base_url_override=base_url,
    )

    summary = summarize_vulnerabilities(results)

    if not summary:
        print("No se detectaron posibles vulnerabilidades con los criterios actuales.")
        return

    print("\nResumen de posibles endpoints vulnerables:\n")
    for endpoint_key, params in summary.items():
        print(f"[+] Endpoint: {endpoint_key}")
        for param_name, payloads in params.items():
            print(f"    Parametro vulnerable: {param_name}")
            print("    Payloads que provocaron comportamiento sospechoso:")
            for p in payloads:
                print(f"        - {p}")


if __name__ == "__main__":
    main()
