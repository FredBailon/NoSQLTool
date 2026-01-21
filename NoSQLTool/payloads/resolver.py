SUPPORTED_ENGINES = {"couchdb", "mongo", "neo4j"}
SUPPORTED_MODES = {"detection", "exploitation"}

def resolve_payload_url(base, engine, mode):
    engine = engine.lower()
    mode = mode.lower()

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Motor NoSQL no soportado: {engine}")

    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Modo no soportado: {mode}")

    return f"{base}/{engine}/{mode}.json"