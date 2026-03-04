SUPPORTED_ENGINES = {"couchdb", "mongo", "neo4j"}
SUPPORTED_MODES = {"detection", "exploitation"}

def resolve_payload_url(base, engine, mode, payload_file=None):
    engine = engine.lower()
    mode = mode.lower()

    if engine not in SUPPORTED_ENGINES:
        raise ValueError(f"Motor NoSQL no soportado: {engine}")

    if mode not in SUPPORTED_MODES:
        raise ValueError(f"Modo no soportado: {mode}")

    if payload_file:
        payload_file = payload_file.strip()
        if payload_file.endswith(".json"):
            payload_name = payload_file
        else:
            payload_name = f"{payload_file}.json"
        return f"{base}/{engine}/{mode}/{payload_name}"

    return f"{base}/{engine}/{mode}.json"