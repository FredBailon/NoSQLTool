import json

def load_payloads(cache_file):
    with open(cache_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Formato inválido de payloads")

    return data