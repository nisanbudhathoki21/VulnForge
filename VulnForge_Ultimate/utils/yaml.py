import yaml

def safe_load(text: str):
    return yaml.safe_load(text)
