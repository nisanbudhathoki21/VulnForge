from pathlib import Path
import yaml


REQUIRED_TEMPLATE_KEYS = {
    "id",
    "name",
    "severity",
    "requests",
}


ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
}


class TemplateValidationError(Exception):
    pass


def load_template(path):
    path = Path(path)

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise TemplateValidationError(
            f"{path}: root must be a mapping"
        )

    missing = REQUIRED_TEMPLATE_KEYS - set(data.keys())

    if missing:
        raise TemplateValidationError(
            f"{path}: missing keys: {sorted(missing)}"
        )

    if not isinstance(data["requests"], list):
        raise TemplateValidationError(
            f"{path}: requests must be a list"
        )

    for index, request in enumerate(data["requests"]):
        validate_request(path, index, request)

    return data


def validate_request(path, index, request):
    if not isinstance(request, dict):
        raise TemplateValidationError(
            f"{path}: request #{index + 1} must be a mapping"
        )

    method = str(
        request.get("method", "GET")
    ).upper()

    if method not in ALLOWED_METHODS:
        raise TemplateValidationError(
            f"{path}: request #{index + 1}: "
            f"unsupported method {method}"
        )

    if "path" not in request:
        raise TemplateValidationError(
            f"{path}: request #{index + 1}: missing path"
        )

    path_value = request["path"]

    if not isinstance(path_value, (str, list)):
        raise TemplateValidationError(
            f"{path}: request #{index + 1}: "
            "path must be string or list"
        )

    if isinstance(path_value, list):
        for item in path_value:
            if not isinstance(item, str):
                raise TemplateValidationError(
                    f"{path}: request #{index + 1}: "
                    "path list must contain strings"
                )

    for key in ("headers", "payloads"):
        if key in request and not isinstance(
            request[key], dict
        ):
            raise TemplateValidationError(
                f"{path}: request #{index + 1}: "
                f"{key} must be a mapping"
            )


def validate_directory(directory="templates"):
    directory = Path(directory)

    errors = []
    valid = []

    for path in sorted(directory.rglob("*.yaml")):
        try:
            template = load_template(path)
            valid.append((path, template))
        except Exception as exc:
            errors.append((path, str(exc)))

    return valid, errors
