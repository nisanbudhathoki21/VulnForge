from engine.template_runtime import TemplateRuntime
from engine.template_validator import validate_directory


def test_variables():
    runtime = TemplateRuntime()

    runtime.set_variables({
        "id": "10"
    })

    assert runtime.render(
        "{{id|int+1}}"
    ) == "11"


def test_base64():
    runtime = TemplateRuntime()

    runtime.set_variables({
        "value": "hello"
    })

    assert runtime.render(
        "{{value|base64}}"
    ) == "aGVsbG8="


def test_payload_expansion():
    runtime = TemplateRuntime()

    result = runtime.expand_payloads({
        "id": ["1", "2"],
        "role": ["user", "admin"],
    })

    assert len(result) == 4


def test_templates():
    valid, errors = validate_directory("templates")

    assert errors == [], errors
    assert len(valid) > 0
