#!/usr/bin/env python3

"""
VulnForge Scanner <-> TemplateRuntime integration test.

This test verifies that Scanner._substitute() correctly supports
the TemplateRuntime syntax without modifying scanner.py.
"""

import sys
from pathlib import Path

# Make the project root importable when running this file directly.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.scanner import Scanner


def main():
    print("=" * 60)
    print("VULNFORGE SCANNER RUNTIME INTEGRATION TEST")
    print("=" * 60)

    scanner = Scanner(
        url="http://127.0.0.1:8765",
        quiet=True,
        template_dir="templates/",
    )

    scanner.context.update({
        "own_id": 100,
        "own_email": "test@example.com",
        "own_username": "testuser",
        "test_id": 101,
    })

    print("[PASS] Scanner initialized")
    print("[PASS] Test context initialized")
    print()

    tests = [
        ("basic variable", "{{own_id}}", "100"),
        ("int filter", "{{own_id|int}}", "100"),
        ("integer +1", "{{own_id|int+1}}", "101"),
        ("integer -1", "{{own_id|int-1}}", "99"),
        ("string filter", "{{own_id|str}}", "100"),
        ("hex filter", "{{own_id|hex}}", "0x64"),
        ("base64 filter", "{{own_id|base64}}", "MTAw"),
        ("email", "{{own_email}}", "test@example.com"),
        ("test ID", "{{test_id}}", "101"),
    ]

    failures = 0

    print("-" * 60)
    print("FILTER TESTS")
    print("-" * 60)

    for name, expression, expected in tests:
        try:
            result = scanner._substitute(expression)

            if result == expected:
                print(
                    f"[PASS] {name:20} "
                    f"{expression:25} -> {result}"
                )
            else:
                failures += 1
                print(
                    f"[FAIL] {name:20} "
                    f"{expression:25} -> {result!r} "
                    f"(expected {expected!r})"
                )

        except Exception as exc:
            failures += 1
            print(
                f"[FAIL] {name:20} "
                f"{expression:25} -> ERROR: {exc}"
            )

    print()
    print("-" * 60)
    print("STRUCTURED VALUE TESTS")
    print("-" * 60)

    structured_tests = [
        (
            "list",
            ["{{own_id}}", "{{own_id|int+1}}"],
            ["100", "101"],
        ),
        (
            "dict",
            {
                "id": "{{own_id}}",
                "next": "{{own_id|int+1}}",
            },
            {
                "id": "100",
                "next": "101",
            },
        ),
    ]

    for name, value, expected in structured_tests:
        try:
            result = scanner._substitute(value)

            if result == expected:
                print(f"[PASS] {name:20} -> {result}")
            else:
                failures += 1
                print(
                    f"[FAIL] {name:20} -> {result!r} "
                    f"(expected {expected!r})"
                )

        except Exception as exc:
            failures += 1
            print(
                f"[FAIL] {name:20} -> ERROR: {exc}"
            )

    print()
    print("-" * 60)
    print("BOLA PATH RENDERING TEST")
    print("-" * 60)

    bola_path = "/api/users/{{own_id|int+1}}"

    try:
        rendered = scanner._substitute(bola_path)
        expected = "/api/users/101"

        if rendered == expected:
            print(f"[PASS] {bola_path} -> {rendered}")
        else:
            failures += 1
            print(
                f"[FAIL] {bola_path} -> {rendered!r} "
                f"(expected {expected!r})"
            )

    except Exception as exc:
        failures += 1
        print(f"[FAIL] BOLA path rendering -> ERROR: {exc}")

    print()
    print("=" * 60)

    if failures == 0:
        print("RESULT: PASS")
        print("Scanner and TemplateRuntime integration works.")
        print("=" * 60)
        return 0

    print(f"RESULT: FAIL ({failures} test(s) failed)")
    print("=" * 60)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
