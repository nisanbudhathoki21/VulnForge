#!/usr/bin/env python3

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from engine.template_validator import validate_directory


def main():
    templates_dir = PROJECT_ROOT / "templates"

    valid, errors = validate_directory(
        str(templates_dir)
    )

    print()
    print("=" * 60)
    print("VULNFORGE TEMPLATE VALIDATOR")
    print("=" * 60)

    print(f"\nValid templates   : {len(valid)}")
    print(f"Invalid templates : {len(errors)}")

    for path, template in valid:
        print(
            f"[OK]   {path} -> "
            f"{template.get('id', 'unknown')}"
        )

    for path, error in errors:
        print(
            f"[FAIL] {path}\n"
            f"       {error}"
        )

    print()

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
