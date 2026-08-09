#!/usr/bin/env python3

import base64
import hashlib
import itertools
import re
import secrets
from typing import Any, Dict, Iterable, List


class TemplateRuntime:
    """
    Safe runtime for VulnForge template variables.

    Supported variables:
        {{variable}}
        {{random}}

    Supported filters:
        {{variable|int}}
        {{variable|str}}
        {{variable|lower}}
        {{variable|upper}}
        {{variable|len}}
        {{variable|base64}}
        {{variable|md5}}
        {{variable|sha1}}
        {{variable|hex}}

    Supported arithmetic:
        {{id|int+1}}
        {{id|int-1}}
    """

    TOKEN_RE = re.compile(r"{{\s*([^{}]+?)\s*}}")

    def __init__(self) -> None:
        self.variables: Dict[str, Any] = {}

    def set_variables(self, variables: Dict[str, Any]) -> None:
        if variables:
            self.variables.update(variables)

    def update_variables(self, variables: Dict[str, Any]) -> None:
        if variables:
            self.variables.update(variables)

    def get_variables(self) -> Dict[str, Any]:
        return dict(self.variables)

    def clear_variables(self) -> None:
        self.variables.clear()

    def render(
        self,
        value: Any,
        variables: Dict[str, Any] = None
    ) -> Any:
        """
        Recursively render strings, lists and dictionaries.
        """

        context = dict(self.variables)

        if variables:
            context.update(variables)

        if value is None:
            return None

        if isinstance(value, str):
            return self._render_string(value, context)

        if isinstance(value, list):
            return [
                self.render(item, context)
                for item in value
            ]

        if isinstance(value, tuple):
            return tuple(
                self.render(item, context)
                for item in value
            )

        if isinstance(value, dict):
            return {
                key: self.render(item, context)
                for key, item in value.items()
            }

        return value

    def _render_string(
        self,
        text: str,
        context: Dict[str, Any]
    ) -> str:
        """
        Replace all {{...}} expressions in a string.
        """

        def replace(match: re.Match) -> str:
            expression = match.group(1).strip()

            result = self.evaluate(
                expression,
                context
            )

            return str(result)

        return self.TOKEN_RE.sub(
            replace,
            text
        )

    def evaluate(
        self,
        expression: str,
        context: Dict[str, Any] = None
    ) -> Any:
        """
        Evaluate one template expression.
        """

        expression = expression.strip()

        if context is None:
            context = self.variables

        # --------------------------------------------------
        # Random token
        # --------------------------------------------------

        if expression == "random":
            return self._random_value()

        # --------------------------------------------------
        # Split filters
        # --------------------------------------------------

        parts = [
            part.strip()
            for part in expression.split("|")
            if part.strip()
        ]

        if not parts:
            return "{{" + expression + "}}"

        variable_name = parts[0]

        # --------------------------------------------------
        # Variable lookup
        # --------------------------------------------------

        if variable_name not in context:
            return "{{" + expression + "}}"

        value = context[variable_name]

        # --------------------------------------------------
        # Apply filters
        # --------------------------------------------------

        for operation in parts[1:]:
            value = self._apply_operation(
                value,
                operation
            )

        return value

    @staticmethod
    def _random_value() -> str:
        """
        Generate a cryptographically secure random token.
        """

        return secrets.token_hex(8)

    def _apply_operation(
        self,
        value: Any,
        operation: str
    ) -> Any:
        """
        Apply one supported operation.
        """

        operation = operation.strip()

        # --------------------------------------------------
        # Integer conversion
        # --------------------------------------------------

        if operation == "int":
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        # --------------------------------------------------
        # String conversion
        # --------------------------------------------------

        if operation == "str":
            return str(value)

        # --------------------------------------------------
        # Lowercase
        # --------------------------------------------------

        if operation == "lower":
            return str(value).lower()

        # --------------------------------------------------
        # Uppercase
        # --------------------------------------------------

        if operation == "upper":
            return str(value).upper()

        # --------------------------------------------------
        # Length
        # --------------------------------------------------

        if operation == "len":
            try:
                return len(value)
            except TypeError:
                return len(str(value))

        # --------------------------------------------------
        # Base64
        # --------------------------------------------------

        if operation == "base64":
            raw = str(value).encode("utf-8")

            return base64.b64encode(
                raw
            ).decode("ascii")

        # --------------------------------------------------
        # MD5
        # --------------------------------------------------

        if operation == "md5":
            return hashlib.md5(
                str(value).encode("utf-8")
            ).hexdigest()

        # --------------------------------------------------
        # SHA1
        # --------------------------------------------------

        if operation == "sha1":
            return hashlib.sha1(
                str(value).encode("utf-8")
            ).hexdigest()

        # --------------------------------------------------
        # SHA256
        # --------------------------------------------------

        if operation == "sha256":
            return hashlib.sha256(
                str(value).encode("utf-8")
            ).hexdigest()

        # --------------------------------------------------
        # Hex
        # --------------------------------------------------

        if operation == "hex":
            try:
                return hex(int(value))
            except (TypeError, ValueError):
                return str(value).encode(
                    "utf-8"
                ).hex()

        # --------------------------------------------------
        # Arithmetic
        #
        # int+1
        # int-1
        # --------------------------------------------------

        arithmetic = re.fullmatch(
            r"int\s*([+-])\s*(\d+)",
            operation
        )

        if arithmetic:
            try:
                number = int(value)
            except (TypeError, ValueError):
                return value

            amount = int(
                arithmetic.group(2)
            )

            if arithmetic.group(1) == "+":
                return number + amount

            return number - amount

        # --------------------------------------------------
        # Replace last character
        # --------------------------------------------------

        replace_last = re.fullmatch(
            r"replace_last_char\((.*?)\)",
            operation
        )

        if replace_last:
            replacement = (
                replace_last.group(1)
                .strip("'\"")
            )

            value_string = str(value)

            if not value_string:
                return value

            return (
                value_string[:-1]
                + replacement
            )

        # --------------------------------------------------
        # Unknown operation
        # --------------------------------------------------

        return value

    def expand_payloads(
        self,
        payloads: Dict[str, Iterable[Any]]
    ) -> List[Dict[str, Any]]:
        """
        Expand payload dictionaries into Cartesian
        combinations.

        Example:

            {
                "id": [1, 2],
                "role": ["user", "admin"]
            }

        becomes:

            [
                {"id": 1, "role": "user"},
                {"id": 1, "role": "admin"},
                {"id": 2, "role": "user"},
                {"id": 2, "role": "admin"}
            ]
        """

        if not payloads:
            return [{}]

        keys = list(payloads.keys())

        values = []

        for key in keys:
            value = payloads[key]

            if isinstance(value, (str, bytes)):
                values.append([value])
            else:
                values.append(list(value))

        combinations = itertools.product(
            *values
        )

        return [
            dict(zip(keys, combination))
            for combination in combinations
        ]
