import difflib
import json
import re
import time
import random
from typing import Dict, Any, Optional
from engine.requester import Requester, HTTPResponseResult

class VerificationVerdict:
    def __init__(
        self,
        is_confirmed: bool,
        confidence: float,
        verdict_reason: str,
        control_request: str = "",
        control_response: str = "",
        mutation_request: str = "",
        mutation_response: str = "",
        differential_proof: str = ""
    ):
        self.is_confirmed = is_confirmed
        self.confidence = confidence
        self.verdict_reason = verdict_reason
        self.control_request = control_request
        self.control_response = control_response
        self.mutation_request = mutation_request
        self.mutation_response = mutation_response
        self.differential_proof = differential_proof

class VerificationStateMachine:
    @staticmethod
    async def verify_sensitive_file(
        requester: Requester,
        base_url: str,
        file_path: str,
        signature_regex: str
    ) -> VerificationVerdict:
        clean_base = base_url.rstrip("/")
        canary_path = f"{clean_base}/vf_canary_notfound_{int(time.time())}"
        control_res = await requester.send("GET", canary_path, module="verify_control")
        target_path = f"{clean_base}{file_path}"
        mutation_res = await requester.send("GET", target_path, module="verify_mutation")

        if mutation_res.status_code != 200:
            return VerificationVerdict(False, 0.0, f"Status {mutation_res.status_code} != 200", control_res.raw_request, control_res.raw_response, mutation_res.raw_request, mutation_res.raw_response)

        content_type = mutation_res.headers.get("content-type", "").lower()
        if "text/html" in content_type and any(file_path.endswith(ext) for ext in [".env", ".git", ".sql", ".key", ".zip", ".bak"]):
            return VerificationVerdict(False, 0.0, "Rejected SPA HTML catch-all page", control_res.raw_request, control_res.raw_response, mutation_res.raw_request, mutation_res.raw_response)

        if control_res.status_code == 200:
            similarity = difflib.SequenceMatcher(None, mutation_res.body[:1500], control_res.body[:1500]).quick_ratio()
            if similarity > 0.85:
                return VerificationVerdict(False, 0.0, f"Soft-404 ({similarity*100:.1f}% match)", control_res.raw_request, control_res.raw_response, mutation_res.raw_request, mutation_res.raw_response)

        match = re.search(signature_regex, mutation_res.body, re.IGNORECASE | re.MULTILINE)
        if match:
            return VerificationVerdict(True, 1.0, f"Matched signature '{match.group(0)}'", control_res.raw_request, control_res.raw_response, mutation_res.raw_request, mutation_res.raw_response, f"Verified signature on {file_path}")

        return VerificationVerdict(False, 0.1, "No signature match", control_res.raw_request, control_res.raw_response, mutation_res.raw_request, mutation_res.raw_response)

    @staticmethod
    async def verify_mass_assignment(
        requester: Requester,
        base_url: str,
        endpoint_path: str,
        privileged_field: str,
        privileged_value: Any
    ) -> VerificationVerdict:
        target = f"{base_url.rstrip('/')}{endpoint_path}"
        
        # Distinct unique emails for control and mutation to prevent uniqueness constraint collisions
        t_id = int(time.time())
        rand_val = random.randint(1000, 9999)
        control_email = f"control_user_{t_id}_{rand_val}@example.com"
        mutation_email = f"mutation_admin_{t_id}_{rand_val + 1}@example.com"

        # 1. CONTROL TEST (Normal user creation)
        control_payload = {"email": control_email, "password": "Password123!"}
        control_res = await requester.send("POST", target, json_data=control_payload, module="verify_control")

        # 2. MUTATION TEST (Admin privilege escalation)
        mutation_payload = {"email": mutation_email, "password": "Password123!", privileged_field: privileged_value}
        mutation_res = await requester.send("POST", target, json_data=mutation_payload, module="verify_mutation")

        # 3. IMPACT ANALYSIS
        if mutation_res.status_code in [200, 201]:
            content_type = mutation_res.headers.get("content-type", "").lower()
            if "text/html" not in content_type:
                try:
                    data = json.loads(mutation_res.body)
                    user_data = data.get("data", data)
                    if isinstance(user_data, dict):
                        actual_val = user_data.get(privileged_field)
                        if str(actual_val).lower() == str(privileged_value).lower():
                            return VerificationVerdict(
                                True, 1.0,
                                f"Server persisted elevated parameter '{privileged_field}': '{actual_val}' in response JSON.",
                                control_res.raw_request, control_res.raw_response,
                                mutation_res.raw_request, mutation_res.raw_response,
                                f"Control created standard user; Mutation created user with {privileged_field}='{actual_val}'."
                            )
                except Exception:
                    pass

        return VerificationVerdict(False, 0.0, "Elevated parameter was not persisted", control_res.raw_request, control_res.raw_response, mutation_res.raw_request, mutation_res.raw_response)
