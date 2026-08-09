# core/differential.py
import time

class ResponseFingerprint:
    def __init__(self, status, length, body, elapsed):
        self.status = status
        self.length = length
        self.body = body
        self.elapsed = elapsed

class DifferentialResult:
    def __init__(self, is_significant, reason=""):
        self.is_significant = is_significant
        self.reason = reason

def compare_boolean_responses(baseline, true_resp, false_resp):
    """
    Compare true and false responses against a baseline.
    Returns DifferentialResult.
    """
    # Heuristic: if true and false differ in status, length, or content,
    # and the difference is meaningful (not just a 404 vs 200)
    true_len = true_resp.length
    false_len = false_resp.length
    true_status = true_resp.status
    false_status = false_resp.status

    # If both have same status and similar length, probably not injectable
    if true_status == false_status and abs(true_len - false_len) < 50:
        return DifferentialResult(False, "No significant difference")

    # Check for content difference: we can use simple presence of known patterns
    # For demo, any status/length difference beyond noise is significant
    if true_status != false_status or abs(true_len - false_len) > 20:
        return DifferentialResult(True, "Status/length differed")

    return DifferentialResult(False, "Too similar")

def compare_timing_responses(baseline, probe_resp, confirm_resp):
    """
    Compare timing between probe and confirm requests.
    """
    probe_time = probe_resp.elapsed
    confirm_time = confirm_resp.elapsed
    # If confirm is significantly slower than probe (e.g., > 2x)
    if confirm_time > probe_time * 2 and confirm_time > 0.5:
        return DifferentialResult(True, f"Confirm time {confirm_time:.2f}s vs probe {probe_time:.2f}s")
    return DifferentialResult(False, "No timing difference")
