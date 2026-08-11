# core/differential.py - FIXED & ADVANCED (nuclei + sqlmap style differential)
import re
import time
from difflib import SequenceMatcher
from typing import Optional

class ResponseFingerprint:
    """
    Unified fingerprint for differential comparison.
    status: HTTP status
    length: content length (bytes)
    body: decoded body (truncated)
    elapsed: response time seconds
    """
    def __init__(self, status: int, length: int, body: str, elapsed: float):
        self.status = int(status) if status is not None else 0
        self.length = int(length) if length is not None else 0
        self.body = body or ""
        self.elapsed = float(elapsed) if elapsed is not None else 0.0

    def __repr__(self):
        return f"FP(status={self.status}, len={self.length}, time={self.elapsed:.2f})"

class DifferentialResult:
    def __init__(self, is_significant: bool, reason: str = "", confidence: float = 0.0):
        self.is_significant = is_significant
        self.reason = reason
        self.confidence = confidence

    def __bool__(self):
        return self.is_significant

# Helpers
def _similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Quick length ratio filter before expensive sequence matcher
    len_a, len_b = len(a), len(b)
    if max(len_a, len_b) == 0:
        return 1.0
    len_ratio = min(len_a, len_b) / max(len_a, len_b)
    if len_ratio < 0.5:
        return len_ratio * 0.5  # very different lengths -> low similarity
    # Sample first 2000 chars for performance
    return SequenceMatcher(None, a[:2000], b[:2000]).quick_ratio()

def _status_interesting_diff(s1: int, s2: int, baseline: int = 200) -> bool:
    # 404 vs 200 is not interesting, but 500 vs 200 might be for SQLi error-based
    if s1 == s2:
        return False
    # If one is 200 and other !=200, that's interesting for boolean-based
    if (s1 == 200 and s2 != 200) or (s2 == 200 and s1 != 200):
        return True
    return s1 != s2

def compare_boolean_responses(baseline: ResponseFingerprint, true_resp: ResponseFingerprint, false_resp: ResponseFingerprint) -> DifferentialResult:
    """
    Advanced boolean differential (true condition vs false condition).
    Logic inspired by sqlmap/nuclei:
    - TRUE should be similar to baseline (or at least 200)
    - FALSE should be different from TRUE in meaningful way
    - Difference should not be just small noise: >5% length delta or content similarity <0.9
    - Status differences matter
    Returns DifferentialResult.
    """
    t_len, f_len = true_resp.length, false_resp.length
    t_status, f_status = true_resp.status, false_resp.status
    t_body, f_body = true_resp.body, false_resp.body

    # Baseline similarity check - TRUE should resemble baseline if baseline provided
    true_to_base_sim = _similarity(t_body, baseline.body) if baseline.body else 1.0
    false_to_base_sim = _similarity(f_body, baseline.body) if baseline.body else 0.0
    true_false_sim = _similarity(t_body, f_body)

    # Logging reasons
    reasons = []

    # 1. Status check
    if _status_interesting_diff(t_status, f_status, baseline.status):
        reasons.append(f"status diff true={t_status} false={f_status}")
    
    # 2. Length delta
    len_delta = abs(t_len - f_len)
    len_ratio = (len_delta / max(t_len, 1)) if max(t_len, f_len) > 0 else 0
    if len_ratio > 0.05 or len_delta > 50:  # >5% or >50 bytes
        reasons.append(f"len diff {t_len} vs {f_len} ({len_ratio*100:.1f}%)")

    # 3. Content similarity - should be < threshold for significant difference
    if true_false_sim < 0.9:
        reasons.append(f"content similarity low {true_false_sim:.2f}")
    
    # 4. Baseline coherence: TRUE should be more similar to baseline than FALSE is
    # e.g., baseline= normal page, true= still normal, false= different/error
    baseline_coherent = (true_to_base_sim > false_to_base_sim + 0.05) or (true_to_base_sim > 0.85 and false_to_base_sim < 0.8)
    if baseline_coherent:
        reasons.append(f"baseline coherence true={true_to_base_sim:.2f} false={false_to_base_sim:.2f}")

    # Decision logic - need at least one strong signal + not too similar
    # Strong signals: status diff, length >5% + similarity <0.95, or baseline coherence + similarity <0.9
    is_sig = False
    confidence = 0.0

    if reasons:
        # If content similarity is VERY high ( >0.98 ) and length delta tiny, it's likely not injectable
        if true_false_sim > 0.97 and len_delta < 20 and t_status == f_status:
            return DifferentialResult(False, f"Too similar sim={true_false_sim:.2f} len_delta={len_delta}", 0.0)
        
        # If we have status diff alone, moderate confidence
        if any("status" in r for r in reasons):
            is_sig = True
            confidence = 0.65

        # Length + similarity combo -> high confidence boolean SQLi typical
        if (len_ratio > 0.05 or len_delta > 100) and true_false_sim < 0.95:
            is_sig = True
            confidence = max(confidence, 0.80)

        # Baseline coherence is strong indicator for blind boolean
        if baseline_coherent and true_false_sim < 0.90:
            is_sig = True
            confidence = max(confidence, 0.85)

        # If only length diff but similarity still high, low confidence but still possible
        if len(reasons) >= 2:
            is_sig = True
            confidence = max(confidence, 0.70)

    if is_sig:
        return DifferentialResult(True, " | ".join(reasons), confidence)
    return DifferentialResult(False, f"No sig diff sim={true_false_sim:.2f} len_delta={len_delta} status {t_status}/{f_status}", 0.0)

def compare_timing_responses(baseline: ResponseFingerprint, probe_resp: ResponseFingerprint, confirm_resp: ResponseFingerprint) -> DifferentialResult:
    """
    Timing differential for time-based blind (like nuclei time matcher + sqlmap).
    Requires reproducibility: both probe and confirm must exceed threshold vs baseline,
    and confirm must not be just network jitter.
    """
    base_time = baseline.elapsed if baseline.elapsed > 0 else 0.5
    probe_time = probe_resp.elapsed
    confirm_time = confirm_resp.elapsed

    # Minimum absolute thresholds - to avoid flagging 0.1s -> 0.3s jitter as injection
    min_delay = 3.0  # expected injection sleep time, from payload SLEEP(5) etc.
    # Extract expected delay from payload? For now heuristic 3 sec min.

    reasons = []

    # Both probe and confirm should be significantly slower than baseline
    if probe_time >= base_time + 2.5:
        reasons.append(f"probe {probe_time:.2f}s > baseline {base_time:.2f}s+2.5s")
    if confirm_time >= base_time + 2.5:
        reasons.append(f"confirm {confirm_time:.2f}s > baseline {base_time:.2f}s+2.5s")

    # Both should be absolutely > threshold (e.g., >3s for SLEEP 5)
    if probe_time >= min_delay and confirm_time >= min_delay:
        reasons.append(f"both >= {min_delay}s (probe {probe_time:.1f}s confirm {confirm_time:.1f}s)")

    # Confirm should reproduce probe (within reasonable ratio, not 10x)
    # If probe 6s and confirm 0.5s, that's jitter, not repro
    repro_ratio = confirm_time / probe_time if probe_time > 0 else 0
    if 0.5 <= repro_ratio <= 2.0:
        reasons.append(f"repro ratio {repro_ratio:.2f}")

    # Strong check: both >5s and similar -> very high confidence time-based
    if probe_time >= 5 and confirm_time >= 5 and 0.5 <= repro_ratio <= 2.0:
        return DifferentialResult(True, " | ".join(reasons), 0.90)

    # Moderate: both >=3s and reproduce
    if probe_time >= 3 and confirm_time >= 3 and 0.3 <= repro_ratio <= 3.0 and len(reasons) >= 2:
        return DifferentialResult(True, " | ".join(reasons), 0.75)

    # Fallback: if confirm is significantly slower than probe *2 and >0.5s absolute (old logic) - keep for compat
    if confirm_time > probe_time * 2 and confirm_time > 0.5 and probe_time > 1:
        return DifferentialResult(True, f"Confirm {confirm_time:.2f}s vs probe {probe_time:.2f}s (x2)", 0.60)

    return DifferentialResult(False, f"No timing repro probe={probe_time:.2f}s confirm={confirm_time:.2f}s base={base_time:.2f}s ratio={repro_ratio:.2f}", 0.0)

def compare_response_length(baseline_len: int, probe_len: int, threshold_ratio: float = 0.10) -> bool:
    """Utility for size-based diff"""
    if baseline_len == 0:
        return probe_len > 0
    return abs(baseline_len - probe_len) / baseline_len > threshold_ratio
