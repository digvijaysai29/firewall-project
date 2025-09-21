import os
import time
import logging
from typing import Dict, Tuple, Optional


# Environment configuration
ML_DETECTOR_ENABLED = os.getenv('ML_DETECTOR_ENABLED', '0') == '1'
LLM_MODEL_PATH = os.getenv('LLM_MODEL_PATH', '').strip()
LLM_CTX_SIZE = int(os.getenv('LLM_CTX_SIZE', '2048'))
LLM_THREADS = int(os.getenv('LLM_THREADS', str(os.cpu_count() or 2)))
LLM_N_GPU_LAYERS = int(os.getenv('LLM_N_GPU_LAYERS', '0'))

ML_DETECT_RATE_LIMIT_PER_SEC = float(os.getenv('ML_DETECT_RATE_LIMIT_PER_SEC', '1'))
ML_DETECT_CACHE_TTL_SEC = float(os.getenv('ML_DETECT_CACHE_TTL_SEC', '300'))
ML_DETECT_MAX_TOKENS = int(os.getenv('ML_DETECT_MAX_TOKENS', '8'))
ML_DETECT_TEMPERATURE = float(os.getenv('ML_DETECT_TEMPERATURE', '0'))
ML_DETECT_ENFORCE = os.getenv('ML_DETECT_ENFORCE', '0') == '1'


_logger = logging.getLogger(__name__)

_llm = None
_last_detection_ts = 0.0
_detection_cache: Dict[str, Tuple[float, str, str]] = {}


def _load_model_if_needed() -> Optional[object]:
    """Lazily initialize the llama.cpp model. Returns None if disabled/unavailable."""
    global _llm
    if not ML_DETECTOR_ENABLED:
        return None
    if not LLM_MODEL_PATH:
        _logger.warning('ML detector enabled but LLM_MODEL_PATH is not set. Detector disabled.')
        return None
    if _llm is not None:
        return _llm
    try:
        from llama_cpp import Llama  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency
        _logger.warning('llama-cpp-python not installed or failed to import: %s. Detector disabled.', exc)
        return None

    if not os.path.exists(LLM_MODEL_PATH):
        _logger.warning('LLM model not found at %s. Detector disabled.', LLM_MODEL_PATH)
        return None

    _logger.info('Loading LLM model from %s (ctx=%s, threads=%s, gpu_layers=%s)...',
                 LLM_MODEL_PATH, LLM_CTX_SIZE, LLM_THREADS, LLM_N_GPU_LAYERS)
    _llm = Llama(
        model_path=LLM_MODEL_PATH,
        n_ctx=LLM_CTX_SIZE,
        n_threads=LLM_THREADS,
        n_gpu_layers=LLM_N_GPU_LAYERS
    )
    return _llm


def _cleanup_cache(now: float) -> None:
    if not _detection_cache:
        return
    expiry_threshold = now - ML_DETECT_CACHE_TTL_SEC
    keys_to_delete = [key for key, (ts, _, __) in _detection_cache.items() if ts < expiry_threshold]
    for key in keys_to_delete:
        _detection_cache.pop(key, None)


def _rate_limited(now: float) -> bool:
    global _last_detection_ts
    if ML_DETECT_RATE_LIMIT_PER_SEC <= 0:
        return True
    min_interval = 1.0 / ML_DETECT_RATE_LIMIT_PER_SEC
    if now - _last_detection_ts < min_interval:
        return True
    _last_detection_ts = now
    return False


def _build_prompt(metadata: Dict[str, str]) -> str:
    """Build a compact prompt for fast classification. Keep under a few hundred tokens."""
    parts = [
        'You are a strict network firewall classifier. Given packet metadata, output one word: allow or block.\n',
        'Criteria (heuristic): block known malicious IPs or obvious scans/exfiltration; otherwise allow.\n',
        'Respond with only: allow or block.\n',
        f"src_ip={metadata.get('src_ip','')}",
        f", dst_ip={metadata.get('dst_ip','')}",
        f", proto={metadata.get('proto','')}",
        f", sport={metadata.get('src_port','')}",
        f", dport={metadata.get('dst_port','')}",
        f", length={metadata.get('length','')}\n",
        'Answer:'
    ]
    return ''.join(parts)


def evaluate_packet(metadata: Dict[str, str]) -> Tuple[str, str]:
    """Evaluate packet metadata with local LLM.

    Returns (decision, reason) where decision in {"allow", "block", "skip"}.
    """
    now = time.monotonic()
    _cleanup_cache(now)

    # Disabled or missing model -> skip quickly
    llm = _load_model_if_needed()
    if llm is None:
        return 'allow', 'ml_disabled'

    # Cache key
    cache_key = f"{metadata.get('src_ip','')}->{metadata.get('dst_ip','')}|{metadata.get('proto','')}|{metadata.get('src_port','')}|{metadata.get('dst_port','')}"
    cached = _detection_cache.get(cache_key)
    if cached and now - cached[0] < ML_DETECT_CACHE_TTL_SEC:
        return cached[1], cached[2]

    # Rate limit
    if _rate_limited(now):
        return 'allow', 'rate_limited'

    prompt = _build_prompt(metadata)
    try:
        # Small, fast completion
        result = llm.create_completion(
            prompt=prompt,
            max_tokens=ML_DETECT_MAX_TOKENS,
            temperature=ML_DETECT_TEMPERATURE,
            stop=["\n"]
        )
        text = (result.get('choices', [{}])[0].get('text') or '').strip().lower()
        decision = 'block' if text.startswith('block') else 'allow'
        reason = f"llm:{text[:16] or 'empty'}"
    except Exception as exc:  # pragma: no cover - inference errors
        _logger.warning('LLM inference failed: %s', exc)
        decision, reason = 'allow', 'ml_error'

    _detection_cache[cache_key] = (now, decision, reason)
    return decision, reason

