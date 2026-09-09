"""
llm_client.py — the single shared Ollama client instance/config.

Everything in this package that talks to the LLM (the fine-tuned
cybersecqwen model doing per-source DETECTED/CLEAN judgments, and its
general-purpose explanation/log-classification calls) imports the SAME
configured instance from here, instead of each defining its own.
"""

import os
from langchain_ollama import ChatOllama

# Without an explicit request timeout, a stuck/overloaded Ollama call blocks
# forever with no signal to distinguish "slow" from "hung" — this bounds it so
# a genuinely stuck call fails with a clear exception instead. Every call site
# still has its own try/except degrading to a safe default, so this timeout
# firing never crashes the workflow, just cuts a bad call short.
MODEL_REQUEST_TIMEOUT_SECONDS = float(os.getenv("MODEL_REQUEST_TIMEOUT_SECONDS", "120"))

# Set MODEL_NUM_GPU=0 to force pure CPU inference (zero layers offloaded to
# GPU) for a controlled A/B test against the default GPU-assisted path. When
# a model doesn't fully fit in VRAM, Ollama splits it across GPU+CPU, and
# every forward pass then pays a PCIe round-trip moving activations between
# the two on every token — that split mode can be slower than running the
# whole model on CPU in one memory space with no cross-device copying at all.
# Left unset, Ollama auto-decides layer placement as it always has.
MODEL_NUM_GPU = os.getenv("MODEL_NUM_GPU")

_model_kwargs = {
    "model": os.getenv("MODEL_NAME", "cybersecqwen"),
    "num_keep": 0,
    "sync_client_kwargs": {"timeout": MODEL_REQUEST_TIMEOUT_SECONDS},
}
if MODEL_NUM_GPU is not None:
    _model_kwargs["num_gpu"] = int(MODEL_NUM_GPU)

model = ChatOllama(**_model_kwargs)

# The exact system prompt cybersecqwen was fine-tuned on (see
# cybersecqwen_finetune/SESSION_SUMMARY.md / model/Modelfile) — every
# per-source DETECTED/CLEAN judgment call in analysis.py must use this
# verbatim, since the model's training rows all pair this system prompt with
# a "Source: {attack_type}\n\nContent:\n{content}" user message.
CYBERSECQWEN_JUDGE_SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. Given the raw content of a security-relevant file or log entry, "
    "state whether it shows DETECTED (an attack/incident indicator) or CLEAN (normal, healthy behavior), "
    "and explain why in 1-3 sentences, citing the specific detail in the content that supports your "
    "conclusion. Be literal and precise about what the content actually says."
)
