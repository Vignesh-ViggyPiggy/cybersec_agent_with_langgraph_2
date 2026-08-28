"""
llm_client.py — the single shared Ollama client instance/config.

Moved out of test_legacy_log_aggregation.py (now removed) so both
attack_status_workflow.py and lib/log_analysis_workflow.py can import the
SAME configured model instead of each defining their own, or one importing
it from the other by convention.
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
