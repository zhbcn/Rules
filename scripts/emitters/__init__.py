"""Five-client native rule emitters for zhbcn/Rules."""
from .common import CompiledBundle, EmitStats, compile_bundles, load_bundles, load_patches
from .egern import emit_egern
from .loon import emit_loon
from .mihomo_stash import emit_mihomo_stash, find_mihomo_bin
from .quantumultx import emit_quantumultx

__all__ = [
    "CompiledBundle",
    "EmitStats",
    "compile_bundles",
    "load_bundles",
    "load_patches",
    "find_mihomo_bin",
    "emit_mihomo_stash",
    "emit_egern",
    "emit_loon",
    "emit_quantumultx",
]
