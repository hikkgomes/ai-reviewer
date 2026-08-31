"""Stable anti-slop rule identifiers and their owning backends."""
from __future__ import annotations

from types import MappingProxyType


RULE_OWNERS = MappingProxyType({
    # Existing deterministic and legacy contracts.
    "python_mutable_default": "legacy",
    "go_discarded_error": "legacy",
    "go_panic_recover": "legacy",
    "csharp_throw_ex": "legacy",
    "rust_refcell_pattern": "deterministic",
    "broad_exception": "deterministic",
    "empty_exception": "deterministic",
    "robotic_naming": "deterministic",
    # Structural backend contracts.
    "anti-slop-python/no-widen-then-cast": "python-ast",
    "anti-slop-python/no-literal-getattr-without-default": "python-ast",
    "anti-slop/no-chained-type-assertions": "oxlint",
    "anti-slop/no-conditional-empty-object-spread": "oxlint",
    "anti-slop/no-known-value-widening": "oxlint",
    "anti-slop/no-module-mocking": "oxlint",
    "anti-slop/no-object-parameters": "oxlint",
    "anti-slop/no-reflect-apply": "oxlint",
    "anti-slop/no-reflect-get": "oxlint",
    "anti-slop/no-runtime-typeof": "oxlint",
    "anti-slop/no-shape-in-symbol-names": "oxlint",
    "anti-slop/no-unknown-parameters": "oxlint",
    "anti-slop/no-unknown-returns": "oxlint",
    "anti-slop/no-unknown-type-aliases": "oxlint",
    "anti-slop/no-unsafe-dictionary-type": "oxlint",
    "anti-slop/no-widen-then-assert": "oxlint",
    "anti-slop/require-safety-comment-for-type-assertion": "oxlint",
    "anti-slop-effect/no-service-constructor-imports": "oxlint",
    "anti-slop-go/no-interface-round-trip": "ast-grep-go",
    "anti-slop-go/no-reflect-interface-round-trip": "ast-grep-go",
    "anti-slop-rust/no-same-type-transmute": "ast-grep-rust",
    "anti-slop-rust/no-immediate-any-round-trip": "ast-grep-rust",
    "anti-slop-c/no-void-pointer-round-trip": "ast-grep-c",
    "anti-slop-cpp/no-void-pointer-cast-chain": "ast-grep-cpp",
    "anti-slop-cpp/no-redundant-same-type-cast": "ast-grep-cpp",
    "anti-slop-java/no-object-cast-round-trip": "ast-grep-java",
    "anti-slop-java/no-literal-class-reflection": "ast-grep-java",
    "anti-slop-csharp/no-object-cast-round-trip": "ast-grep-csharp",
    "anti-slop-csharp/no-literal-type-reflection": "ast-grep-csharp",
})


def owner_for(rule_id: str) -> str | None:
    return RULE_OWNERS.get(rule_id)
