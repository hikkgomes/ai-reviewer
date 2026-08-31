# Anti-slop rule contract

Anti-slop rules produce structural review candidates. They do not prove a
correctness defect and they never become findings without falsification and
semantic verification.

## Required rule fields

Every rule file must define a unique rule ID, explicit language, message,
severity, and metadata containing its contract ID, `structural` analysis level,
confidence, and this document as the contract reference. The implementation
must record the logical path, source layer, line, column, and content hash when
it creates a candidate.

Every rule contract must state:

- Concrete harmful behaviour and why the syntax is evidence.
- What the match does not prove.
- At least three positive and eight meaningful negative examples.
- Malformed-source, generated-code, framework, and suppression behaviour where
  those cases can occur.
- Known false-positive risks, confidence, suggested severity, and remediation.
- Parser-error behaviour and the candidate-only review contract.

Default-enabled rules must meet the complete quality gate: the fixture set
passes, output locations are exact, messages do not overstate syntax, the
curated negative corpus is clean, and a manual sample reaches at least 90%
precision. Structural rules remain narrow and candidate-only when syntax
cannot establish semantic intent.

## Rule catalogue

| Rule ID | Language | Backend | Level | Confidence | Default | Contract boundary |
| --- | --- | --- | --- | --- | --- | --- |
| `anti-slop-python/no-widen-then-cast` | Python | `python-ast` | structural | high | yes | Same-expression `cast(Target, cast(Any/object, value))`; it does not assess justified API or protocol boundaries. |
| `anti-slop-python/no-literal-getattr-without-default` | Python | `python-ast` | structural | medium | yes | Literal non-dunder lookup without a default; it does not prove that direct access is safe or required. |
| `anti-slop/no-chained-type-assertions` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Chained assertions may hide an unsafe narrowing; it does not prove the asserted type is wrong. |
| `anti-slop/no-conditional-empty-object-spread` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Conditional empty object spreads may obscure control flow; it does not prove a runtime defect. |
| `anti-slop/no-known-value-widening` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Known values widened to a less precise type may lose useful guarantees; it does not ban justified boundaries. |
| `anti-slop/no-module-mocking` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Module mocking may hide integration behaviour; it does not prove a test is invalid. |
| `anti-slop/no-object-parameters` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Broad object parameters may weaken an interface; it does not ban deliberate open records. |
| `anti-slop/no-reflect-apply` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Reflective invocation may obscure a direct call contract; it does not prove the call is unsafe. |
| `anti-slop/no-reflect-get` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Reflective property access may obscure a direct member contract; it does not ban dynamic APIs. |
| `anti-slop/no-runtime-typeof` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Runtime type checks may replace a stronger contract; it does not prove the check is redundant. |
| `anti-slop/no-shape-in-symbol-names` | JavaScript/TypeScript | `oxlint-js-ts` | structural | low | yes | Symbol names that describe implementation shape may add generated narration; it does not prove naming is harmful. |
| `anti-slop/no-unknown-parameters` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Unknown parameters may weaken a callable contract; it does not ban untyped external input boundaries. |
| `anti-slop/no-unknown-returns` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Unknown returns may hide a useful output contract; it does not prove the implementation is incorrect. |
| `anti-slop/no-unknown-type-aliases` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Unknown aliases may conceal a type contract; it does not ban deliberate compatibility aliases. |
| `anti-slop/no-unsafe-dictionary-type` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | Unbounded dictionary types may weaken key/value guarantees; it does not ban validated maps. |
| `anti-slop/no-widen-then-assert` | JavaScript/TypeScript | `oxlint-js-ts` | structural | high | yes | Immediate widening followed by assertion may erase and restore a type without proof; it does not assess justified boundaries. |
| `anti-slop/require-safety-comment-for-type-assertion` | JavaScript/TypeScript | `oxlint-js-ts` | structural | medium | yes | A type assertion without the required safety explanation lacks local evidence; it does not prove the assertion is wrong. |
| `anti-slop-effect/no-service-constructor-imports` | TypeScript with Effect | `oxlint-js-ts` | structural | medium | yes | Direct service-constructor imports may bypass the Effect dependency contract; it does not prove runtime failure. |
| `anti-slop-go/no-interface-round-trip` | Go | `ast-grep-go` | structural | high | yes | Immediate `any(value).(Target)` or `interface{}(value).(Target)`; it excludes stored boundaries and type switches. |
| `anti-slop-go/no-reflect-interface-round-trip` | Go | `ast-grep-go` | structural | medium | yes | Immediate `reflect.ValueOf(value).Interface().(Target)`; it does not judge legitimate reflection APIs. |
| `anti-slop-rust/no-same-type-transmute` | Rust | `ast-grep-rust` | structural | high | yes | Textually identical `transmute::<T, T>` source and destination types; it does not resolve aliases or prove runtime layout. |
| `anti-slop-rust/no-immediate-any-round-trip` | Rust | `ast-grep-rust` | structural | medium | yes | Explicit same-expression `Box<dyn Any>` construction and downcast; it does not judge deliberate dynamic registries. |
| `anti-slop-c/no-void-pointer-round-trip` | C | `ast-grep-c` | structural | medium | yes | Immediate object-pointer conversion through `void *`; it does not assess allocator, FFI, callback, or ABI boundaries. |
| `anti-slop-cpp/no-void-pointer-cast-chain` | C++ | `ast-grep-cpp` | structural | medium | yes | Immediate nested cast through `void *`; it does not assess allocators, placement construction, FFI, serialisation, tagging, or ABI. |
| `anti-slop-cpp/no-redundant-same-type-cast` | C++ | `ast-grep-cpp` | structural | medium | yes | Nested casts use identical textual destination syntax; it does not prove resolved C++ type identity. |
| `anti-slop-java/no-object-cast-round-trip` | Java | `ast-grep-java` | structural | high | yes | Same-expression `(Target) (Object) value`; it does not assess generated bridges or serialisation adapters. |
| `anti-slop-java/no-literal-class-reflection` | Java | `ast-grep-java` | structural | medium | yes | Class-literal reflection with a literal member name; it does not assess framework or annotation-processing contracts. |
| `anti-slop-csharp/no-object-cast-round-trip` | C# | `ast-grep-csharp` | structural | high | yes | Same-expression target cast after `object` or `dynamic`; it does not assess boxing across an external boundary. |
| `anti-slop-csharp/no-literal-type-reflection` | C# | `ast-grep-csharp` | structural | medium | yes | `typeof(KnownType).GetMethod/GetProperty("LiteralName")`; it does not assess dynamic type discovery or framework contracts. |

## Fixture and suppression policy

Tests use `valid` examples for expected no-match behaviour and `invalid`
examples for structural candidate behaviour. Parser-error input is retained as
a test of safe failure. Generated examples are excluded by Dissect's explicit
`paths.generated` policy, not by filename guesses. Framework examples remain
negative unless the contract explicitly covers that framework boundary.

Suppression comments and tool-specific suppression directives are respected by
the parser or tool. A suppression is not evidence that a rule is wrong. The
reviewer must decide whether the suppression is justified in the surrounding
contract.

Malformed or unparseable input makes the relevant backend incomplete. Earlier
valid candidates remain available, while public coverage becomes `Not
verified`. A match is always stored with status `candidate`; the rule message
must use terms such as “may”, “candidate”, or “structural” when syntax does not
prove the harmful behaviour.

## Ownership

Each contract has one active owner in
`scripts/dissect_checks/anti_slop/rules.py`. Existing deterministic and legacy
contracts remain in their existing owners. A new AST rule must not duplicate a
deterministic contract. If a contract moves, its stable ID and equivalence
fixtures move with it and the old implementation is removed in the same
change.

## Adding a rule or language

1. Add the language and backend capability to `scripts/language_registry.py`.
2. Add one owner and one rule contract entry.
3. Add the narrowest rule and the required positive, negative, malformed,
   generated, framework, and suppression fixtures.
4. Run the native ast-grep rule tests or the Python AST tests and inspect exact
   locations.
5. Confirm stable candidate IDs, root-bound paths, deterministic ordering, and
   `Checked` versus `Not verified` coverage behaviour.
6. Update the relevant language reference pack and this catalogue.
