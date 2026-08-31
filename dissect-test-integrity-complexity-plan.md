# Dissect: implementation audit and next implementation plan

## Reference state

Use this repository state as the audit reference:

- Repository: `hikkgomes/dissect`
- Branch: `main`
- Commit: `625984ad1a895cf42c2ac701bc3fbde74efd33ef`
- Commit message: `feat: add bounded multi-language review analysis`
- Parent: `b9373cca22c97de84c12c5ad48c5980d9c39c09e`

The branch can move after this plan is written. Record the actual starting commit before any change. Preserve all newer work. Do not reset or overwrite unrelated changes.

## Audit verdict

The implementation is materially better than the previous version. The language detector, process supervisor, bounded file scopes, source snapshots, backend structure, installer verification, and coverage model are real improvements.

The implementation is not yet reliable enough to use as proof that a check or test is useful. It contains the exact failure pattern that this next change must prevent: a unit test caused special control flow to be added to production code.

Do not treat the current green CI result as proof that the new rules are correct. The current CI proves that the current tests pass. It does not prove that the tests can detect a wrong implementation, that the rule fixtures are valid programs, or that each rule has acceptable precision.

## Confirmed strengths to preserve

Preserve these behaviours unless a failing contract test proves that they are wrong:

1. One central language registry is used for full and diff language detection.
2. Mandatory context and detector failures stop the shell workflow.
3. Unsupported files are removed from comment analysis before normal file reads.
4. The generic comment extractor uses a forward-only cursor.
5. Comment and anti-slop analysis have file, byte, candidate, and time budgets.
6. The context hard timeout is enforced by a supervisor process.
7. Diff analysis can materialise commit, index, worktree, and untracked source states.
8. Identical source content can be merged across source layers.
9. Oxlint, Python AST, and ast-grep use a shared backend result model.
10. Oxlint and ast-grep are skill-local and version-pinned.
11. No applicable backend maps to `Not applicable`.
12. Applicable but incomplete analysis maps to `Not verified`.
13. All analyser output remains candidate evidence. It does not become a final finding without review.
14. Review command execution uses the existing explicit approval and executable snapshot model.

## Confirmed defects and false-assurance risks

Fix these before the new feature work.

### A. Test-only production path in the context CLI

`scripts/build_review_context.py` contains an in-process branch that detects when `build` is no longer a normal `types.FunctionType`. It then runs the replacement in a daemon thread and returns without the normal supervisor and output contract.

This branch exists to support a monkey-patched timeout test. It is production behaviour created for a test. It can bypass normal output validation and can return success without producing the requested context file.

Required correction:

- Delete the `types.FunctionType` and daemon-thread branch.
- Delete the related imports.
- Test the real supervisor with a real worker fixture or a private worker command.
- Require the same process, output, timeout, validation, and cleanup path in tests and production.

### B. Comment density performs a second unbudgeted scan

`_comment_density()` calls comment extraction before `scan_comment_targets()` performs the bounded scan.

Problems:

- Each diff target can be parsed twice.
- The first pass does not claim the comment analyser file and byte budgets.
- The first pass does not use the per-file deadline.
- Logical-path dictionaries can pair ranges from one source layer with text from another source layer when staged and worktree content differ.

Required correction:

- Remove the pre-scan.
- Compute changed-line and comment counts during the bounded target scan.
- Key all snapshot data by a stable target identity, not only by logical path.
- Use `(logical_path, source_layer, content_sha256)` as the minimum target key.
- Return aggregate density evidence from the scanner result.

### C. Per-file comment timeout is only cooperative

The comment scanner checks a deadline at selected points. A large `SequenceMatcher` or another single expensive operation cannot be interrupted by that check.

Required correction:

- Remove unbounded full-text similarity work.
- Limit the maximum comment text, following-code text, and token count used by similarity checks.
- Prefer bounded token overlap and bounded edit distance over `SequenceMatcher` on arbitrary text.
- Check the deadline before and after each bounded scoring stage.
- Stop processing new files after a terminal analyser budget is exhausted. Do not append one repeated skip for every remaining file.

### D. Anti-slop reads and hashes files before budget enforcement

`orchestrator.build_targets()` hashes files before the backend claims file and aggregate byte budgets. The backend then reads each file again.

Required correction:

- Build targets from one bounded source read.
- Claim file and aggregate bytes before or during that read.
- Reuse the same bytes and SHA-256 in the selected backend.
- Do not read a file once for hashing and again for validation.
- Do not keep a hard-coded pre-budget 10 MiB read path.

### E. Candidate grouping can merge distinct evidence

Anti-slop diagnostics are grouped by `(contract, path, line)`.

This can merge:

- Two diagnostics at different columns on one line.
- Two source snapshots with different content.
- Two different rules that use one broad contract name.
- Two backend findings that need separate semantic checks.

Required correction:

Use a canonical evidence identity that contains at least:

- Rule ID.
- Backend ID.
- Logical path.
- Source layer.
- Content SHA-256.
- Line.
- Column.
- Rule-specific discriminator.

Merge only exact duplicate evidence. A later semantic deduplication step can join candidates after it proves that they describe the same violated contract.

### F. Python `getattr` rule uses identifier names as evidence

The Python backend treats a receiver as reflective when its name contains `proxy`, `reflect`, `dynamic`, or `delegate`. It also suppresses calls inside a whole class or module when that container defines `__getattr__` or `__getattribute__`.

These rules are easy to bypass and can suppress unrelated calls.

Required correction:

- Disable `anti-slop-python/no-literal-getattr-without-default` by default until it is binding-aware and calibrated.
- Remove receiver-name exemptions.
- Resolve the receiver binding where possible.
- Suppress only `getattr(self, ...)` or `getattr(cls, ...)` when the same class provides the dynamic protocol and the call uses that dynamic receiver.
- Do not suppress `getattr(other, ...)` only because an enclosing class has `__getattr__`.
- Track lexical imports, shadowing, and rebinding for `cast`, `Any`, and `getattr` rules.

### G. ast-grep rule quality requirements are not enforced

The rule contract states that a default rule needs positive, negative, malformed-source, generated-code, framework, suppression, location, and manual precision evidence. The current native rule suite mainly proves that ast-grep matches short snippets.

Required correction:

- Make the rule contract machine-readable.
- Fail CI when a default-enabled rule does not have each required evidence item.
- Store measured calibration evidence in a versioned file.
- Do not claim a precision threshold without the reviewed sample and decisions that produced it.
- Separate parser micro-tests from behavioural acceptance tests.

### H. Several rule fixtures are not compiler-valid programs

Current fixtures use undefined placeholder types and invalid function signatures. This is acceptable for a parser micro-test. It is not acceptable as the only acceptance evidence for a production rule.

Required correction:

- Keep small ast-grep pattern tests and label them `pattern` tests.
- Add compiler-valid mini-projects for Go, Rust, C, C++, Java, and C#.
- Run the language compiler or type checker before the rule result is accepted.
- Add realistic valid examples that must not match.
- Mark parser errors as partial analysis, not `Checked`.

### I. Some tests do not prove their stated claim

Examples in the current suite include:

- A test named as proof that unsupported files are not opened patches `Path.read_text`, while the production path opens files in binary mode.
- A disabled-analyser test patches the old `run_anti_slop.analyse` entry point, while context construction now calls the new orchestrator.
- A rule-corpus test checks only aggregate diagnostic counts. One false positive can cancel one false negative.
- A rule-ownership test checks ast-grep file IDs but does not compare all deterministic, legacy, Oxlint, Python AST, and ast-grep contracts.
- Linear-work tests trust a work counter produced by the same code under test.

Required correction:

- Remove or rewrite tests that patch the wrong boundary.
- Assert the actual observable contract.
- Use one named fixture and one exact expected location per case.
- Add a negative-control mutation that proves the test fails when the target behaviour is broken.
- Use independent instrumentation for complexity and work-count checks.

### J. Old anti-slop compatibility behaviour remains active

`scripts/run_anti_slop.py` still exposes old `ok` and `skipped` states, `legacy_status`, duplicated preflight logic, and a JS/TS-only special branch.

Required correction:

- Define one versioned public anti-slop envelope.
- Migrate all consumers and tests.
- Remove obsolete compatibility fields and duplicate preflight logic in the same change.
- Keep a command wrapper only when it delegates without changing semantics.

### K. Parser failures can be hidden by filtered diagnostics

Oxlint filters diagnostics to anti-slop rule IDs. ast-grep accepts a valid JSON result but does not separately prove that every selected file parsed successfully.

Required correction:

- Detect parser or syntax diagnostics before rule filtering.
- Track parse completion for each applicable file.
- A malformed applicable source file must make the backend partial and public coverage `Not verified`.
- Add malformed-source tests for every backend.

### L. Effect configuration is not source-snapshot aware

The Oxlint variant is selected from current worktree manifests. A staged or reviewed commit can have different Effect dependencies.

Required correction:

- Derive the variant from the same source snapshot as the analysed file.
- Resolve the nearest applicable package manifest in that snapshot.
- Include the selected manifest hash and variant in diagnostic metadata.

### M. Small avoidable quadratic path remains

`ambiguous_header_paths()` recalculates the whole-scope header language for each path.

Required correction:

- Calculate the header language once.
- Reuse it for the complete comprehension.

## Product decisions for the new work

The following decisions are mandatory.

1. Do not attempt to detect whether code was written by an LLM. Apply the checks to changed or selected code. Authorship detection is not needed for the product goal.
2. Do not delete a test from a static smell alone.
3. Static test checks produce candidates only.
4. Recommend test removal only after dynamic evidence shows that the test has no unique behavioural value.
5. A test that fails old code and passes new code is useful evidence, but it still needs an independent contract or oracle.
6. A test that passes both old and new code can still be useful. It is not automatically redundant.
7. A surviving mutant is evidence that a test did not detect that mutation. It is not proof that the test has no value.
8. Use changed-code mutation and hunk reversion before full-repository mutation.
9. Do not use one mutation score as a product-quality score.
10. Do not create broad test-smell rules for test size, assertion count, fixture count, or mocking count.
11. Cyclomatic complexity is a review signal. It is not an automatic defect.
12. Prefer the repository's configured complexity policy. Use a skill-local fallback only when no policy exists.
13. Never change production behaviour only to make a test easier to patch or inspect.
14. Never generate and commit a proof test automatically.
15. Test execution remains explicit and approval-bound because tests execute repository code.

## Target architecture

Add two review domains and one candidate-verification workflow.

### New review families

Add these families to `reference/check-families.md` and `config/rules.yaml`:

```text
GOV-TESTS
COR-COMPLEXITY
```

Recommended layer mappings:

```yaml
GOV-TESTS: [1, 2, 5, 6]
COR-COMPLEXITY: [2, 5, 6]
```

`GOV-TESTS` covers test validity, test weakening, false assurance, invalid or circular oracles, hidden regressions, and evidence that a test detects the claimed fault.

`COR-COMPLEXITY` covers function-level cyclomatic complexity in changed or selected code. It also records complexity growth and the source of the threshold.

Do not move existing security checks into these families.

### New source layout

Use this structure unless the existing code makes one small adjustment clearly simpler:

```text
scripts/dissect_checks/test_integrity/
    __init__.py
    model.py
    inventory.py
    static_analysis.py
    change_analysis.py
    evidence_matrix.py
    mutation.py
    proof_test.py
    orchestrator.py

scripts/dissect_checks/complexity/
    __init__.py
    model.py
    configuration.py
    lizard_backend.py
    orchestrator.py

scripts/run_test_integrity.py
scripts/run_complexity.py
scripts/prove_candidate.py
scripts/validate_test_evidence.py

reference/test-integrity-rule-contract.md
reference/test-evidence-schema.json
reference/complexity-policy.md
```

Do not create one adapter class for every test framework before it is needed. Use a small registry and plain functions. Add an adapter only when the framework has different syntax or command semantics.

### Static and dynamic separation

The test-integrity result must have separate backend records:

```text
static-test-analysis
dynamic-test-matrix
targeted-mutation
proof-test
```

The public family still uses the four existing evidence states:

```text
Finding
Checked
Not applicable
Not verified
```

Internal execution states can be:

```text
complete
partial
not_applicable
planned
unavailable
failed
```

`planned` never becomes a new public evidence state. It maps to `Not verified` when execution is applicable but not approved.

### Test evidence model

Add frozen data models similar to the existing anti-slop models.

Minimum model:

```python
@dataclass(frozen=True)
class TestArtifact:
    logical_path: str
    framework_id: str
    role: str
    source_kind: str
    content_sha256: str

@dataclass(frozen=True)
class TestSubject:
    logical_path: str
    qualified_name: str
    start_line: int
    end_line: int
    source_kind: str
    content_sha256: str

@dataclass(frozen=True)
class TestChange:
    test: TestArtifact
    change_kinds: tuple[str, ...]
    affected_subjects: tuple[TestSubject, ...]
    evidence: tuple[dict[str, Any], ...]

@dataclass(frozen=True)
class TestRunResult:
    scenario_id: str
    command_plan_digest: str
    exit_code: int | None
    completed: bool
    passed: bool | None
    collected_tests: int | None
    selected_tests: tuple[str, ...]
    output_fingerprint: str
    reason_code: str | None

@dataclass(frozen=True)
class MutationResult:
    mutation_id: str
    subject: TestSubject
    mutation_kind: str
    patch_sha256: str
    build_valid: bool | None
    killed: bool | None
    killing_tests: tuple[str, ...]
    reason_code: str | None
```

Persist only bounded, redacted evidence. Do not persist full test output or full patches in the review context.

## Phase 0: baseline and direct reproductions

Before editing:

1. Record:
   - `git rev-parse HEAD`
   - `git status --short`
   - Python version
   - Node version
   - ast-grep version
   - Oxlint version
2. Install the current skill-local dependencies with the lock file.
3. Run the current full suite and save the output outside the checkout.
4. Run the current `dissect-full` workflow against Dissect itself from an installed skill copy.
5. Record all current anti-slop and comment-slop candidates.
6. Run an exact complexity baseline with the selected fallback tool. Do not add suppressions before this baseline is reviewed.
7. Add direct failing tests for every confirmed defect in the audit section.

The first new tests must include these proofs:

- The context CLI must not return success when the requested output was not created.
- Monkey-patching an internal function must not select a different production control path.
- Different index and worktree snapshots must not share text or changed-line ranges.
- Comment density must not read a target twice.
- A per-file comment deadline must limit every scoring stage.
- Anti-slop must not read a file before claiming its budget.
- Two same-line diagnostics at different columns must remain distinct.
- `getattr(other, "name")` must not be suppressed because the enclosing class defines `__getattr__` for `self`.
- A malformed source file must make the relevant backend partial.
- Effect rule selection must use the analysed source snapshot.
- A test that patches `Path.read_text` must fail to claim that a `Path.open` call did not occur.
- A disabled-analyser test must patch or observe the real orchestrator call path.

Do not change production code until each reproduction fails for the intended reason.

## Phase 1: repair the current implementation

### 1.1 Remove the test-only context path

In `scripts/build_review_context.py`:

- Delete the `types` and `threading` imports used only by the test seam.
- Delete the `if not isinstance(build, types.FunctionType)` branch.
- Keep one path from CLI entry to supervisor or worker.
- Add a private worker fixture command for timeout tests.
- Make all supervisor tests start a real child process.
- Assert exit code, stderr, process cleanup, temporary-file cleanup, and final output behaviour.

Add a structural self-check that reports production code which changes behaviour based on:

- A unit-test framework import.
- A mock type.
- A test-only environment variable.
- A monkey-patched function type.
- A `TESTING` branch outside a documented composition root.

This check is a candidate only. Exclude normal language test modules such as Rust `#[cfg(test)]`, Java test source sets, and code that is not shipped.

### 1.2 Make comment analysis one-pass and target-safe

Refactor the comment analyser so one bounded read produces:

- Source hash.
- Comment extraction.
- Changed-line comment count.
- Candidate scoring.
- Bytes visited.
- Completion state.

Use a target ID:

```text
logical path + source layer + content SHA-256
```

Do not key diff evidence only by path.

Add the following fields to `CommentAnalysisResult`:

```python
changed_line_count: int
changed_comment_count: int
comment_density: float
```

The result must calculate density from the exact targets it scanned.

Replace arbitrary `SequenceMatcher` input with a bounded method. Initial limits:

```text
maximum normalised comment characters: 2,000
maximum following-code characters: 2,000
maximum tokens per side: 256
```

Make these internal constants first. Add configuration only after a real repository needs a different value.

When `total_timeout`, `max_files`, `max_total_bytes`, or `max_candidates` is reached:

- Stop the loop.
- Retain completed candidates.
- Record one aggregate skip count and up to three path samples.
- Do not continue one file at a time only to record the same terminal reason.

### 1.3 Make anti-slop source loading single-pass

Add an immutable loaded source object:

```python
@dataclass(frozen=True)
class LoadedAnalysisTarget:
    target: AnalysisTarget
    data: bytes
    content_sha256: str
```

The shared loader must:

1. Validate the logical and physical path.
2. Claim the file budget.
3. Perform one bounded binary read.
4. Claim the actual bytes.
5. Reject binary-looking input.
6. Calculate SHA-256.
7. Return bytes for Python AST or a validated physical file for external tools.

External tools still read their files. The Python orchestration must not perform another full read only for hashing.

For materialised Git snapshots, reuse the already loaded bytes and hash.

### 1.4 Correct anti-slop identity and deduplication

Create one helper:

```python
canonical_diagnostic_identity(diagnostic: BackendDiagnostic) -> str
```

The identity must include all fields listed in audit defect E.

Group only exact duplicate identities.

Add a later semantic relation field when two candidates appear related:

```json
{
  "related_candidate_ids": ["candidate-..."]
}
```

Do not merge them before semantic review.

### 1.5 Fix Python binding analysis

Implement a small lexical binding tracker. It must track:

- Module imports.
- Function parameters.
- Local assignments.
- Class scope.
- Nested functions.
- Import aliases.
- Rebinding of `cast`, `Any`, `typing`, and `getattr`.

Do not build a full Python type checker.

For `no-widen-then-cast`:

- Report only when both calls resolve to `typing.cast` or `typing_extensions.cast` in the local scope.
- Do not report after a local rebinding.
- Keep the immediate same-expression requirement.

For `no-literal-getattr-without-default`:

- Keep it disabled by default until acceptance criteria pass.
- Do not use variable names as type evidence.
- Suppress dynamic protocol use only when the receiver binding is `self` or `cls` for the same class.
- Add real framework negatives for ORMs, proxies, serializers, mocks, plugin systems, and descriptors.
- Enable the rule only after the measured precision gate passes.

### 1.6 Enforce parser completion

For every backend, record per-target parse state.

A backend can be `complete` only when every applicable target is known to have parsed successfully.

For Oxlint:

- Inspect parser diagnostics before filtering to anti-slop rule IDs.
- Treat a fatal parse diagnostic as a target failure.

For ast-grep:

- Use its output and a compiler-valid acceptance layer.
- When ast-grep cannot report per-file parser completion, run a bounded parser or compiler check for acceptance fixtures.
- At review time, treat a tool process or parse error as partial coverage.

### 1.7 Make Effect detection snapshot-aware

Create a snapshot manifest resolver that accepts the same target set as the backend.

For each JS/TS target:

- Find the nearest `package.json` in the same snapshot layer.
- Parse dependencies from that snapshot.
- Select generic or Effect rules for that package.
- Group targets by selected configuration.
- Include manifest logical path, source layer, and hash in diagnostic metadata.

Do not use one current-worktree root manifest for all snapshots.

### 1.8 Remove the old anti-slop envelope

Define one public schema, for example `anti-slop/2.0`.

Remove:

- `legacy_status`.
- The old `ok` versus `skipped` conversion.
- Duplicate JS/TS preflight in `run_anti_slop.py`.
- Direct old candidate conversion paths that are not used by the orchestrator.
- Tests which exist only to preserve obsolete fields.

Keep `scripts/run_anti_slop.py` as a thin argument parser and JSON printer.

### 1.9 Replace false-assurance tests

For every rewritten test:

- State the contract in the test name.
- Observe the real boundary.
- Add a negative control which breaks the contract and makes the test fail.
- Assert exact output, state, path, and source layer where relevant.
- Do not use aggregate diagnostic counts when each case can be asserted separately.

## Phase 2: inventory tests and their claimed subjects

### 2.1 Add a test artefact registry

Detect test artefacts from repository evidence, not from one broad filename rule.

Support these first-class frameworks:

- Python: `unittest` and pytest.
- JavaScript and TypeScript: Node test, Jest, Vitest, and Mocha.
- Go: package `testing` and `_test.go`.
- Rust: `#[test]`, `#[tokio::test]`, and test modules.
- Java: JUnit 4 and JUnit 5.
- C#: xUnit, NUnit, and MSTest.
- C and C++: GoogleTest, Catch2, and doctest when the repository declares them.

The registry must classify:

```text
test
test helper
fixture
snapshot or golden file
test configuration
CI test command
production source
shared build or manifest file
```

A helper or fixture is not a useless test because it has no assertion.

Use evidence in this order:

1. Repository test command and framework dependencies.
2. Framework source layout.
3. Test declaration syntax.
4. Filename convention.
5. User configuration.

Record uncertainty. Do not force an unknown file into a test role.

### 2.2 Map tests to subjects

Build a bounded relation between tests and production symbols.

Evidence can include:

- Direct import or reference.
- Framework route, component, service, or module binding.
- Same package and named symbol.
- Existing coverage data supplied by the repository.
- User configuration.
- A changed test and changed source with an exact symbol reference.

Do not infer a test subject only from a similar filename when better evidence contradicts it.

One test can cover several subjects. One subject can have several tests.

Persist the relation and its evidence. Do not persist a guessed relation as fact.

### 2.3 Partition a diff

Create a change partition:

```text
production patch
test patch
test-support patch
shared configuration patch
documentation or generated patch
```

A file can be shared. When a clean partition is impossible, mark the dynamic matrix inconclusive instead of creating a false hybrid state.

For staged and worktree changes, keep source-layer separation. Do not merge two different patches because they have the same path.

## Phase 3: add high-signal static test-integrity candidates

Add only checks that have a concrete failure model. Each static match remains a candidate.

### 3.1 Test disabled, deleted, or removed from discovery

Candidate ID family: `GOV-TESTS-001`.

Detect changes such as:

- A test or parameter case is deleted.
- `skip`, `todo`, `xfail`, `Ignore`, or disabled attributes are added.
- A test file is removed from a suite or project.
- CI test paths or filters exclude a prior test.
- `continue-on-error`, `|| true`, `--passWithNoTests`, zero-test success, or an equivalent bypass is added.
- Required coverage or failure thresholds are reduced.

Do not report an intentional quarantine without reviewing its issue, reason, and replacement protection.

### 3.2 Assertion or exception contract weakened

Candidate ID family: `GOV-TESTS-002`.

Use language-aware syntax comparison. Detect:

- Assertion removed.
- Exact equality changed to existence or truthiness.
- Expected exception changed to a broader base exception.
- Expected failure changed to success without an intent source.
- Numeric tolerance, time range, or accepted set is broadened.
- Negative authorisation or validation assertion is removed.
- Parameter cases are reduced.
- An assertion is moved behind a branch that need not execute.

Compare the base and head syntax trees. Do not use assertion line count alone.

### 3.3 Oracle changed to mirror the implementation

Candidate ID family: `GOV-TESTS-003`.

Detect high-signal circular oracles:

- Expected value calls the same production function as the actual value.
- Expected data is generated by the same serializer, parser, pricing rule, or validator under test.
- A golden file is regenerated by the same changed code and accepted without another contract source.
- The test copies a new constant or branch from the production implementation when the requirement source differs or is absent.
- The test compares two aliases of the same object or expression.

Do not report a standard round-trip property when the two directions are independent and the property is the intended contract.

### 3.4 Focal behaviour mocked or bypassed

Candidate ID family: `GOV-TESTS-004`.

Detect when the changed test mocks, patches, stubs, replaces, or monkey-patches the exact subject it claims to test.

Examples:

- A service method is patched and then the test claims to verify that service method.
- An authentication guard is mocked while the test claims to verify route protection.
- A transaction or retry helper is mocked while the test claims to verify rollback or retry behaviour.
- A parser or analyser function is patched while the test claims end-to-end coverage.

Do not flag mocks of external boundaries when the unit under test is still executed.

### 3.5 Tautological or non-failing test

Candidate ID family: `GOV-TESTS-005`.

Detect only high-confidence forms:

- `assert True` or exact equivalents.
- Equality of one expression with itself.
- Assertion on a constant known at test parse time.
- Test catches every exception and does not re-raise or fail.
- Test has no assertion, expected exception, property check, snapshot check, or externally observable side-effect verification.
- Test function returns before all checks on every path.
- Test body contains only setup and no observable verification.

Framework hooks, property-based tests, compile tests, type tests, and subprocess exit-code tests can be valid without a normal assertion. The analyser must understand these before it reports a candidate.

### 3.6 Test-only behaviour in production code

Candidate ID family: `GOV-TESTS-006`.

Detect production paths that change runtime behaviour only because a test needs a seam.

Evidence examples:

- Runtime type checks for a mock or monkey-patched function.
- Branches on pytest, unittest, Jest, Vitest, or test-process environment markers.
- A production function returns success without its normal output only under a test condition.
- A private production path exists only to bypass process, validation, or persistence boundaries in tests.

Do not flag dependency injection, clock injection, interface substitution, or explicit test build modules when these are part of the normal architecture and do not alter the production contract.

### 3.7 Invalid fixture presented as behavioural proof

Candidate ID family: `GOV-TESTS-007`.

Detect when:

- A rule fixture parses only because the pattern tool accepts incomplete code.
- The language compiler or type checker rejects the fixture.
- Undefined placeholder types or impossible signatures are used as the only positive evidence.
- A test asserts only that a matcher returns a match, while the product claim is about safe or harmful behaviour.

Parser micro-tests remain valid. They must be labelled and must not satisfy the behavioural acceptance gate.

### 3.8 Test does not exercise the stated subject

Candidate ID family: `GOV-TESTS-008`.

This check needs stronger evidence than a missing direct call.

Use one of:

- Dynamic coverage shows the focal symbol was not reached.
- A call trace or instrumentation shows the subject was not reached.
- The test patches the only path to the subject.
- Static control flow proves that the call cannot occur.

A missing textual reference alone is not enough.

### 3.9 Flaky or non-deterministic evidence

Candidate ID family: `GOV-TESTS-009`.

Flag only after repeated execution shows inconsistent results under the same source, command, environment, and seed.

Record:

- Run count.
- Pass and fail count.
- Seeds.
- Order settings.
- Output fingerprints.
- First differing failure.

Do not call a test flaky because it uses time, randomness, concurrency, or unordered data. These are risk indicators only until repeated execution proves instability.

### 3.10 Static rule quality requirements

Add `reference/test-integrity-rule-contract.md` and a machine-readable rule manifest.

Every default-enabled static rule needs:

1. A concrete harmful behaviour.
2. At least three positive cases.
3. At least eight meaningful negative cases.
4. Compiler-valid or interpreter-valid fixtures.
5. Framework-specific cases where relevant.
6. Exact expected locations.
7. A mutation or negative control that makes the acceptance test fail when the rule is broken.
8. A reviewed real-repository sample.
9. A recorded precision result of at least 90% for high-confidence rules.
10. A statement of what the rule does not prove.

A rule which does not pass this gate stays disabled or experimental.

Do not allow a Markdown statement to satisfy this gate. CI must validate the evidence files.

## Phase 4: add the base and head test evidence matrix

### 4.1 Purpose

The matrix must answer four different questions:

- Did the old repository pass its old tests?
- Do the new tests reject the old code?
- Does the new code still pass the old tests?
- Does the new repository pass its new tests?

Use these scenarios:

| Scenario | Production code | Tests |
| --- | --- | --- |
| A | Base | Base |
| B | Base | Head |
| C | Head | Base |
| D | Head | Head |

### 4.2 Interpretation

Use these rules. Do not reduce them to one score.

| A | B | C | D | Meaning |
| --- | --- | --- | --- | --- |
| Pass | Fail | Pass | Pass | The new test distinguishes old from new code. This is strong regression evidence when the oracle is independent. |
| Pass | Pass | Pass | Pass | The new test does not distinguish old and new code. It can still cover a stable contract, but it does not prove the claimed fix. |
| Pass | Fail | Fail | Pass | The code and tests changed a contract. Require explicit intent before calling this correct or wrong. |
| Pass | Pass | Fail | Pass | The changed tests can be hiding a regression or changing the expected result to fit new code. Treat this as a strong candidate. |
| Pass | Any | Any | Fail | The head state is not verified. |
| Fail | Any | Any | Any | Baseline is invalid or the selected command is not stable. The matrix is inconclusive. |

A scenario can also be `not collected`, `timeout`, `build failure`, or `not approved`. These map to `Not verified` where the scenario is applicable.

### 4.3 Exact source construction

Build scenarios in private temporary Git worktrees or materialised trees outside the reviewed checkout.

For a clean commit-range review:

- Base code and tests come from the merge base.
- Head code and tests come from the reviewed head.

For staged changes:

- Base is `HEAD`.
- Head is the index snapshot.

For unstaged changes:

- Base is the index when a staged version exists, otherwise `HEAD`.
- Head is the worktree snapshot.

For untracked tests or source:

- Base omits the untracked file.
- Head includes it.

When staged and unstaged changes both exist, create separate layer-specific evidence plans. Do not combine them into one misleading matrix.

### 4.4 Test command selection

Use this order:

1. Explicit `.ai-review/local.json` command.
2. Existing repository CI command.
3. Existing package or workspace test script.
4. A framework command already proved by repository configuration.

Do not invent framework arguments from memory.

When selecting only changed tests:

- Use a framework-native selector only when its installed version and command semantics are verified.
- Otherwise run the existing bounded test command.
- Record the exact selected tests and command source.

### 4.5 Execution safety

Tests execute repository code. They must use the existing explicit approval model.

Add a new execution-plan kind: `test-evidence`.

Its approval digest must bind:

- Repository identity.
- Base and head commits.
- Index and worktree content hashes where used.
- Production patch hash.
- Test patch hash.
- Shared configuration patch hash.
- Scenario ID.
- Exact executable identity.
- Exact argv.
- Working directory.
- Complete child environment.
- Test selector.
- Time and output limits.

Revalidate all fields immediately before execution.

Use:

- A temporary `HOME`.
- No inherited credentials.
- No production URLs.
- No repository write-back.
- One process group per scenario.
- A hard timeout.
- Bounded redacted output.
- Cleanup in every exit path.

Do not claim that this is a security sandbox. It is explicit, bounded execution of reviewed repository code.

### 4.6 Result integration

Add dynamic evidence to the candidate ledger as verification or contradiction evidence.

Example:

```json
{
  "kind": "test_matrix",
  "scenario": "base-code-head-tests",
  "command_plan_digest": "...",
  "production_patch_sha256": "...",
  "test_patch_sha256": "...",
  "completed": true,
  "passed": false,
  "selected_tests": ["tests/test_account.py::test_rejects_other_tenant"],
  "output_fingerprint": "..."
}
```

Do not store full unredacted output in the ledger.

## Phase 5: add targeted mutation and hunk-reversion evidence

### 5.1 Start with changed-code reversion

The first mutation method must be language-neutral and simple:

- Keep head tests.
- Revert one changed production hunk or one changed function to its base form.
- Check that the mixed source still parses, builds, or type-checks.
- Run the relevant approved test selection.

If the test still passes, it did not prove that changed behaviour.

If the test fails, it killed the reverted change. This is useful evidence, but the oracle still needs contract validation.

### 5.2 Mutation selection

Select only changed production code.

Prioritise mutations around:

- Conditions and branch direction.
- Boundary comparisons.
- Validation and rejection paths.
- Authorisation and ownership predicates.
- Error propagation.
- Retry and idempotency logic.
- Transaction boundaries.
- Return values.
- State transitions.
- Security controls.

Do not mutate:

- Formatting.
- Comments.
- Generated files.
- Vendored code.
- Unchanged full-repository code by default.
- Code that cannot be mapped to a relevant test.

Initial limits:

```text
maximum mutants per review: 25
maximum mutants per changed function: 3
maximum mutation execution time: 300 seconds
maximum test runs per mutant: 1, unless flakiness validation is requested
```

Make these configurable after the first implementation.

### 5.3 Validate each mutant

Before a test result is used:

1. Apply the mutation to a private source tree.
2. Confirm that the patch changed the intended source.
3. Run the repository's approved parse, build, or type-check command when available.
4. Reject an invalid mutant.
5. Run only the mapped test selection when safe and supported.
6. Record the exact patch hash and source span.

An invalid mutant does not count as killed.

### 5.4 Do not use one mutation score

Report each surviving mutant with:

- Subject.
- Mutation kind.
- Source span.
- Test selection.
- Build validity.
- Result.
- Evidence still needed.

You may report aggregate counts for navigation. Do not report a composite quality score.

### 5.5 Test-specific mutation value

For each changed test, record the set of valid mutants it kills.

A test is a removal candidate only when all conditions below hold:

1. It has no independently supported contract which is unique to that test.
2. It does not reach a unique subject, boundary, error path, or integration.
3. It kills no selected valid mutant which another retained test does not kill.
4. It passes with the relevant production hunk reverted.
5. It passes on both base and head code when it was claimed as proof of a fix.
6. It is not the only compile, type, schema, migration, snapshot, or integration check for that behaviour.
7. Repeated execution does not show hidden order or timing coverage.
8. Semantic review confirms that removal does not reduce protection.

When only some conditions hold, recommend `rewrite` or `strengthen`, not `remove`.

### 5.6 Optional native mutation adapters

Do not require a new mutation framework for every language in the first release.

The generic changed-hunk method is the default.

Add an optional adapter only when the repository already configures a maintained mutation tool or when Dissect pins and tests it separately.

Any native adapter must:

- Mutate changed code only.
- Use the approved execution-plan system.
- Limit mutants and time.
- Exclude equivalent and invalid mutants where evidence supports that decision.
- Emit the common `MutationResult` model.

## Phase 6: add the proof-test workflow for review candidates

### 6.1 Purpose

Add a workflow that asks the reviewer or agent to write a focused test which proves or disproves one candidate concern.

This workflow is for uncertain behavioural claims. It is not for style-only findings or complexity-only candidates.

### 6.2 New command

Add:

```text
python3 scripts/prove_candidate.py \
  --context <context.json> \
  --candidate-id <candidate-id> \
  --test-patch <patch-file> \
  --format json
```

The command first creates an inert execution plan. It must not run the test until the exact plan digest is approved.

### 6.3 Test-patch requirements

The proposed test patch must stay outside the reviewed checkout until execution.

Validate that it:

- Changes only test, fixture, or test-support files.
- Does not weaken or delete an existing test.
- Does not change production code.
- Does not change CI to hide a failure.
- Parses or compiles.
- Selects the candidate's claimed behaviour.
- Does not mock the focal subject.
- Contains an observable assertion or expected failure.
- Has an oracle provenance statement.

Required metadata:

```json
{
  "candidate_id": "candidate-...",
  "claimed_contract": "Only the authenticated tenant can load this invoice.",
  "oracle_source": {
    "kind": "user_intent|public_contract|existing_invariant|external_spec|independent_reference",
    "reference": "..."
  },
  "focal_subjects": ["service.load_invoice"],
  "expected_current_result": "fail|pass",
  "control": "base|known_good|targeted_mutant"
}
```

Do not accept `current implementation output` as an independent oracle.

### 6.4 Falsification sequence

Use this sequence:

1. Confirm that the test collects or compiles.
2. Confirm that the focal subject is reached.
3. Run it on the current candidate source.
4. Run it on an independent control:
   - Base source when the concern is a regression.
   - A known-good implementation.
   - A targeted mutant which removes the claimed control.
5. Compare the outcomes.

Interpretation:

- The test passes on current code when the candidate predicted failure:
  - Record contradicting evidence.
  - Mark the candidate `disproved` when the test has a valid oracle and reaches the focal path.
- The test fails on current code and passes on a known-good control:
  - Record supporting evidence.
  - The candidate can become `verified` only when the full contract, trigger, and impact chain is also proven.
- The test passes on current code and also passes on a mutant which should break the contract:
  - The proof test is weak or does not reach the intended behaviour.
  - Do not use it as verification.
- The test result has no independent oracle or control:
  - Mark the verification `not_verifiable` or `Not verified`.

### 6.5 Reachability evidence

Use the least intrusive available method:

1. Existing coverage output.
2. Existing trace or test framework hooks.
3. A temporary test-only wrapper in the private worktree.
4. Language-specific call instrumentation.

Do not add instrumentation to production source in the real checkout.

### 6.6 Ledger integration

Add a verification record:

```json
{
  "kind": "proof_test",
  "candidate_id": "candidate-...",
  "test_patch_sha256": "...",
  "oracle_kind": "existing_invariant",
  "focal_subjects": ["service.load_invoice"],
  "command_plan_digest": "...",
  "current_result": "pass",
  "control_result": "fail",
  "reachability": "confirmed",
  "outcome": "disproved|supported|inconclusive",
  "output_fingerprint": "..."
}
```

Never commit the test automatically.

When the test is valid and useful, include it as a proposed patch in the final report or implementation task.

## Phase 7: add cyclomatic complexity analysis

### 7.1 Scope

Do not try to determine which functions were written by an LLM.

In diff mode:

- Analyse new and changed functions only.
- Compare base and head complexity.
- Do not report unchanged pre-existing complex functions.

In full mode:

- Analyse all selected, non-generated, non-vendored functions in supported languages.

Analyse test functions too, but label them as test complexity. High test complexity is a review signal because it can make the oracle hard to understand. It is not automatic proof of a bad test.

### 7.2 Threshold source order

Use this order:

1. Repository-configured complexity threshold.
2. Threshold emitted by an approved repository-native lint command.
3. Dissect fallback threshold.

Read repository configuration without executing commands where possible.

Recognise at least:

- Ruff or flake8 McCabe `C901` and `max-complexity`.
- ESLint `complexity` rule.
- golangci-lint `gocyclo` or `cyclop` settings.
- Other native configuration only after a tested parser is added.

Do not assume that all tools use the same default or the same complexity variant.

### 7.3 Skill-local fallback

Pin Lizard `1.24.0` as the fallback multi-language analyser.

Vendor or lock it as a skill-local dependency. Record:

- Exact version.
- SHA-256.
- Licence.
- Upstream source.
- Supported language set.
- Upgrade procedure.

Use its library API on Dissect-selected files or source snapshots. Do not let Lizard traverse the repository itself.

Do not search `PATH` for a global Lizard installation.

### 7.4 Supported languages

Use the fallback for languages it supports and that Dissect already treats as first-class, including:

- Python.
- JavaScript.
- TypeScript.
- Go.
- Rust.
- C.
- C++.
- Java.
- C#.

If a parser cannot analyse a selected file, mark that file `Not verified`.

### 7.5 Metrics

For each function or method, record:

```text
qualified name
logical path
source layer
content SHA-256
start line
end line
cyclomatic complexity
NLOC
token count
parameter count
threshold
threshold source
base complexity
head complexity
delta
```

Do not persist elapsed time in deterministic context JSON.

### 7.6 Function matching across base and head

Match functions in this order:

1. Language, path, qualified name, and normalised signature.
2. Rename mapping plus qualified name and signature.
3. Changed-line overlap plus declaration fingerprint.

When mapping is ambiguous, report head complexity without a delta and state that base comparison was not verified.

### 7.7 Initial candidate policy

Use a configurable policy. Initial fallback values:

```text
absolute fallback threshold: 15
complexity growth candidate: delta of at least 5 and head complexity above 10
maximum reported candidates per review: 100
```

Create a candidate when:

- A new function exceeds the active threshold.
- A changed function exceeds the active threshold and its complexity increased.
- A changed function grows by at least the configured delta and ends above the lower review boundary.

For full mode, report functions above the active threshold.

Do not report a finding only because a number is high. The reviewer must confirm concrete risk such as:

- Unclear failure paths.
- Hard-to-test branch combinations.
- Mixed responsibilities.
- Hidden state transitions.
- Security controls spread across many branches.
- A change which cannot be reviewed safely as one unit.

### 7.8 Remediation rules

Do not recommend mechanical extraction only to reduce a metric.

A valid remediation must improve at least one of:

- Behavioural cohesion.
- Explicit state transition.
- Reusable decision policy.
- Error-path clarity.
- Testability.
- Security-boundary clarity.

Do not create tiny forwarding helpers, hidden shared state, or indirect control flow only to make the number green.

### 7.9 Complexity result and coverage

Add backend records such as:

```text
repository-native-complexity
lizard-fallback
```

Coverage rules:

- No supported selected functions: `Not applicable`.
- Every selected function analysed: `Checked`.
- Parser failure, missing fallback, ambiguous base mapping, or budget exhaustion: `Not verified` for the affected scope.
- Complexity candidates do not make coverage `Finding` automatically.

## Phase 8: define test usefulness without a false score

Do not produce a single usefulness score.

Record these separate evidence dimensions for each changed or challenged test:

```text
collects or compiles
passes on head
reaches focal subject
distinguishes base and head
kills targeted valid mutant
uses independent oracle
has explicit contract source
is stable across repeated runs
covers a unique boundary or failure mode
has unique mutation kill set
```

Recommended actions:

- `keep`: evidence shows a clear and unique contract or regression guard.
- `strengthen`: test is relevant but its oracle, reachability, or fault sensitivity is weak.
- `rewrite`: test encodes the wrong contract, mirrors implementation, or mocks the focal behaviour.
- `remove`: dynamic and semantic evidence shows no unique protection.
- `not verified`: execution or contract evidence is missing.

Only `remove` needs all removal conditions in Phase 5.5.

## Phase 9: make Dissect test its own tests and rules

### 9.1 Replace parser-only rule confidence

Split current ast-grep tests into:

```text
scripts/vendor/anti-slop/ast-grep/tests/pattern/
tests/fixtures/anti-slop/acceptance/go/
tests/fixtures/anti-slop/acceptance/rust/
tests/fixtures/anti-slop/acceptance/c/
tests/fixtures/anti-slop/acceptance/cpp/
tests/fixtures/anti-slop/acceptance/java/
tests/fixtures/anti-slop/acceptance/csharp/
```

Pattern tests prove AST matching only.

Acceptance mini-projects must:

- Compile or type-check.
- Contain valid positive cases.
- Contain realistic negative cases.
- Run the actual backend.
- Assert exact rule ID and location.
- Include malformed-source behaviour.
- Include generated-code exclusion.
- Include suppression behaviour when suppression is supported.

Use explicit toolchain versions in CI.

### 9.2 Add meta-mutation for rule tests

Add `scripts/validate_rule_effectiveness.py`.

For each default-enabled Dissect rule:

1. Run its acceptance test.
2. Disable or invert the rule in a temporary copy.
3. Run the acceptance test again.
4. Require the test to fail for the intended reason.

This prevents a green test that does not depend on the rule implementation.

Do not mutate the real checkout.

### 9.3 Add exact case tests

Replace aggregate count tests with table-driven exact cases.

Each case must state:

- Fixture name.
- Expected rule ID or no rule.
- Expected path.
- Expected line and column.
- Expected backend status.
- Why the case is positive or negative.

One false positive must not cancel one false negative.

### 9.4 Add independent work instrumentation

For the comment scanner complexity test:

- Inject a cursor observer or byte-reader wrapper from the test.
- Count actual reads or cursor advances outside the scanner's own reported result.
- Add a temporary mutation which restores prefix newline counting.
- Require the regression test to fail under that mutation.

Keep wall-clock benchmarks as release information only. Do not make a fragile timing ratio the only guard.

### 9.5 Run the new checks on Dissect itself

After the new features work:

1. Install a clean skill copy outside the repository.
2. Run `dissect-full` against Dissect.
3. Run test-integrity static analysis on all tests.
4. Run the approved dynamic matrix for the implementation diff.
5. Run targeted mutations on the changed analyser functions.
6. Run complexity analysis.
7. Review every candidate.
8. Fix verified issues in the same branch.
9. Record disproved and not-verified candidates.

Do not add broad suppressions for Dissect itself.

### 9.6 Refactor current complexity hotspots only after measurement

At minimum, measure these functions:

- `_diff_optional_targets`.
- `_optional_analyser_evidence_impl`.
- `scan_comment_targets`.
- The generic comment scanner.
- `anti_slop.orchestrator.analyse`.
- Oxlint backend `analyse` and command execution.
- ast-grep backend `analyse` and command execution.

Refactor a function only when the active policy flags it and the new structure improves behavioural cohesion.

Do not split functions only to pass the metric.

## Phase 10: schema, reports, and reviewer workflow

### 10.1 Review context schema

Bump only the review-context schema when the persisted shape changes. Use `1.2` for this implementation.

Add:

```json
{
  "coverage": {
    "test-integrity": {
      "state": "Not verified",
      "reason": "Dynamic test evidence was applicable but not executed.",
      "backends": {}
    },
    "complexity": {
      "state": "Checked",
      "reason": "All selected functions were analysed.",
      "backends": {}
    }
  },
  "test_evidence": {
    "artifacts": [],
    "relations": [],
    "static_candidates": [],
    "matrix": [],
    "mutations": [],
    "proof_tests": []
  },
  "complexity": {
    "functions": [],
    "policy": {}
  }
}
```

Keep the stored data bounded. Large detail belongs in a separate evidence artefact outside the checkout. The context stores its path, hash, schema version, and a compact summary.

Update `scripts/validate_review_context.py` to enforce:

- Canonical public states.
- Canonical internal states.
- Non-negative counts.
- Exact scenario IDs.
- Unique test artefact IDs.
- Unique mutation IDs.
- Candidate references which exist.
- `checked <= applicable` invariants.
- Valid SHA-256 values.
- No full unredacted command output.
- No raw secret-bearing environment values.

### 10.2 Candidate ledger

Static test-integrity and complexity output must use the current candidate ledger.

Each test-integrity candidate needs:

- Exact claim.
- Test path and source layer.
- Base and head evidence.
- Claimed or inferred contract.
- Focal subject.
- What the static evidence does not prove.
- Dynamic verification plan.
- Suggested action only after verification.

Each complexity candidate needs:

- Function identity.
- Base and head complexity.
- Delta.
- Threshold and source.
- Changed lines.
- Concrete review risk to verify.

### 10.3 Review workflow changes

Update `reference/review-workflow.md`.

After candidate generation and before final verification:

1. Review test changes as untrusted evidence.
2. Check whether tests were weakened, bypassed, or made circular.
3. When a concern is uncertain, request or create a proof-test patch outside the checkout.
4. Run the proof test only through an approved evidence plan.
5. Use the result to disprove, support, or leave the candidate unverified.
6. Use targeted mutation to check whether changed tests detect changed behaviour.
7. Review complexity candidates in the context of changed behaviour.

Add a strict statement:

> A passing test is evidence only for the exact behaviour it can distinguish. It is not proof that the implementation or oracle is correct.

### 10.4 Report template

Add compact sections:

```text
Test integrity findings
Proof tests performed
Mutation evidence
Complexity review candidates
Not verified test evidence
```

Do not dump the full matrix or mutant list into a normal report. Show only evidence that affects a finding or a material open question.

## Phase 11: configuration

Extend `review_options.analysis_limits` with validated fields:

```json
{
  "test_integrity_timeout_seconds": 300,
  "test_matrix_timeout_seconds": 600,
  "mutation_timeout_seconds": 300,
  "mutation_max_mutants": 25,
  "mutation_max_per_function": 3,
  "proof_test_timeout_seconds": 120,
  "flaky_test_repetitions": 3,
  "complexity_timeout_seconds": 60,
  "complexity_max_files": 20000,
  "complexity_max_total_bytes": 268435456,
  "complexity_max_candidates": 100,
  "complexity_fallback_threshold": 15,
  "complexity_delta_threshold": 5,
  "complexity_delta_minimum_head": 10
}
```

Add feature toggles:

```json
{
  "test_integrity": true,
  "complexity": true,
  "dynamic_test_evidence": true,
  "targeted_mutation": true,
  "proof_tests": true
}
```

Meaning:

- Static analysis can run without approval.
- Dynamic test evidence, mutation, and proof tests require exact approval.
- A disabled applicable check maps to `Not verified`.
- A check with no applicable artefacts maps to `Not applicable`.

Reject booleans where an integer is required. Reject non-finite numbers, zero where positive is required, and negative values.

Do not silently fall back after invalid safety configuration.

## Phase 12: tests for the new implementation

### 12.1 Tests which must prove their own value

For every new behavioural test, add one of these controls:

- A small temporary mutant.
- A reverted production hunk.
- A broken fixture.
- An inverted predicate.
- A missing assertion.

The control must make the test fail for the intended reason.

Do not add a control to simple data-model or serialisation tests where an exact value assertion already directly proves the contract. Use judgement, but document the reason.

### 12.2 Static test-integrity cases

Add exact positive and negative cases for every rule.

Required positives:

- Test changed from exact equality to truthiness.
- Expected exception broadened.
- Negative authorisation case removed.
- Test skipped.
- CI command changed to ignore failure.
- Focal function mocked.
- Expected value calls the focal function.
- Test-only production branch.
- Constant tautology.
- Catch-all test which always passes.
- Invalid parser-only acceptance fixture.

Required negatives:

- Intentional contract change with explicit task evidence.
- Mock of an external client while service logic runs.
- Property-based test with no normal assertion.
- Compile-time or type-level test.
- Snapshot update with independent reviewed fixture.
- Test helper with no assertion.
- Parameter removal because the input is no longer supported and intent proves it.
- Test quarantine with a linked issue and replacement guard.
- Dependency injection used in production normally.
- Rust test module excluded from production.

### 12.3 Matrix tests

Create temporary repositories for every matrix pattern in Phase 4.2.

Assert:

- Exact scenario source hashes.
- Exact production and test partitions.
- Exact command plan digest binding.
- A changed plan invalidates approval.
- Base failure makes the result inconclusive.
- Head failure never becomes `Checked`.
- Staged and worktree layers remain separate.
- Untracked tests are absent from base and present in head.
- Shared configuration ambiguity is reported.
- Temporary trees are removed.
- The target checkout is unchanged.

### 12.4 Mutation tests

Test:

- Reverted hunk is killed.
- Reverted hunk survives.
- Mutation does not compile.
- Mutation patch does not change the target and is rejected.
- One test kills a unique mutant.
- Two tests have the same kill set.
- Mutant budget ends the pass and retains earlier results.
- Timeout kills the complete process group.
- No mutation reaches generated or vendored files.
- Exact source-layer mapping.

### 12.5 Proof-test tests

Test:

- Test patch changes production code and is rejected.
- Test patch weakens an existing test and is rejected.
- Test patch has no oracle provenance and is inconclusive.
- Test passes current code and disproves a false concern.
- Test fails current code and passes known-good code.
- Test passes both current and broken mutant and is rejected as weak evidence.
- Focal subject is mocked and the patch is rejected.
- Focal subject is not reached and result is inconclusive.
- Approval digest binds the test patch and all source hashes.
- Output is redacted.
- Proposed test is never written to the real checkout.

### 12.6 Complexity tests

Use small compiler-valid functions with known classic McCabe complexity.

Test:

- Straight-line function is 1.
- Each `if`, loop, and decision branch changes the metric as expected for the selected tool.
- Repository threshold overrides fallback threshold.
- Ruff `max-complexity` parsing.
- ESLint complexity rule parsing.
- golangci-lint gocyclo or cyclop parsing.
- New function above threshold.
- Changed function with positive delta.
- Unchanged high-complexity function is not a diff candidate.
- Renamed function maps across base and head.
- Ambiguous function mapping is `Not verified` for delta.
- Parser failure produces partial coverage.
- Generated and vendored files are excluded.
- Test function is labelled as test complexity.
- Candidate limit retains deterministic first candidates.
- Source order and candidate IDs are stable.

Add an integration test which temporarily replaces the complexity result with a constant green result. The acceptance test must fail. This proves that the suite depends on the measured metric.

### 12.7 Test deletion decision tests

Create fixtures where a test:

- Has no assertion but is a valid compile test. Keep it.
- Passes base and head but kills a unique mutant. Keep it.
- Fails base and passes head with a valid oracle. Keep it.
- Mocks the focal subject and kills no mutant. Rewrite it.
- Is duplicate, kills no unique mutant, has no unique contract, and passes a reverted hunk. Remove it.
- Has missing execution evidence. Mark it `Not verified`.

No static-only fixture may result in `remove`.

### 12.8 Self-review regression tests

Add named regressions for the current repository defects:

- `test_context_cli_has_no_mock_type_control_path`
- `test_comment_density_uses_exact_snapshot_target`
- `test_comment_target_is_read_once`
- `test_terminal_comment_budget_stops_iteration`
- `test_anti_slop_claims_budget_before_hashing`
- `test_same_line_different_column_diagnostics_are_distinct`
- `test_dynamic_protocol_does_not_suppress_other_receiver`
- `test_rule_acceptance_fixtures_compile`
- `test_disabled_analyser_observes_real_orchestrator`
- `test_unsupported_open_regression_observes_path_open`
- `test_rule_case_results_cannot_cancel_each_other`
- `test_malformed_source_never_reports_checked`
- `test_effect_variant_uses_snapshot_manifest`
- `test_anti_slop_cli_has_one_public_envelope`

## Phase 13: CI and release gates

### 13.1 Keep the current matrix

Keep Python 3.11, 3.13, and 3.14 until the support policy changes.

Keep the macOS runtime smoke job.

### 13.2 Add compiler-valid anti-slop acceptance jobs

Use explicit toolchain setup.

Run:

- Go compiler and tests.
- Rust `cargo check` or focused tests.
- Clang C syntax or build check.
- Clang C++ syntax or build check.
- Java compiler or focused Gradle/Maven-free fixture compile.
- .NET build for the C# fixture.

Then run the actual ast-grep backend against the same valid source.

A pattern test cannot replace this job.

### 13.3 Add rule-effectiveness job

Run the meta-mutation validator for:

- Deterministic structured rules.
- Python AST rules.
- ast-grep rule packs.
- Static test-integrity rules.
- Complexity integration.

The job must show that disabling each default-enabled rule breaks at least one acceptance test.

### 13.4 Add Dissect self-review job

Run static, non-executing checks on the Dissect checkout:

- Test-integrity static analysis.
- Complexity analysis.
- Anti-slop.
- Comment-slop.

Do not auto-fail on all candidates.

Fail only on:

- Internal analyser failure.
- Invalid rule evidence.
- Unapproved complexity regression above the repository policy.
- A verified high-confidence test bypass pattern in Dissect's own production code.

Store the detailed self-review evidence as a CI artefact.

### 13.5 Add a scheduled calibration job

Run a scheduled or manual workflow which:

- Executes the real-repository rule corpus.
- Records true positive, false positive, true negative, and false negative decisions.
- Compares rule precision and recall with the prior reviewed baseline.
- Does not change rule state automatically.

A human-reviewed evidence file must be merged before a rule becomes default-enabled.

### 13.6 Keep normal PR cost bounded

Normal pull requests should run:

- Static test-integrity analysis.
- Complexity analysis.
- Pattern and acceptance tests for changed rule packs.
- Targeted meta-mutations for changed analyser rules.

Full dynamic matrix and mutation execution should be manual or approval-triggered unless the repository explicitly opts into trusted CI execution.

## Phase 14: installer and vendoring

Update `scripts/install.py` to copy and verify:

- New test-integrity modules.
- New complexity modules.
- Lizard fallback package.
- New schemas and reference files.
- New commands.

The installer must verify exact versions and hashes.

It must not report success when a required default analyser is missing.

Keep dynamic test execution optional. The skill can install the planner without running repository tests.

Add licence and provenance files for every new vendored dependency.

Do not add a package only because it is convenient. Use the standard library and current dependencies first.

## Phase 15: documentation

Update:

- `README.md`.
- `SKILL.md`.
- `reference/methodology.md`.
- `reference/review-workflow.md`.
- `reference/report-template.md`.
- `reference/check-families.md`.
- `reference/test-integrity-rule-contract.md`.
- `reference/complexity-policy.md`.
- `config/rules.yaml`.
- `config/local.json.template`.
- Review-context schema and validator docs.
- Installer docs.
- Relevant language packs.

Document these limits clearly:

1. Static test smells are candidates only.
2. Test usefulness needs behavioural evidence.
3. Mutation survival does not prove a test is useless.
4. A generated proof test needs an independent oracle.
5. Dynamic evidence requires explicit execution approval.
6. Cyclomatic complexity is a review signal, not a direct correctness result.
7. There is no reliable LLM-authorship gate in this feature.
8. Parser pattern fixtures and compiler-valid acceptance fixtures are different evidence levels.
9. `Checked` means the selected analysis completed. It does not mean the product is correct.

Run adapter generation after the canonical documents change. Do not hand-edit generated adapter content.

## Recommended commit sequence

Use small commits in this order:

1. `test: reproduce false-assurance and analyser boundary defects`
2. `fix: remove test-only context execution path`
3. `fix: make comment density bounded and snapshot-specific`
4. `fix: enforce anti-slop budgets before source hashing`
5. `fix: preserve exact anti-slop diagnostic identities`
6. `fix: make parser completion and Effect detection snapshot-aware`
7. `refactor: remove obsolete anti-slop compatibility envelope`
8. `test: replace ineffective analyser and rule tests`
9. `feat: add test artefact inventory and subject mapping`
10. `feat: add static test-integrity candidates`
11. `feat: add approved base-head test evidence matrix`
12. `feat: add targeted changed-code mutation evidence`
13. `feat: add candidate proof-test workflow`
14. `feat: add bounded cyclomatic complexity analysis`
15. `test: add compiler-valid rule acceptance and meta-mutation gates`
16. `fix: resolve verified Dissect self-review findings`
17. `docs: document test evidence and complexity policy`
18. `ci: add acceptance, self-review, and calibration workflows`

Do not put the complete change in one large commit.

## Final validation commands

Use exact commands from the repository after implementation. At minimum run:

```bash
npm ci --prefix scripts/vendor/anti-slop

python3 -m unittest discover -s tests -v

scripts/vendor/anti-slop/node_modules/.bin/ast-grep test \
  --config scripts/vendor/anti-slop/ast-grep/sgconfig.yml \
  --color never

python3 scripts/validate_rule_effectiveness.py

python3 scripts/run_complexity.py \
  --root . \
  --mode full \
  --format json

python3 scripts/run_test_integrity.py \
  --root . \
  --mode full \
  --format json

python3 scripts/sync_adapters.py --check

bash -n scripts/review.sh scripts/review_changed.sh

python3 scripts/validate_benchmarks.py

python3 scripts/validate_review_result.py \
  tests/fixtures/sample-review-result.json
```

Also run compiler-valid acceptance commands for all supported language rule fixtures.

Run the dynamic matrix, targeted mutation, and proof-test workflows only with exact approved plan digests.

## Definition of done

Do not mark this work complete until every condition below is true.

### Current implementation repair

- No production branch detects a mock type or monkey-patched function to change the context CLI path.
- Supervisor tests use a real worker process.
- Comment density uses the exact bounded target scan.
- Different source layers cannot overwrite each other's text or ranges.
- Terminal budgets stop new work.
- Anti-slop does not read or hash before budget accounting.
- Diagnostic identity includes source layer, content hash, line, and column.
- Python rules use lexical binding evidence.
- The `getattr` rule is disabled until its precision gate passes.
- Every malformed applicable source makes coverage incomplete.
- Effect configuration comes from the analysed snapshot.
- One anti-slop public envelope remains.
- Small avoidable quadratic path logic is removed.

### Test integrity

- Test artefacts and production artefacts are classified with evidence.
- Static test checks produce candidates only.
- Base/head test scenarios are built from exact source states.
- Dynamic execution is approval-bound and leaves the real checkout unchanged.
- Test weakening and test bypass patterns have exact positive and negative cases.
- No rule recommends removal from static evidence alone.
- Removal requires unique-contract, reachability, matrix, and mutation evidence.
- Compiler and type tests are not misclassified as assertion-free slop.
- Mocks of external boundaries are not treated as mocks of the focal subject.
- Invalid pattern fixtures cannot satisfy behavioural acceptance.

### Proof tests

- A proof-test patch cannot change production code.
- The test has an independent oracle source.
- The focal behaviour is reached.
- The current result and an independent control are compared.
- False concerns can move to `disproved` with valid evidence.
- True concerns gain a reproducible test artefact.
- Inconclusive tests remain `Not verified`.
- No generated test is auto-committed.

### Mutation evidence

- Mutations are limited to changed production code by default.
- Every mutant has a stable ID and exact patch hash.
- Invalid mutants are excluded from killed results.
- Surviving mutants are reported individually.
- No single mutation score is used as a safety or quality score.
- Test-specific unique kill evidence is available.
- Time, file, and mutant limits are enforced.

### Complexity

- Changed and new functions are mapped across base and head.
- Repository policy takes precedence over fallback policy.
- Lizard is exact-pinned and skill-local when used.
- All metrics have threshold-source evidence.
- Unchanged legacy complexity is not a diff candidate.
- Parser failure produces `Not verified`.
- Complexity candidates remain review candidates.
- Refactoring guidance does not create forwarding-function slop only to lower the metric.
- Dissect's own changed code passes its active complexity policy or has a reviewed, narrow exception with an owner and removal condition.

### Test quality of Dissect itself

- Every default-enabled rule has a machine-validated evidence record.
- Every rule has compiler-valid or interpreter-valid acceptance evidence.
- Disabling each rule makes at least one acceptance test fail.
- Aggregate count tests no longer hide case-level errors.
- Tests patch or observe the actual production boundary.
- No test exists only to preserve obsolete compatibility behaviour.
- CI stores self-review evidence.
- A human-reviewed calibration artefact supports every claimed precision threshold.

### Product and release

- All configured Python jobs pass.
- macOS smoke passes.
- Compiler-valid language acceptance jobs pass.
- Context output remains deterministic.
- All temporary worktrees, snapshots, and mutant trees are removed.
- Output and environment data remain redacted.
- Installer verification passes.
- Generated adapters are synchronised.
- Documentation states what each check proves and does not prove.
- The final implementation report lists:
  - Starting and ending commits.
  - Changed files.
  - Removed false-assurance tests.
  - New static rule evidence.
  - Dynamic matrix results.
  - Mutation results.
  - Proof-test examples.
  - Complexity results and refactors.
  - Compiler-valid rule acceptance results.
  - Remaining `Not verified` areas.

## Source basis for the design

Codex must verify current versions and commands again before implementation.

The design is based on these sources:

- OpenAI, "Detecting and reducing scheming in AI models", and related reward-hacking examples for coding agents which patch or bypass tests.
- Google Research, "The State of Mutation Testing at Google".
- Google Research, "Practical Mutation Testing at Scale".
- Research on mutation suppression and developer use of surviving mutants.
- Research on LLM-generated tests which learn bugs from the implementation under test.
- Research on LLM-generated test maintenance and flakiness.
- Research which warns that static test-smell detectors often over-report.
- Ruff McCabe complexity documentation.
- ESLint complexity rule documentation.
- golangci-lint gocyclo and cyclop documentation.
- Lizard project documentation and the exact PyPI release record for version `1.24.0`.

Do not copy a threshold or rule only because one source uses it. Preserve the evidence-first model and calibrate against real repositories.
