# r2papi Python refactoring plan

This document tracks the long-term plan to make `r2papi` more Pythonic,
typed, portable, and in sync with modern radare2 JSON outputs.

Items are referenced with identifiers of the form `PX-YY` where `X` is the
phase number and `YY` is the item number within the phase.

## Phase 0 — Hygiene (no public API break)

Goal: fix obvious bugs, remove Python 2 leftovers, and modernize low-risk
code without changing public signatures.

- **p0-1** Drop Python 2 compatibility code.
  - Remove `from __future__ import print_function`.
  - Remove `print2` references and Python 2 branches in tests.
  - Use `super()` without arguments consistently.

- **p0-2** Replace non-idiomatic type checks and string formatting.
  - Replace `type(x) == str/bytes/bool` with `isinstance()`.
  - Replace `%` string formatting with f-strings.
  - Normalize whitespace and imports.

- **p0-3** Fix `Flags.exists()`.
  - The old implementation relied on `??` returning a boolean value.
    Modern radare2 returns help text for `??`, so the method was broken.
  - New implementation scans `fj` (JSON flag list) and checks for the name.

- **p0-4** Fix `ConfigType.__setattr__` boolean coercion bug.
  - The old code compared the *attribute name* to `True`/`False` instead of
    the *value*.
  - New code converts the value when it is a Python boolean.

- **p0-5** Improve debugger `CPU` robustness.
  - Fix typo `"Ivalid register"` → `"Invalid register"`.
  - Replace bare `except:` with explicit `KeyError`/None handling.
  - Make `CPU.__str__` tolerate non-integer register values and empty
    register sets (important on platforms where the debugger cannot attach).

- **p0-6** Fix `IOMap.setFlags()` and `flags` property.
  - radare2 stores effective (`perm`) and requested (`sperm`) permissions
    separately. `omp` updates `sperm`, so expose `sperm` in the property.
  - Add validation and keep `__setattr__` wiring.

- **p0-7** Add public exports and minor cleanups.
  - Extend `r2papi.__all__` to include `Result`, `ResultArray`, `R2Base`,
    `Function`, `Print`, `Write`, `Config`, `ConfigType`, `Flags`, `Esil`,
    `EsilCPU`, `EsilVM`, `File`, `IOMap`, `Search`, `Debugger`, `CPU`.
  - Wire `R2Api.search` to the existing `Search` submodule.
  - Preserve backward compatibility for renamed keyword arguments where
    feasible (e.g. `Print.bytes(..., asList=...)` still works).

## Phase 1 — Command builder and safety

Goal: stop assembling radare2 commands with raw string concatenation and
provide consistent escaping.

- **p1-1** Introduce an internal `_Cmd` builder.
  - Build commands from command name + positional/flag arguments.
  - Escape or quote arguments that contain spaces, quotes, or `@`.
  - Generate temporary seek (`@ addr`) safely.

- **p1-2** Port every `R2Base` subclass to use the command builder.
  - Start with `Write` and `Print` (highest injection risk).
  - Then `Search`, `Flags`, `Debugger`, `Esil`, `Config`, `File`, `IOMap`.

- **p1-3** Add return-code checking for radare2 commands.
  - Use `?=`, `$?`, or parse JSON ` raised` fields where available.
  - Raise a custom `R2CommandError` on failure instead of returning raw
    error strings.

- **p1-4** Add type annotations to the public API.
  - Annotate `_exec` and every public method in `R2Base` subclasses.
  - Use `from __future__ import annotations` to keep 3.9 compatibility.

## Phase 2 — Typed result objects

Goal: turn opaque `Result`/`ResultArray` dicts into typed objects while
keeping the legacy dict interface as a compatibility shim.

- **p2-1** Define dataclasses for common radare2 JSON structures.
  - `BinaryInfo`, `FunctionInfo`, `Instruction`, `BasicBlock`, `Section`,
    `Flag`, `Map`, `FileInfo`, `Breakpoint`, `RegisterSet`, `Xref`,
    `SearchHit`, `Symbol`, `Import`, `Export`, `String`, `Comment`.

- **p2-2** Refactor `Result` to wrap a dataclass.
  - Keep `_dict`, `__getitem__`, `__contains__`, and attribute access.
  - Add a typed `__repr__` and optional immutability.

- **p2-3** Return typed objects from high-level methods.
  - `R2Api.info()` → `BinaryInfo`.
  - `R2Api.functions()` → list of `Function` wrapping typed `FunctionInfo`.
  - `Print.disassemble()` / `disasmBytes()` → list of `Instruction`.
  - `Search` methods → list of `SearchHit`.
  - `Debugger.listBreakpoints()` / `backtrace()` → typed collections.

- **p2-4** Add missing high-level accessors.
  - `R2Api.sections` via `iSj`.
  - `R2Api.symbols` via `isj`.
  - `R2Api.imports` via `iij`.
  - `R2Api.exports` via `iEj`.
  - `R2Api.strings` via `izj` / `izzj`.
  - `R2Api.comments` via `Cj`.

## Phase 3 — Collections and indexing

Goal: make sets of objects feel like Python collections.

- **p3-1** Turn `Flags`, `Functions`, `Files`, `Maps`, `Breakpoints` into
  collection-like classes.
  - Implement `__iter__`, `__len__`, `__contains__`, `__getitem__`.
  - Support lookup by name and by address where it makes sense.

- **p3-2** Replace one-off lookup methods with collection access.
  - `r.functionByName("main")` → `r.functions["main"]`.
  - `"main" in r.flags`.
  - `r.files[fd]`.

- **p3-3** Add lazy caching for expensive lists.
  - Cache function list, flags, maps with an explicit `refresh()` method.
  - Invalidate cache when mutating commands are issued.

- **p3-4** Improve slicing and item access on `R2Api`.
  - Keep `r[a:b]` byte slicing but make it explicit and side-effect free.
  - Keep `r[addr] = bytes` but return the written value.

## Phase 4 — Search modernization

Goal: stop parsing text search output and prefer JSON radare2 commands.

- **p4-1** Add a unified `SearchHit` dataclass and parser.
  - Fields: `offset`, `type`, `size`, `data`.

- **p4-2** Reimplement search methods to prefer JSON variants.
  - `/j` for byte/string searches.
  - `/ij`, `/nj`, `/wj`, `/wij` for wide/case-insensitive/numeric searches.
  - Fallback to text parsing only when JSON is unavailable.

- **p4-3** Merge `string` / `string_json` into a single API.
  - `search.string("foo")` always returns an iterable of typed hits.
  - Keep `string_json` as a deprecated alias for one release cycle.

- **p4-4** Escape and validate search patterns.
  - Quote patterns containing spaces or special characters.
  - Validate hex input for byte searches.

## Phase 5 — Portable radare2 commands

Goal: audit every command against current radare2 and prefer JSON,
temporary-seek, and portable equivalents.

- **p5-1** Binary info.
  - Keep `ij`; wrap in `BinaryInfo`.
  - Handle `core`, `bin`, and `plugins` subkeys safely.

- **p5-2** Symbol/address resolution.
  - Prefer `fdj` / `fd.` over `?vi $$ @ sym`.
  - Add `R2Base.resolve(sym)` returning an integer address.

- **p5-3** Functions.
  - Keep `aflj` / `afij`.
  - Add `aflqj` fallback for name-only lists.
  - Note that `afij` returns a list `[{...}]`.

- **p5-4** Instructions.
  - Use `aoj` / `pdj` / `pDj` consistently.
  - Map to typed `Instruction` objects.

- **p5-5** Xrefs.
  - Use `axtj` and `axfj`.
  - Return typed `Xref` objects.

- **p5-6** Maps and files.
  - Use `omj` and `oj`.
  - Use `perm` / `sperm` correctly.
  - Update `File` to prefer `uri` over `filename`.

- **p5-7** Registers and debugger.
  - Use `drj` / `aerj`.
  - Handle string vs numeric register values.
  - Use `dbj` / `dbtj` for breakpoints and backtrace.

- **p5-8** Comments and metadata.
  - Add `comments` collection backed by `Cj`.
  - Add support for flag comments via `fC`.

## Phase 6 — Documentation, testing, and release engineering

Goal: make the library reliable and discoverable.

- **p6-1** Add a changelog and migration guide.
  - Document renamed/deprecated APIs.
  - Provide examples for each phase.

- **p6-2** Expand the test suite.
  - Unit tests for command builder escaping.
  - Property-based tests for round-trips (write → read).
  - Skip or mock debugger tests on platforms without ptrace permissions.

- **p6-3** Add linting and formatting.
  - Configure `ruff` or `flake8` + `black`.
  - Enforce type hints incrementally.

- **p6-4** Release a 0.2.0 alpha.
  - Keep Phase 0 changes in a patch release.
  - Bundle Phase 1–3 changes in a minor release with deprecation
    warnings.

## Quick reference: identifier to topic

| ID | Topic |
|----|-------|
| p0-1 | Drop Python 2 code |
| p0-2 | `isinstance` + f-strings |
| p0-3 | Fix `Flags.exists` |
| p0-4 | Fix `Config` boolean bug |
| p0-5 | Debugger `CPU` robustness |
| p0-6 | `IOMap.setFlags` / `flags` property |
| p0-7 | `__all__` exports |
| p1-1 | Internal command builder |
| p1-2 | Port all classes to builder |
| p1-3 | Command error handling |
| p1-4 | Type annotations |
| p2-1 | Dataclasses for JSON results |
| p2-2 | Typed `Result` shim |
| p2-3 | Typed return values |
| p2-4 | Missing accessors (sections, symbols, strings, comments) |
| p3-1 | Collection-like classes |
| p3-2 | Replace lookup methods with indexing |
| p3-3 | Lazy caching |
| p3-4 | Safe slicing/item access |
| p4-1 | Unified `SearchHit` |
| p4-2 | JSON search commands |
| p4-3 | Merge string/string_json |
| p4-4 | Pattern escaping |
| p5-1 | Binary info JSON |
| p5-2 | `fdj` resolution |
| p5-3 | Functions JSON |
| p5-4 | Instructions JSON |
| p5-5 | Xrefs JSON |
| p5-6 | Maps/files JSON |
| p5-7 | Registers/debugger JSON |
| p5-8 | Comments metadata |
| p6-1 | Changelog/migration guide |
| p6-2 | Expand tests |
| p6-3 | Lint/format |
| p6-4 | 0.2.0 alpha release |
