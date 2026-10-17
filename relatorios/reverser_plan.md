# Reverser Agent (RE de firmware MIPS) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a builtin `reverser` agent to Kimi Code CLI with a 6-tool RE toolset (`BinIdent`, `BinStrings`, `Disassemble`, `GhidraDecompile`, `RefRE`, `PersistSession`) for reverse-engineering MIPS32 big-endian stripped firmware ELFs, plus `capstone` and per-session persistence to `rev/<target>.md`.

**Architecture:** New `kimi_cli.tools.re` package with `CallableTool2`-based tools following the `tools/web/search.py` pattern, sharing one `run_command` helper that wraps `kaos.exec`. A `reverser` agent spec (`extend: default`) selects the default tools plus the 6 RE tools, with a dedicated `system.md` prompt. `PersistSession` writes/merges checkpoints under `rev/` in the session workdir. Agent registration follows the `jarvis` precedent end-to-end (`agentspec.py` → `cli/__init__.py` → `README.md` → default `subagents`).

**Tech Stack:** Python 3.12+ / uv, `pytest` + `pytest-asyncio`, `capstone` (new runtime dep), `kaos.exec` for external binutils (`file`, `readelf`, `strings`, `analyzeHeadless`), `kosong.tooling.CallableTool2`.

**Spec:** `docs/superpowers/specs/2026-10-14-reverser-agent-design.md` (the plan argues from the spec; executors read both).

## Global Constraints

- Tools must not import from `kimi_cli/wire/` — use `kosong.tooling` (`ToolReturnValue`, `DisplayBlock`). (`src/kimi_cli/tools/AGENTS.md`)
- No `chalk`/color rules apply here (Python repo, no TUI changes).
- Ruff line length **100**; lint+format rules `E, F, UP, B, SIM, I`; types via pyright + ty. (`AGENTS.md`)
- Tests are `pytest` + `pytest-asyncio`, files `tests/**/test_*.py`. (`AGENTS.md`)
- Conventional Commits, allowed types `feat|fix|test|refactor|chore|style|docs|perf|build|ci|revert`; scope `reverser`. (`AGENTS.md`)
- **Minor-bump-only** versioning — never bump patch; do not touch `pyproject.toml` version. (`AGENTS.md`)
- Tool `__init__` positional params are injected by annotation from `dependencies`; a tool with no `__init__` in its own class dict is instantiated with no args; `SkipThisTool` raised in `__init__` removes the tool from the set. (`src/kimi_cli/soul/toolset.py:695-753`)
- A tool whose module import raises `ImportError` is dropped and breaks agent loading as `InvalidToolError` — `capstone` must be installed before `disassemble.py` is created. (`toolset.py:726-739`)
- `self._runtime.session.work_dir` is a `KaosPath` (absolute). (`src/kimi_cli/session.py:23`)
- RE tools run external binaries via `kaos.exec(*args, env=get_noninteractive_env())`; read stdout/stderr via `stream.readline()`; close stdin. (`tools/shell/__init__.py:221-261`)
- `tests/conftest.py` provides the `runtime: Runtime` fixture whose `session.work_dir` points at `temp_work_dir`. (`tests/conftest.py:150-180, 283`)

## Review Focus

Inputs the spec implies but no task's happy-path test exercises; each is pinned by a test in the owning task below.

1. **Disassemble on an unknown arch / non-binary file** must return a clean error result, not a capstone/struct exception. → Task 4.
2. **BinIdent / BinStrings on a nonexistent or non-ELF path** must return an error result, not raise. → Task 2.
3. **PersistSession with `merge=False` on an existing file** must overwrite (not preserve old tools). → Task 7.
4. **PersistSession `target` containing `/` or `..`** must be rejected so it cannot escape `rev/`. → Task 7.
5. **RefRE with an unknown topic** must return an error listing valid topics. → Task 6.

---

### Task 1: capstone dependency + RE package scaffold + shared command runner

**Files:**
- Modify: `pyproject.toml` (add `capstone` to `dependencies`)
- Modify: `uv.lock` (via `uv add`)
- Create: `src/kimi_cli/tools/re/__init__.py` (empty package marker)
- Create: `src/kimi_cli/tools/re/_util.py`
- Test: `tests/tools/re/test_util.py`

**Interfaces:**
- Consumes: `kaos.exec`, `get_noninteractive_env` from `kimi_cli.utils.subprocess_env`.
- Produces: `async def run_command(*args: str, timeout: int = 120) -> tuple[int, str]` in `src/kimi_cli/tools/re/_util.py` — runs the external command via `kaos.exec`, streams combined stdout+stderr, returns `(exit_code, output)`. Later tasks (BinIdent, BinStrings, GhidraDecompile) import it as `from kimi_cli.tools.re._util import run_command`.

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.tools.re._util import run_command


@pytest.mark.asyncio
async def test_run_command_captures_output_and_exit_code():
    code, output = await run_command("printf", "hello\nworld")
    assert code == 0
    assert "hello" in output and "world" in output


@pytest.mark.asyncio
async def test_run_command_reports_nonzero_exit():
    code, output = await run_command("false")
    assert code != 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_util.py -v`
Expected: FAIL with `ModuleNotFoundError: kimi_cli.tools.re`

- [ ] **Step 3: Add capstone and create the package scaffold**

Run: `uv add capstone` (adds `capstone` to `pyproject.toml` `dependencies` and updates `uv.lock`). Create `src/kimi_cli/tools/re/__init__.py` as an empty file. Create `src/kimi_cli/tools/re/_util.py` implementing `run_command` with `kaos.exec(*args, env=get_noninteractive_env())`, closing stdin, and draining stdout+stderr via `stream.readline()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_util.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Verify capstone import + lint**

Run: `uv run python -c "import capstone; print(capstone.__version__)"` and `uv run ruff check src/kimi_cli/tools/re/`
Expected: capstone version printed; ruff reports no errors.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock src/kimi_cli/tools/re/
git commit -m "build: add capstone dependency and RE tool package scaffold"
```

---

### Task 2: `BinIdent` tool + MIPS ELF test fixture

**Files:**
- Create: `src/kimi_cli/tools/re/bin_ident.py`
- Create: `src/kimi_cli/tools/re/bin_ident.md` (tool description, rendered via `load_desc`)
- Create: `tests/tools/re/conftest.py` (`mips_elf_path` fixture shared by Tasks 2/3/4)
- Test: `tests/tools/re/test_bin_ident.py`

**Interfaces:**
- Consumes: `run_command` from Task 1; `mips_elf_path` fixture (this task).
- Produces: `class BinIdent(CallableTool2[Params])` at `kimi_cli.tools.re.bin_ident:BinIdent`, with `name="BinIdent"`, `description=load_desc(Path(__file__).parent / "bin_ident.md", {})`, `params: type[Params] = Params`, no custom `__init__`, and `async def __call__(self, params) -> ToolReturnValue`. `Params` = `target: str` (path to the binary). On success returns `builder.ok()` with the combined output of `file <target>` and `readelf -h -l -S -d <target>`.

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.tools.re.bin_ident import BinIdent, Params


@pytest.mark.asyncio
async def test_bin_ident_recognizes_mips_elf(mips_elf_path: str):
    result = await BinIdent()(Params(target=mips_elf_path))
    assert not result.is_error
    assert "MIPS" in result.output
    assert "MSB" in result.output  # big-endian from `file`


@pytest.mark.asyncio
async def test_bin_ident_missing_file_returns_error(tmp_path):
    result = await BinIdent()(Params(target=str(tmp_path / "nope")))
    assert result.is_error
```

`tests/tools/re/conftest.py`: add a `mips_elf_path: str` fixture that writes a **minimal but valid ELF32 big-endian MIPS executable** (embedded bytes) to `tmp_path` and yields its path string. Requirements so downstream tools parse it: `e_ident` with `EI_DATA=2` (big-endian) and `EI_CLASS=1` (32-bit); `e_machine=EM_MIPS=8`; `e_type=ET_EXEC`; a `.text` section containing the bytes `0x00000000` (`nop`), `0x03e00008` (`jr $ra`), `0x24040001` (`addiu $a0,$zero,1`), followed by the ASCII string `HELLORE\0`; plus a section-name string table so `readelf -S` parses.

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_bin_ident.py -v`
Expected: FAIL with `ImportError` / `AttributeError` (`kimi_cli.tools.re.bin_ident` missing).

- [ ] **Step 3: Implement `BinIdent` in `src/kimi_cli/tools/re/bin_ident.py`**

`Params` is a pydantic `BaseModel` with one required field `target: str`. `BinIdent` follows the `Think` pattern (class-level `name`/`description`/`params`, no `__init__`). In `__call__`, run `run_command("file", target)` then `run_command("readelf", "-h", "-l", "-S", "-d", target)`, write both outputs to a `ToolResultBuilder(max_line_length=None)`; if a command exits non-zero, return `builder.error(...)` with the captured output.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_bin_ident.py -v`
Expected: PASS (2 passed) — requires `file`/`readelf` on PATH (standard binutils).

- [ ] **Step 5: Commit**

```bash
git add src/kimi_cli/tools/re/ tests/tools/re/
git commit -m "feat(reverser): add BinIdent tool with MIPS ELF test fixture"
```

---

### Task 3: `BinStrings` tool

**Files:**
- Create: `src/kimi_cli/tools/re/bin_strings.py`
- Create: `src/kimi_cli/tools/re/bin_strings.md`
- Test: `tests/tools/re/test_bin_strings.py`

**Interfaces:**
- Consumes: `run_command` (Task 1); `mips_elf_path` fixture (Task 2).
- Produces: `class BinStrings(CallableTool2[Params])` at `kimi_cli.tools.re.bin_strings:BinStrings`, no custom `__init__`. `Params` fields: `target: str`; `min_length: int = 4`; `encoding: Literal["s", "b", "S", "l"] = "s"` (strings `-n`/`-e` flags). Runs `strings` with `-n <min_length> -e <encoding>`, writes output via `ToolResultBuilder`, returns error on non-zero exit.

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.tools.re.bin_strings import BinStrings, Params


@pytest.mark.asyncio
async def test_bin_strings_finds_embedded_string(mips_elf_path: str):
    result = await BinStrings()(Params(target=mips_elf_path, min_length=4))
    assert not result.is_error
    assert "HELLORE" in result.output


@pytest.mark.asyncio
async def test_bin_strings_missing_file_returns_error(tmp_path):
    result = await BinStrings()(Params(target=str(tmp_path / "nope")))
    assert result.is_error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_bin_strings.py -v`
Expected: FAIL with `ImportError` (`kimi_cli.tools.re.bin_strings` missing).

- [ ] **Step 3: Implement `BinStrings` in `src/kimi_cli/tools/re/bin_strings.py`**

Same shape as `BinIdent`: pydantic `Params`, class-level metadata, `__call__` builds `["strings", "-n", str(min_length), "-e", encoding, target]` and runs it via `run_command`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_bin_strings.py -v`
Expected: PASS (2 passed) — requires `strings` on PATH.

- [ ] **Step 5: Commit**

```bash
git add src/kimi_cli/tools/re/ tests/tools/re/
git commit -m "feat(reverser): add BinStrings tool"
```

---

### Task 4: `Disassemble` tool (capstone, auto-detect arch/endian)

**Files:**
- Create: `src/kimi_cli/tools/re/disassemble.py`
- Create: `src/kimi_cli/tools/re/disassemble.md`
- Test: `tests/tools/re/test_disassemble.py`

**Interfaces:**
- Consumes: `mips_elf_path` fixture (Task 2); `capstone` (Task 1).
- Produces: `class Disassemble(CallableTool2[Params])` at `kimi_cli.tools.re.disassemble:Disassemble`, no custom `__init__`. `Params` fields:
  - `target: str`
  - `arch: Literal["mips", "arm", "x86"] | None = None` (default: auto-detect)
  - `endian: Literal["big", "little"] | None = None` (default: auto-detect)
  - `offset: int | None = None` (file offset to disassemble from)
  - `va: int | None = None` (virtual address to disassemble from; translated to a file offset)
  - `size: int = 0x40` (bytes to disassemble)
  - `count: int = 0` (max instructions; `0` = all in `size`)

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.tools.re.disassemble import Disassemble, Params


@pytest.mark.asyncio
async def test_disassemble_mips_auto_detect(mips_elf_path: str):
    result = await Disassemble()(Params(target=mips_elf_path, size=8))
    assert not result.is_error
    assert "nop" in result.output
    assert "jr" in result.output


@pytest.mark.asyncio
async def test_disassemble_non_binary_returns_error(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("not an elf at all")
    result = await Disassemble()(Params(target=str(p)))
    assert result.is_error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_disassemble.py -v`
Expected: FAIL with `ImportError` (`kimi_cli.tools.re.disassemble` missing).

- [ ] **Step 3: Implement `Disassemble` in `src/kimi_cli/tools/re/disassemble.py`**

Auto-detect by reading the first 20 bytes of the target: `EI_DATA` (byte 5) → endian (`2`=big), `EI_CLASS` (byte 4) → `1`=32-bit/`2`=64-bit. If `va` is given, translate it to a file offset from the `.text` section via `readelf -S` output; if `offset` given, use it directly. Build a `capstone.Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | (CS_MODE_BIG_ENDIAN if endian=="big" else CS_MODE_LITTLE_ENDIAN))` (only MIPS required for v1; `arm`/`x86` map to the corresponding `CS_ARCH`). Disassemble the byte slice, write each instruction as `address  bytes  mnemonic operands`, stop at `count` if set. Wrap read/capstone failures in a `builder.error(...)` (do not let exceptions escape — this pins Review Focus item 1).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_disassemble.py -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add src/kimi_cli/tools/re/ tests/tools/re/
git commit -m "feat(reverser): add Disassemble tool with capstone"
```

---

### Task 5: `GhidraDecompile` tool (detection + dispatch)

**Files:**
- Create: `src/kimi_cli/tools/re/ghidra_decompile.py`
- Create: `src/kimi_cli/tools/re/ghidra_decompile.md`
- Test: `tests/tools/re/test_ghidra_decompile.py`

**Interfaces:**
- Consumes: `run_command` (Task 1); `SkipThisTool` from `kimi_cli.tools`.
- Produces: `class GhidraDecompile(CallableTool2[Params])` at `kimi_cli.tools.re.ghidra_decompile:GhidraDecompile` with a custom `__init__` that locates `analyzeHeadless` (`shutil.which` plus known snap path `/snap/ghidra/current/**/support/analyzeHeadless`) and **raises `SkipThisTool()` if not found** (so the tool silently drops from the set when Ghidra is absent). `Params` fields: `target: str`; `function: str | None = None`; `timeout: int = 600`. `__call__` builds an `analyzeHeadless` command (temp project, `-import <target>`, decompile via a bundled Ghidra script), runs it, and returns the decompiled pseudo-code.

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.tools import SkipThisTool
from kimi_cli.tools.re.ghidra_decompile import GhidraDecompile, Params


def test_ghidra_decompile_skips_when_headless_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(SkipThisTool):
        GhidraDecompile()


@pytest.mark.asyncio
async def test_ghidra_decompile_dispatch_path(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr("shutil.which", lambda _: "/fake/analyzeHeadless")

    async def fake_run(*args: str, timeout: int = 120):
        calls.append(list(args))
        return 0, "decompiled code"

    monkeypatch.setattr("kimi_cli.tools.re.ghidra_decompile.run_command", fake_run)
    tool = GhidraDecompile()
    result = await tool(Params(target="/tmp/sample", function="main"))
    assert not result.is_error
    assert "decompiled code" in result.output
    assert calls and calls[0][0].endswith("analyzeHeadless")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_ghidra_decompile.py -v`
Expected: FAIL with `ImportError` (`kimi_cli.tools.re.ghidra_decompile` missing).

- [ ] **Step 3: Implement `GhidraDecompile` in `src/kimi_cli/tools/re/ghidra_decompile.py`**

`__init__` resolves the `analyzeHeadless` path and raises `SkipThisTool()` when absent. `__call__` runs `analyzeHeadless <tmpdir> <proj> -import <target> [-postScript <decompiler script> ...]` via `run_command`, capturing output. Real Ghidra execution is not exercised in CI (skip path is the tested contract; the dispatch test pins command construction).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_ghidra_decompile.py -v`
Expected: PASS (2 passed) — no real Ghidra needed.

- [ ] **Step 5: Commit**

```bash
git add src/kimi_cli/tools/re/ tests/tools/re/
git commit -m "feat(reverser): add GhidraDecompile tool with skip-when-absent dispatch"
```

---

### Task 6: `RefRE` tool + curated reference library

**Files:**
- Create: `src/kimi_cli/tools/re/ref_re.py`
- Create: `src/kimi_cli/tools/re/ref_re.md`
- Create: `src/kimi_cli/tools/re/reference/{mitigations,bypass,memory,techniques,fuzzing,report,checklists,legal}.md` (8 curated markdown files)
- Test: `tests/tools/re/test_ref_re.py`

**Interfaces:**
- Consumes: nothing external.
- Produces: `class RefRE(CallableTool2[Params])` at `kimi_cli.tools.re.ref_re:RefRE`, no custom `__init__`. `Params` = `topic: str` (the reference filename stem). `__call__` returns the content of `reference/<topic>.md`; for an unknown topic returns an error listing the valid topics (pins Review Focus item 5).

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.tools.re.ref_re import RefRE, Params

TOPICS = ["mitigations", "bypass", "memory", "techniques", "fuzzing", "report", "checklists", "legal"]


@pytest.mark.asyncio
@pytest.mark.parametrize("topic", TOPICS)
async def test_ref_re_returns_topic(topic: str):
    result = await RefRE()(Params(topic=topic))
    assert not result.is_error
    assert len(result.output.strip()) > 0


@pytest.mark.asyncio
async def test_ref_re_unknown_topic_errors():
    result = await RefRE()(Params(topic="nope"))
    assert result.is_error
    assert "mitigations" in result.output  # error lists valid topics
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_ref_re.py -v`
Expected: FAIL with `ImportError` (`kimi_cli.tools.re.ref_re` missing).

- [ ] **Step 3: Implement `RefRE` and author the 8 reference files**

`RefRE` resolves `Path(__file__).parent / "reference" / f"{topic}.md"`, reads it, returns via `ToolResultBuilder`; on missing file returns `builder.error` listing the 8 valid topics. Author each `reference/*.md` as curated, re-written content (not copied verbatim) covering the spec §4.2 topics: `mitigations` (ASLR/KASLR/NX/DEP/Canary/RELRO/CFG/CET + `checksec`); `bypass` (bypass decision tree); `memory` (stack BOF, heap/glibc tcache/fastbin/unsorted/House of Force/Spirit, FSOP, UAF, format string, integer overflow, TOCTOU); `techniques` (ROP, ret2libc, ret2csu, SROP, SEH overflow, VirtualProtect, ARM Thumb); `fuzzing` (AFL++/libFuzzer, `afl-tmin`, CWE triage); `report` (RE report structure); `checklists` (offensive/defensive checklists); `legal` (authorized-writing disclaimer, CVD, BR Lei 12.737/2012, US CFAA).

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_ref_re.py -v`
Expected: PASS (10 passed: 8 topics + error + parametrized count).

- [ ] **Step 5: Commit**

```bash
git add src/kimi_cli/tools/re/ tests/tools/re/
git commit -m "feat(reverser): add RefRE tool and curated reference library"
```

---

### Task 7: `PersistSession` tool (merge to `rev/<target>.md`)

**Files:**
- Create: `src/kimi_cli/tools/re/persist_session.py`
- Create: `src/kimi_cli/tools/re/persist_session.md`
- Test: `tests/tools/re/test_persist_session.py`

**Interfaces:**
- Consumes: `Runtime` from `kimi_cli.soul.agent` (injected via `__init__`); `runtime.session.work_dir`.
- Produces: `class PersistSession(CallableTool2[Params])` at `kimi_cli.tools.re.persist_session:PersistSession` with `def __init__(self, runtime: Runtime)` storing `self._runtime = runtime`. `Params` fields: `target: str` (binary/lib name, may keep `.so`/`.a`/`.dll`); `notes: str` (complete state markdown); `merge: bool = True`. `__call__` writes to `rev/<target>.md` under `self._runtime.session.work_dir`, auto-creating `rev/`, and returns the **absolute path** written in `result.output`. When `merge` and the file exists, it preserves the existing `## Ferramentas` section and prepends it to `notes`.

- [ ] **Step 1: Write the failing test**

```python
import pytest
from kaos.path import KaosPath

from kimi_cli.tools.re.persist_session import PersistSession, Params


@pytest.mark.asyncio
async def test_persist_session_creates_rev_file(runtime, temp_work_dir: KaosPath):
    tool = PersistSession(runtime)
    result = await tool(Params(target="libixml.so", notes="# RE — libixml.so\n\n## Descobertas\nfirst"))
    path = temp_work_dir / "rev" / "libixml.so.md"
    assert not result.is_error
    assert str(path) in result.output
    assert (await path.read_text()).find("first") != -1


@pytest.mark.asyncio
async def test_persist_session_merge_preserves_tools(runtime, temp_work_dir: KaosPath):
    tool = PersistSession(runtime)
    await tool(Params(target="t", notes="# RE — t\n\n## Ferramentas\n| readelf | /usr/bin/readelf |\n\n## Descobertas\nfirst"))
    result = await tool(Params(target="t", notes="## Descobertas\nsecond"))
    path = temp_work_dir / "rev" / "t.md"
    text = await path.read_text()
    assert "| readelf | /usr/bin/readelf |" in text   # old tools preserved
    assert "second" in text                            # new state applied


@pytest.mark.asyncio
async def test_persist_session_merge_false_overwrites(runtime, temp_work_dir: KaosPath):
    tool = PersistSession(runtime)
    await tool(Params(target="t", notes="## Ferramentas\n| old | x |"))
    await tool(Params(target="t", notes="## Descobertas\nnew", merge=False))
    text = await (temp_work_dir / "rev" / "t.md").read_text()
    assert "| old | x |" not in text
    assert "new" in text


@pytest.mark.asyncio
async def test_persist_session_rejects_path_traversal(runtime):
    tool = PersistSession(runtime)
    result = await tool(Params(target="../../etc/passwd", notes="x"))
    assert result.is_error
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/tools/re/test_persist_session.py -v`
Expected: FAIL with `ImportError` (`kimi_cli.tools.re.persist_session` missing).

- [ ] **Step 3: Implement `PersistSession` in `src/kimi_cli/tools/re/persist_session.py`**

`__init__(self, runtime: Runtime)` stores `self._runtime`. In `__call__`: reject `target` containing `/`, `\\`, or `..` (pins Review Focus item 4). Build `rev_dir = Path(str(self._runtime.session.work_dir)) / "rev"`, `mkdir(parents=True, exist_ok=True)`; target path `rev_dir / f"{target}.md"`. If `merge` and the file exists, extract the existing `## Ferramentas` section (from the `## Ferramentas` line through the next `## ` heading or EOF, inclusive) and prepend it to `notes`; write the result. Return `builder.ok()` with the absolute path in `result.output`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/tools/re/test_persist_session.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/kimi_cli/tools/re/ tests/tools/re/
git commit -m "feat(reverser): add PersistSession tool with rev/ merge"
```

---

### Task 8: Agent registration + `reverser` spec and prompt

**Files:**
- Modify: `src/kimi_cli/agentspec.py:22` (add `REVERSER_AGENT_FILE`)
- Modify: `src/kimi_cli/cli/__init__.py:285,382,463-469` (Literal, import, match case)
- Modify: `README.md:194-198` (agent table row + usage example)
- Modify: `src/kimi_cli/agents/default/agent.yaml:27-35` (add `reverser` to `subagents`)
- Create: `src/kimi_cli/agents/reverser/agent.yaml`
- Create: `src/kimi_cli/agents/reverser/system.md`
- Modify: `src/kimi_cli/tools/re/__init__.py` (export the 6 tools)
- Test: `tests/core/test_reverser_agent.py`

**Interfaces:**
- Consumes: `REVERSER_AGENT_FILE` (this task); the 6 RE tool classes from Tasks 2–7; `load_agent`/`load_agent_spec` from `kimi_cli.soul.agent`/`kimi_cli.agentspec`.
- Produces: the `reverser` agent spec and prompt; the populated `kimi_cli.tools.re` package exporting `BinIdent`, `BinStrings`, `Disassemble`, `GhidraDecompile`, `RefRE`, `PersistSession`.

- [ ] **Step 1: Write the failing test**

```python
import pytest

from kimi_cli.agentspec import REVERSER_AGENT_FILE, load_agent_spec
from kimi_cli.soul.agent import Runtime, load_agent

RE_TOOLS = {"BinIdent", "BinStrings", "Disassemble", "RefRE", "PersistSession"}


@pytest.mark.asyncio
async def test_reverser_agent_loads_re_toolset(runtime: Runtime):
    agent = await load_agent(REVERSER_AGENT_FILE, runtime, mcp_configs=[])
    assert agent.name == "reverser"
    tool_names = {tool.name for tool in agent.toolset.tools}
    assert RE_TOOLS <= tool_names, f"missing: {RE_TOOLS - tool_names}"


def test_reverser_agent_inherits_default_subagents():
    spec = load_agent_spec(REVERSER_AGENT_FILE)
    assert set(spec.subagents) == {"coder", "explore", "plan"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/core/test_reverser_agent.py -v`
Expected: FAIL with `ImportError: cannot import name 'REVERSER_AGENT_FILE'`.

- [ ] **Step 3: Register the agent**

- `src/kimi_cli/agentspec.py:22`: add `REVERSER_AGENT_FILE = get_agents_dir() / "reverser" / "agent.yaml"`.
- `src/kimi_cli/cli/__init__.py:285`: `Literal["default", "okabe", "jarvis", "reverser"] | None`.
- `src/kimi_cli/cli/__init__.py:382`: add `REVERSER_AGENT_FILE` to the `from kimi_cli.agentspec import ...` line.
- `src/kimi_cli/cli/__init__.py:463-469`: add `case "reverser": agent_file = REVERSER_AGENT_FILE`.
- `README.md` after line 198: add row `| \`reverser\` | Agente de engenharia reversa (RE) de firmware embarcado, com toolset RE e persistência \`rev/<target>.md\`. |` and a `# Agente reverser (engenharia reversa)` usage example `uv run kimi --agent reverser -p "..."`.
- `src/kimi_cli/agents/default/agent.yaml` `subagents:`: add
  `reverser:\n  path: ../reverser/agent.yaml\n  description: "Reverse engineering of embedded firmware binaries (RE toolset + session persistence)."`

- [ ] **Step 4: Create `src/kimi_cli/agents/reverser/agent.yaml`**

`version: 1`, `agent:` with `name: "reverser"`, `extend: default`, `system_prompt_path: ./system.md`, `system_prompt_args: { ROLE_ADDITIONAL: "" }`, and `tools:` listing the 17 default tools (copy verbatim from `default/agent.yaml:8-26`) **plus** the 6 RE import paths: `kimi_cli.tools.re.bin_ident:BinIdent`, `kimi_cli.tools.re.bin_strings:BinStrings`, `kimi_cli.tools.re.disassemble:Disassemble`, `kimi_cli.tools.re.ghidra_decompile:GhidraDecompile`, `kimi_cli.tools.re.ref_re:RefRE`, `kimi_cli.tools.re.persist_session:PersistSession`.

- [ ] **Step 5: Create `src/kimi_cli/agents/reverser/system.md`**

Author the system prompt covering the spec §4.1: role/objective (RE of embedded firmware); the zero-day pipeline (Alvo → Superfície → Descoberta → Triage → Exploit → Reliability/Bypass → Disclosure); static/dynamic/symbolic methodology with fuzzing as a documented technique; MIPS o32 gotchas (delay slots, `$a0`–`$a3`, `$gp`/`$t9`, MIPS vs x86 syscalls, VA↔file offset, PIE vs non-PIE); exploitability honesty; the Markdown report convention; and **session persistence**: at session start look for `rev/<target>.md` in the workdir (via `Glob` + `ReadFile`) and resume pending items/map/tools; before the final analysis message, call `PersistSession` to write the full state.

- [ ] **Step 6: Populate `src/kimi_cli/tools/re/__init__.py`**

Export all six tools (pattern of `tools/web/__init__.py`): `from .bin_ident import BinIdent`, `from .bin_strings import BinStrings`, `from .disassemble import Disassemble`, `from .ghidra_decompile import GhidraDecompile`, `from .ref_re import RefRE`, `from .persist_session import PersistSession`, plus `__all__`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `uv run pytest tests/core/test_reverser_agent.py -v`
Expected: PASS (2 passed).

- [ ] **Step 8: Commit**

```bash
git add src/kimi_cli/agentspec.py src/kimi_cli/cli/__init__.py README.md \
        src/kimi_cli/agents/default/agent.yaml src/kimi_cli/agents/reverser/ \
        src/kimi_cli/tools/re/__init__.py tests/core/test_reverser_agent.py
git commit -m "feat(reverser): register builtin reverser agent"
```

---

### Task 9: Full verification

**Files:** none (verification only).

**Interfaces:** — 

- [ ] **Step 1: Run the full check and test suites**

Run: `make check && make test`
Expected: Both pass (ruff, pyright/ty, and the full pytest suite green, including the new `tests/tools/re/` and `tests/core/test_reverser_agent.py`).

- [ ] **Step 2: Smoke-test agent selection**

Run: `uv run kimi --agent reverser -p "list your tools"` (or, if a model is unavailable, confirm `uv run kimi --agent reverser --help` parses the flag without error).
Expected: The CLI accepts `--agent reverser` and loads the reverser agent.

- [ ] **Step 3: Commit any stragglers**

Run: `git status`
Expected: Clean working tree (nothing uncommitted) or only unrelated pre-existing changes remain.

---

## Self-Review Notes

- **Spec coverage:** §4.1 agent + system.md → Task 8; §4.2 six tools → Tasks 2–7; §4.3 registration (agentspec/cli/README/default subagents) → Task 8; §4.4 capstone dep → Task 1; §4.5 tests + MIPS ELF fixture → Tasks 2–7 + Task 9. Success criteria (`kimi --agent reverser` loads, toolset responds, `PersistSession` merge, `make check`/`make test`) → Tasks 8/9. Ghidra CI-skip and snap-path risk → Task 5. All spec sections mapped.
- **Interfaces:** `run_command` (Task 1) consumed by Tasks 2/3/5; `mips_elf_path` (Task 2) consumed by Tasks 3/4; 6 tool class names/import paths produced in Tasks 2–7 and consumed verbatim by the agent spec in Task 8 — names match across tasks.
- **Review Focus:** all five items pinned by tests (Tasks 2, 4, 6, 7).

