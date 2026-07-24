# ASI — Aegis Static/dynamic Inspector

> A general-purpose **dead-code refactoring harness**. It finds functions that
> your test vectors never exercise, so you can delete them with confidence — and
> ranks the hot functions that are worth optimising.

ASI is **not** tied to this repository. Drop a small JSON config next to *any*
code base and it works. The engine is pure Python standard library — no `pip
install`, no third-party packages.

한국어 요약은 맨 아래 [「한국어 안내」](#한국어-안내) 참고.

---

## Why a harness, not an agent?

The task was: *find dead code, where "dead" means a function that is **not used
when the test-vector inputs are run**.*

That is a **measurement** problem, not a judgement problem. Whether a function
executes for a given input is a ground-truth fact you can observe by running the
code. So ASI is built as a deterministic **harness** that *measures* execution,
rather than an LLM **agent** that *guesses* reachability:

| | Coverage harness (ASI) | LLM agent |
|---|---|---|
| Answer to "did this run?" | Observed fact (ground truth) | Inference / guess |
| Reproducible | Yes, bit-for-bit | No |
| Handles reflection / function pointers / `dlsym` / `getattr` | Yes (it just runs) | Often wrong |
| Cost per run | ~free | tokens + latency |
| Auditable | JSON you can diff in CI | Prose |

The static approach (parse the call graph, mark unreachable functions) *can't*
satisfy the requirement either: it can't see indirect calls, and — more
importantly — it answers "is this reachable from `main`?", **not** "is this used
*by these specific test vectors*?", which is the question that was actually
asked. Dynamic coverage answers exactly that question.

> An agent is still useful *on top of* ASI — e.g. to read the machine-readable
> report and draft the deletion PR. ASI deliberately owns the part that must be
> exact (detection) and leaves the judgement calls to a human or an agent.

---

## What it does

1. Resolves your **test-vector corpus** — from a manifest text file that lists
   the paths (the common case), or by scanning a nested vector directory.
2. Builds/instruments the target for coverage (backend-specific).
3. **Replays every vector** against the program.
4. Collects **function-level execution counts** aggregated across the whole
   corpus.
5. Reports, per function:
   - **DEAD** — `hits == 0`: defined but never executed by any vector →
     safe-to-remove candidate.
   - **LIVE** — with a hit count, so the hottest functions surface as
     optimisation targets (the secondary goal).

Output: a terminal summary, `report.json` (machine-readable, CI-friendly), and
`report.md` (review-friendly, grouped by file).

6. **(Optional) Acts on the report** — `asi refactor` comments out the dead
   functions and can LLM-refactor the rest. See below.

---

## Backends (languages / toolchains)

| backend | languages | mechanism | requirements |
|---|---|---|---|
| `gcov`    | C, C++            | gcc/g++ `--coverage` + `gcov --json-format` | `gcc`, `gcov` |
| `llvmcov` | C, C++ (Obj-C…)   | clang `-fprofile-instr-generate -fcoverage-mapping` + `llvm-cov export` | `clang`, `llvm-profdata`, `llvm-cov`, compiler-rt |
| `pytrace` | Python            | pure-stdlib `sys.settrace` tracer | just Python |

Adding a backend for another language is ~40 lines — see
[GUIDE.md](GUIDE.md#adding-a-backend). The rest of the pipeline (vector
resolution, run loop, reporting) is language-agnostic.

---

## Quick start

```bash
cd ASI

# 1. see it work on the bundled examples
bash tests/selftest.sh

# 2. run a single example and read the report
python3 -m asi run -c examples/python_demo/asi.json
python3 -m asi run -c examples/c_demo/asi.json
cat examples/c_demo/asi_report/report.md
```

Expected: each demo has exactly three functions that no vector touches, and ASI
flags precisely those.

### On your own project

```bash
# Put ASI on the import path, then point it at your config.
# The config's relative paths resolve against the config file's own directory,
# so the config can live next to your project and stay portable.
PYTHONPATH=/path/to/ASI python3 -m asi run -c /path/to/your/asi.json
```

Useful flags:

```
python3 -m asi run -c asi.json            # full pipeline
                    --no-build            # skip the build step (already built)
                    --fail-on-dead        # exit 1 if any dead code (CI gate)
                    -v                     # per-vector run log
python3 -m asi list-vectors -c asi.json   # print resolved vector paths
python3 -m asi backends                    # list available backends
```

---

## Configuration in 30 seconds

A config is one JSON file. Minimal Python example:

```json
{
  "name": "myproject",
  "backend": "pytrace",
  "sources": { "include": ["mypkg/**/*.py"], "exclude": ["**/tests/**"] },
  "vectors": { "manifest": "vectors/index.txt", "base": "vectors" },
  "run": { "command": "run_one.py {input}" }
}
```

Minimal C example:

```json
{
  "name": "myproject",
  "backend": "gcov",
  "build": { "command": "make coverage" },
  "gcov": { "objdir": "build" },
  "sources": { "include": ["src/**/*.c"] },
  "vectors": { "manifest": "test_vectors/paths.txt", "base": "test_vectors" },
  "run": { "command": "./build/prog {input}" }
}
```

- `{input}` in `run.command` is replaced by each vector's path. Set
  `"run": { "stdin": true }` instead if the program reads the vector from stdin.
- `vectors.manifest` is a text file with **one vector path per line**
  (`#` comments and blank lines ignored; glob lines allowed). Prefer this — it
  matches the "paths collected in a separate text file" layout. Or use
  `vectors.dir` + `vectors.glob` to scan a nested folder directly.

The full reference for every key, plus troubleshooting, is in
**[GUIDE.md](GUIDE.md)**.

---

## Reading the result

`report.json` shape:

```json
{
  "summary": { "functions_total": 6, "functions_live": 3, "functions_dead": 3, ... },
  "dead": [ { "file": "calc.c", "name": "mul", "start_line": 14, "end_line": 14, "hits": 0 } ],
  "live": [ { "file": "calc.c", "name": "main", "hits": 3 }, ... ]
}
```

Every `dead` entry carries `file` + `start_line`/`end_line`, so removing it (or
generating a patch) is mechanical.

> ⚠️ **Dead means "not covered by *this* corpus."** If your vectors don't
> exercise a code path, functions on it look dead even though they're needed in
> production. ASI warns when vector runs fail (a failing run covers less) and
> reports how many vectors ran. Treat the dead list as *review candidates*, and
> make sure your corpus represents real usage before deleting anything.

---

## Acting on the report: `asi refactor`

The report *finds* dead code; `asi refactor` *acts* on it. It comments out the
dead functions and, optionally, uses an LLM to refactor the rest of the file —
in two clearly separated steps so correctness never depends on the model:

1. **Deterministic commenting (always safe).** Using the exact line ranges from
   the report, ASI disables each dead function — Python with `#`, C/C++ with
   `#if 0 … #endif`, others with `//`. This is exact and needs no API key.
2. **LLM refactor (optional).** The already-dead-commented file is sent to
   Claude with strict rules: keep the dead functions commented, preserve the
   public API and observable behaviour of the live code, output only the file.
   The result is **verified** (Python is syntax-checked; an optional
   `refactor.verify` build command runs for `--in-place`), and any output that
   fails verification is **discarded in favour of the safe commented-only
   version**. So the model can only ever improve the live code — it can never
   produce broken or dead-code-reviving output that gets written.

```bash
# Safest: just comment out the dead functions (no API key, no model).
python3 -m asi refactor -c asi.json --comment-only --out asi_refactored

# Full LLM refactor (needs: pip install anthropic, and ANTHROPIC_API_KEY or
# `ant auth login`). Writes to an output dir by default; --in-place keeps .asi.bak.
python3 -m asi refactor -c asi.json --out asi_refactored
python3 -m asi refactor -c asi.json --in-place        # overwrite, with backups
python3 -m asi refactor -c asi.json --dry-run          # preview, write nothing
python3 -m asi refactor -c asi.json --all-files        # refactor every file, not just dead-code ones
```

By default only files that **contain dead code** are processed (targeted and
cheap). `--all-files` (or `refactor.scope: "all"`) refactors the whole analysed
codebase. The LLM stage uses `claude-opus-4-8` with adaptive thinking and
streaming; model/effort are configurable under `llm` in the config. See
[GUIDE.md](GUIDE.md#the-refactor-stage) for the full reference.

### No API key? Use the agent skill instead

If you'd rather have **Claude Code drive the refactor itself** — reading the
report and editing files with its own tools, instead of a script calling the
API — this repo ships a project skill at
[`.claude/skills/asi-refactor`](../.claude/skills/asi-refactor/SKILL.md). It uses
the deterministic, API-free `--comment-only` step for the exact commenting, then
the agent refactors the live code and re-runs `asi run` to verify. Trigger it by
asking to "apply the ASI report" / "refactor based on the dead-code report".

> ⚠️ An LLM refactor rewrites live code. Always review the diff (or start with
> `--comment-only`), keep the run under version control, and re-run
> `asi run` afterwards to confirm the live functions still execute and the
> vectors still pass.

---

## 한국어 안내

**무엇을 하나요?** 테스트 벡터(입력 파일)들을 실제로 실행시켜서, **함수 단위로
한 번도 실행되지 않은 함수 = 죽은 코드(dead code)** 를 찾아 줍니다. 부가적으로
가장 많이 호출된 함수를 순위로 보여 주어 최적화 대상도 알려 줍니다.

**왜 agent가 아니라 harness인가요?** "이 함수가 이 테스트 벡터로 실행되는가"는
추론이 아니라 **관측**의 문제입니다. 코드를 직접 돌려서 커버리지를 측정하면
함수 포인터·리플렉션·`getattr` 같은 간접 호출까지 정확히 잡힙니다. LLM
agent는 이를 추측할 뿐이고, 정적 호출그래프 분석은 "`main`에서 도달 가능한가"만
답할 뿐 "이 벡터들이 실제로 쓰는가"에는 답하지 못합니다. 그래서 결정론적
harness로 만들었습니다.

**사용법**
- 대상 언어에 맞는 backend 선택: C/C++ → `gcov` 또는 `llvmcov`, Python →
  `pytrace`.
- 테스트 벡터는 **경로가 한 줄씩 적힌 manifest 텍스트 파일**(`vectors.manifest`)
  로 지정하거나, 여러 단계 하위폴더를 `vectors.dir` + `vectors.glob`로 스캔.
- 실행: `PYTHONPATH=/경로/ASI python3 -m asi run -c asi.json`
- 결과: 터미널 요약 + `asi_report/report.md` + `report.json`.

**주의**: "죽음"의 기준은 **주어진 벡터 corpus 기준**입니다. 벡터가 실제 사용을
충분히 대표하지 못하면 살아있는 함수도 죽은 것처럼 보일 수 있으니, dead 목록은
바로 삭제하지 말고 *검토 후보*로 다루세요.

**리팩토링 단계 (`asi refactor`)**: 리포트 결과를 바탕으로 (1) 사용하지 않는
함수를 **결정론적으로 주석 처리**하고 (Python `#`, C/C++ `#if 0`, 기타 `//`),
(2) 선택적으로 **LLM(Claude)으로 나머지 코드를 리팩토링**합니다. 두 단계는
분리되어 있어 정확성이 모델에 의존하지 않습니다 — 주석 처리는 리포트의 정확한
줄 범위로 항상 올바르게 되고, LLM 출력은 검증(Python 문법 검사 / 선택적 빌드
명령)을 통과하지 못하면 **안전한 주석-only 버전으로 자동 폴백**됩니다.

```bash
# 가장 안전: 죽은 함수만 주석 처리 (API 키 불필요)
python3 -m asi refactor -c asi.json --comment-only --out asi_refactored
# 전체 LLM 리팩토링 (pip install anthropic + ANTHROPIC_API_KEY 필요)
python3 -m asi refactor -c asi.json --out asi_refactored   # --in-place / --dry-run / --all-files
```

LLM 단계는 `claude-opus-4-8`(adaptive thinking, streaming)을 사용하며 `llm`
설정으로 모델·effort를 바꿀 수 있습니다. LLM 리팩토링은 살아있는 코드를 다시
쓰므로 반드시 diff를 검토하고, 이후 `asi run`을 다시 돌려 동작을 확인하세요.

자세한 설정과 backend 추가 방법은 [GUIDE.md](GUIDE.md)에 있습니다.
