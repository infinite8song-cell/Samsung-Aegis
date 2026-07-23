# ASI Guide — configuration reference & extension

This is the deep reference. For the pitch and quick start, see
[README.md](README.md).

- [How it works, end to end](#how-it-works-end-to-end)
- [Configuration reference](#configuration-reference)
- [Recipes](#recipes)
- [Interpreting results correctly](#interpreting-results-correctly)
- [Adding a backend](#adding-a-backend)
- [Troubleshooting](#troubleshooting)

---

## How it works, end to end

```
 config.json
     │
     ▼
 resolve sources ─────────────► the "universe": every function that could be dead
     │
 resolve vectors (manifest / dir scan)
     │
     ▼
 backend.prepare()      build + instrument the target (once)
 backend.before_run()   delete stale coverage counters (once)
     │
     ▼   for each vector:
 runner → backend.wrap_command() + backend.per_run_env() → subprocess
     │
     ▼
 backend.collect()      parse coverage → [FunctionCoverage(file,name,lines,hits)]
     │
     ▼
 report:  hits == 0  ⇒  DEAD        hits ranked  ⇒  optimisation hotspots
```

`hits` is the **aggregate over the whole corpus**: a function is dead only if
*no* vector ever entered it. Coverage counters accumulate across runs
(gcov merges `.gcda` automatically; llvm merges `.profraw`; pytrace unions
trace files).

---

## Configuration reference

A config is a single JSON object. All relative paths resolve against
`root` (which itself defaults to the directory containing the config file).

### Top level

| key | type | default | meaning |
|---|---|---|---|
| `name` | string | project dir name | label used in reports |
| `backend` | string | **required** | `gcov` \| `llvmcov` \| `pytrace` |
| `root` | path | config file's dir | base for all relative paths |
| `workdir_tmp` | path | system temp | where ASI keeps coverage scratch files |
| `sources` | object | — | which files define the candidate functions |
| `vectors` | object | **required** | the test-vector corpus |
| `build` | object | — | optional build/instrument command |
| `run` | object | **required** | how to run one vector |
| `report` | object | — | output location/formats |
| plus one backend-specific block (`gcov` / `llvmcov` / `pytrace`) | | | |

### `sources`

Defines the analysis universe — the functions that *can* be reported dead.

```json
"sources": { "include": ["src/**/*.c", "lib/**/*.c"], "exclude": ["**/test/**"] }
```

| key | type | meaning |
|---|---|---|
| `include` | string \| [string] | glob(s), `**` = recursive |
| `exclude` | string \| [string] | globs removed from the include set |

> For `llvmcov`, source filtering is applied by the exported coverage data
> itself, so `sources.include` is advisory there; for `gcov` and `pytrace` it
> is authoritative.

### `vectors`

Two mutually-exclusive modes.

**Manifest mode** (preferred — matches "paths listed in a separate text file"):

```json
"vectors": { "manifest": "vectors/paths.txt", "base": "vectors", "exclude": ["**/skip/**"] }
```

- `manifest`: text file, **one vector path per line**. `#` comments and blank
  lines ignored. A line containing glob magic (`group_*/**/*.bin`) is expanded.
- `base`: directory that manifest paths are relative to (default: `root`).

**Directory-scan mode**:

```json
"vectors": { "dir": "test_vectors", "glob": "**/*", "exclude": [] }
```

- `dir`: root of the (arbitrarily nested) vector tree.
- `glob`: pattern under `dir` (default `**/*`); only files are kept.

`exclude` (both modes): globs, relative to `base`/`dir`, removed from the set.

### `build`

Optional. Skipped entirely if absent, or with `--no-build`.

```json
"build": { "command": "make coverage", "workdir": ".", "env": { "CC": "gcc" } }
```

The command **must produce a coverage-instrumented target**:
- `gcov`: compile with `--coverage` (`-fprofile-arcs -ftest-coverage`).
- `llvmcov`: compile with `-fprofile-instr-generate -fcoverage-mapping`.
- `pytrace`: usually no build needed.

### `run`

How ASI turns one vector into one process.

```json
"run": {
  "command": "./build/prog {input}",
  "stdin": false,
  "per_vector": true,
  "workdir": ".",
  "timeout": 120,
  "allow_failure": true,
  "env": {}
}
```

| key | default | meaning |
|---|---|---|
| `command` | **required** | `{input}` is replaced by the vector path (shell-quoted) |
| `stdin` | `false` | if true, feed the vector file to the program's stdin (no `{input}`) |
| `per_vector` | `true` | if false, run `command` **once** (the program consumes the whole corpus itself) |
| `workdir` | `root` | cwd for each run |
| `timeout` | `120` | seconds per run |
| `allow_failure` | `true` | non-zero exit doesn't abort the analysis (but is counted + warned) |
| `env` | `{}` | extra environment variables |

The command runs through the shell, so pipelines, wrappers and emulators work:
`"qemu-arm -L /sysroot ./prog {input}"`.

### Backend blocks

`gcov`:
```json
"gcov": { "objdir": "build", "tool": "gcov" }
```
- `objdir`: where the `.gcno`/`.gcda` live (default: `build.workdir`).
- `tool`: gcov binary (use a matching `gcov` for your `gcc`; for clang builds
  point this at `llvm-cov gcov` via a wrapper, or use the `llvmcov` backend).

`llvmcov`:
```json
"llvmcov": { "binary": "build/prog", "profdata_tool": "llvm-profdata", "cov_tool": "llvm-cov" }
```
- `binary`: **required**, the instrumented executable to export coverage from.

`pytrace`:
```json
"pytrace": { "python": "python3" }
```
- `python`: interpreter used to run the target (default: the one running ASI).
- **`run.command` must be the target script itself** (`solve.py {input}`), not
  `python solve.py {input}` — the tracer supplies the interpreter.

### `report`

```json
"report": { "dir": "asi_report", "formats": ["md", "json"] }
```

---

## Recipes

**Program reads the vector from stdin:**
```json
"run": { "command": "./prog", "stdin": true }
```

**KAT-style runner that iterates the whole corpus itself:**
```json
"run": { "command": "./run_all_kats", "per_vector": false }
```
(Here ASI measures coverage of that single run; there is no per-vector loop.)

**CI gate that fails the build when dead code appears:**
```bash
PYTHONPATH=$PWD/ASI python3 -m asi run -c asi.json --fail-on-dead
```

**Vectors nested many folders deep, no manifest:**
```json
"vectors": { "dir": "test_vectors", "glob": "**/*.bin" }
```

**Vectors listed in an existing paths file (nested tree):**
```json
"vectors": { "manifest": "test_vectors/all_paths.txt", "base": "test_vectors" }
```

---

## Interpreting results correctly

- **Dead = uncovered by *this* corpus.** The result is only as good as the
  vectors. Before deleting, confirm the corpus represents real usage. Run
  `python3 -m asi list-vectors -c asi.json` to see exactly what was replayed.
- **Failed runs undercount coverage.** If vectors error out early, functions on
  later paths look dead. ASI prints `N ok, M failed` and the report warns when
  `M > 0`. Fix the corpus/runner first.
- **Optimisation build vs. coverage build.** Coverage builds use `-O0`. Use the
  dead-code list to *decide what to remove*; re-measure performance on your
  normal optimised build.
- **`static`/`inline`/header functions (C).** Inlined functions may be
  attributed to each including translation unit; ASI ORs liveness across TUs
  (max hit count wins), so a function used anywhere is never falsely dead.
- **Whole-program vs. library.** ASI measures whatever your `run.command`
  drives. To judge a library, make the corpus drive the public API you care
  about.

---

## Adding a backend

Everything except coverage extraction is already language-agnostic, so a new
backend is small. Steps:

1. Create `asi/backends/<lang>.py` with a `Backend` subclass:

   ```python
   from .base import Backend
   from ..model import FunctionCoverage

   class RustBackend(Backend):
       key = "rustcov"

       def prepare(self):        # build + instrument (once)
           self._build()

       def before_run(self):     # delete stale counters (once)
           ...

       def per_run_env(self, index, vector):   # give each run its own data file
           return {"LLVM_PROFILE_FILE": f".../{index}.profraw"}

       def wrap_command(self, command, index, vector):  # optional: wrap the run
           return command

       def collect(self):        # -> list[FunctionCoverage]
           # parse your coverage tool's output; hits == 0 means dead
           return [FunctionCoverage(file=..., name=..., start_line=...,
                                    end_line=..., hits=...)]
   ```

2. Register it in `asi/backends/__init__.py`:

   ```python
   from .rustcov import RustBackend
   _REGISTRY[RustBackend.key] = RustBackend
   ```

That's it — vector resolution, the run loop, reporting and the CLI all work
unchanged. The only contract is: **return one `FunctionCoverage` per function
with an accurate aggregate `hits`, where `0` means "never executed".**

The `pytrace` backend (pure-stdlib `sys.settrace`, ~70 lines including the
subprocess tracer in `asi/_tracerun.py`) is a good template for
interpreted-language backends; `gcov`/`llvmcov` for compiled ones.

---

## Troubleshooting

| symptom | cause / fix |
|---|---|
| everything reported dead | coverage not produced. gcov: forgot `--coverage`; check `.gcda` appear next to `.gcno` in `objdir`. llvm: no `.profraw` (missing `-fprofile-instr-generate`/compiler-rt). pytrace: `run.command` had a `python` prefix — remove it. |
| `no .profraw produced` | the instrumented binary didn't write coverage; ensure the build flags are present and `run.command` invokes the instrumented binary. |
| gcov emits gzipped files, JSON parse skipped | your gcov version differs; point `gcov.tool` at a wrapper that supports `--json-format --stdout`, or use the `llvmcov` backend. |
| `libclang_rt.profile... not found` (llvm) | install LLVM's compiler-rt profile runtime for your clang, or use the `gcov` backend with gcc. |
| runs all fail with rc≠0 | run the `run.command` by hand on one vector; fix the invocation, then re-run ASI. |
| a known-used function shows dead | your corpus doesn't cover that path — add a vector that does; check `list-vectors`. |

Run the bundled self-test any time to confirm ASI itself is healthy:

```bash
bash tests/selftest.sh   # -> ALL CHECKS PASSED
```
