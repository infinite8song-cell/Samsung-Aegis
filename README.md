# Gerrit Fuzzing Harness Generator

Gerrit diff 기반의 자동 퍼징 하네스 생성 도구. Gerrit 변경사항을 가져와 ARM Metis로 보안 분석 후, LLVM LibFuzzer 하네스와 코퍼스를 자동 생성하고 실행합니다.

## Architecture

```
Gerrit URL ──> Gerrit REST API ──> Diff 추출
                                      │
                                      ▼
                              ARM Metis 분석
                           (보안 취약점 탐지)
                                      │
                                      ▼
                            취약점 분석 결과
                          (SARIF / Heuristic)
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                  Harness 생성              Corpus 생성
                (LibFuzzer .cpp)        (Seed 입력 데이터)
                         │                         │
                         └────────────┬────────────┘
                                      ▼
                           clang++ -fsanitize=
                          fuzzer,address,undefined
                                      │
                                      ▼
                             LibFuzzer 실행
                                      │
                                      ▼
                           결과 리포트 생성
                        (Crash / Coverage 보고)
```

## Requirements

- Python >= 3.10
- clang/clang++ with LibFuzzer support (compiler-rt)
- ARM Metis (optional, falls back to heuristic analysis)

## Installation

```bash
# Install the Python package
pip install -e .

# Install clang + LibFuzzer (Ubuntu/Debian/Fedora/Arch)
chmod +x scripts/setup_libfuzzer.sh
sudo ./scripts/setup_libfuzzer.sh

# Optional: Install ARM Metis for AI-powered analysis
pip install metis-ai
```

## Usage

### Full Pipeline (fetch -> analyze -> generate -> fuzz)

```bash
gerrit-fuzzer run https://gerrit.example.com/c/project/+/12345
```

### Options

```bash
gerrit-fuzzer run <GERRIT_URL> \
    --output-dir ./fuzz_output \       # Output directory
    --metis-cmd /path/to/metis \       # Metis binary path
    --llm-provider openai \            # LLM provider for Metis
    --model gpt-4 \                    # LLM model
    --fuzz-time 600 \                  # Fuzzing duration (seconds)
    --jobs 4 \                         # Parallel fuzzing jobs
    --gerrit-user myuser \             # Gerrit authentication
    --gerrit-pass mypass \
    --no-verify-ssl \                  # Skip SSL verification
    -v                                 # Verbose logging
```

### Generate Only (no fuzzing)

```bash
gerrit-fuzzer run --no-fuzz https://gerrit.example.com/c/project/+/12345 -o ./output
```

### Analyze Only

```bash
gerrit-fuzzer analyze https://gerrit.example.com/c/project/+/12345 -o findings.json
```

### Generate Harnesses Only

```bash
gerrit-fuzzer generate https://gerrit.example.com/c/project/+/12345 -o ./harnesses
```

### Run Previously Generated Harnesses

```bash
gerrit-fuzzer fuzz ./output/harnesses --fuzz-time 600 --jobs 4
```

## Output Structure

```
output/
├── harnesses/
│   ├── fuzz_main_abc123.cpp         # Generated harness
│   ├── CMakeLists.txt               # CMake build file
│   └── Makefile                     # Make build file
├── corpus/
│   └── corpus_fuzz_main_abc123/     # Seed corpus
│       ├── seed_0000_...
│       └── seed_0001_...
├── build/
│   ├── fuzz_main_abc123             # Compiled binary
│   ├── fuzz_main_abc123.log         # Fuzzer log
│   └── artifacts_fuzz_main_abc123/  # Crash artifacts
├── metis_work/
│   ├── change.diff                  # Extracted diff
│   └── findings.sarif               # Metis output
└── report.txt                       # Summary report
```

## Supported Vulnerability Categories

| Category | Description | CWE |
|---|---|---|
| buffer-overflow | Buffer overflow via memcpy/strcpy/sprintf etc. | CWE-120 |
| integer-overflow | Integer overflow in arithmetic | CWE-190 |
| use-after-free | Use of freed memory | CWE-416 |
| double-free | Double free of memory | CWE-415 |
| null-dereference | NULL pointer dereference | CWE-476 |
| out-of-bounds | Array out-of-bounds access | CWE-125 |
| format-string | Format string vulnerability | CWE-134 |
| uninitialized-memory | Use of uninitialized memory | CWE-457 |

## How It Works

1. **Gerrit Diff Fetch**: Connects to Gerrit REST API, retrieves the latest patchset diff for the specified change number
2. **Metis Analysis**: Runs ARM Metis `review_patch` on the diff to identify security vulnerabilities using AI-driven semantic analysis. Falls back to regex-based heuristic pattern matching if Metis is not installed
3. **Harness Generation**: Groups findings by file, generates category-specific LibFuzzer harness code (C++) with Jinja2 templates
4. **Corpus Generation**: Creates seed inputs from diff content, vulnerability snippets, and category-specific boundary values
5. **Build & Fuzz**: Compiles harnesses with `clang++ -fsanitize=fuzzer,address,undefined` and runs LibFuzzer
6. **Reporting**: Collects crash artifacts and generates a summary report

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
