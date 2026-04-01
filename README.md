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

- Python >= 3.12
- clang/clang++ with LibFuzzer support (compiler-rt)
- ARM Metis + LLM API Key (선택 - 없으면 휴리스틱 분석으로 폴백)

## Installation

```bash
# 1. 프로젝트 설치
pip install -e .

# 2. clang + LibFuzzer 설치 (Ubuntu/Debian/Fedora/Arch)
chmod +x scripts/setup_libfuzzer.sh
sudo ./scripts/setup_libfuzzer.sh

# 3. ARM Metis 설치 (GitHub에서 클론 + Python 3.12 venv)
chmod +x scripts/setup_metis.sh
./scripts/setup_metis.sh
```

### ARM Metis 설치 상세

Metis는 PyPI에 없으며, GitHub 소스에서 직접 설치해야 합니다.
`scripts/setup_metis.sh` 스크립트가 자동으로 처리합니다:

1. Python 3.12+ 확인/설치 (deadsnakes PPA 사용)
2. `https://github.com/arm/metis.git` 클론 → `~/.local/share/metis`
3. 전용 venv 생성 후 `pip install -e .`
4. `~/.local/bin/metis` 심볼릭 링크 생성

수동 설치:

```bash
git clone https://github.com/arm/metis.git
cd metis
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
metis --version
```

### Metis 분석 전략 (우선순위)

| 순서 | 방법 | 조건 |
|---|---|---|
| 1 | **Python API** | `metis` 패키지가 import 가능 + `OPENAI_API_KEY` 설정 |
| 2 | **CLI subprocess** | `metis` 바이너리가 PATH에 존재 |
| 3 | **Heuristic fallback** | Metis 미설치 시 자동 - 10개 C/C++ 위험 패턴 정규식 |

Metis가 설치되지 않아도 프로젝트는 정상 동작합니다 (heuristic 모드).

## Environment Variables

### 환경변수 목록

| 변수명 | 설명 | 필수 여부 | 기본값 |
|---|---|---|---|
| `GERRIT_USERNAME` | Gerrit HTTP 인증 사용자명 | Gerrit 인증 시 필수 | _(없음)_ |
| `GERRIT_PASSWORD` | Gerrit HTTP 인증 비밀번호 | Gerrit 인증 시 필수 | _(없음)_ |
| `OPENAI_API_KEY` | vLLM / OpenAI-compatible API 키 | Metis 사용 시 필수 | _(없음)_ |
| `OPENAI_API_BASE` | vLLM / OpenAI-compatible 엔드포인트 URL | Metis 사용 시 필수 | _(없음)_ |
| `METIS_MODEL` | LLM 모델 이름 | 선택 | metis.yaml의 기본값 |

Metis는 **vLLM (OpenAI-compatible)** 프로바이더를 사용합니다.
`OPENAI_API_KEY`와 `OPENAI_API_BASE`가 모두 설정되어야 Metis AI 분석이 실행됩니다.
미설정 시 내장 휴리스틱 분석으로 자동 폴백합니다.

> **우선순위**: CLI 옵션 (`--gerrit-user`, `--gerrit-pass`) > 환경변수
>
> CLI 옵션을 지정하면 환경변수 값을 무시합니다. CLI 옵션이 없으면 환경변수를 자동으로 사용합니다.

### 설정 방법

#### 1. 셸에서 직접 설정 (현재 세션만 유효)

```bash
export GERRIT_USERNAME="myuser"
export GERRIT_PASSWORD="mypassword"
export OPENAI_API_KEY="sk-..."                        # vLLM API 키
export OPENAI_API_BASE="http://vllm-server:8000/v1"   # vLLM 엔드포인트 URL
export METIS_MODEL="my-model-name"                     # 사용할 LLM 모델 (선택)
```

#### 2. 셸 프로필에 영구 등록 (~/.bashrc 또는 ~/.zshrc)

```bash
# ~/.bashrc 또는 ~/.zshrc 끝에 추가
echo 'export GERRIT_USERNAME="myuser"' >> ~/.bashrc
echo 'export GERRIT_PASSWORD="mypassword"' >> ~/.bashrc
echo 'export OPENAI_API_KEY="sk-..."' >> ~/.bashrc
echo 'export OPENAI_API_BASE="http://vllm-server:8000/v1"' >> ~/.bashrc
echo 'export METIS_MODEL="my-model-name"' >> ~/.bashrc

# 변경사항 적용
source ~/.bashrc
```

#### 3. .env 파일 사용 (프로젝트별 설정)

프로젝트 루트에 `.env` 파일을 생성하고 실행 전에 로드합니다.

```bash
# .env 파일 생성
cat > .env << 'EOF'
GERRIT_USERNAME=myuser
GERRIT_PASSWORD=mypassword
OPENAI_API_KEY=sk-...
OPENAI_API_BASE=http://vllm-server:8000/v1
METIS_MODEL=my-model-name
EOF

# 실행 전 로드
source .env
gerrit-fuzzer run https://gerrit.example.com/c/project/+/12345
```

> `.env` 파일에는 민감한 정보가 포함되므로, `.gitignore`에 반드시 추가하세요.

#### 4. 인라인 실행 (일회성)

```bash
GERRIT_USERNAME=myuser GERRIT_PASSWORD=mypass \
    gerrit-fuzzer run https://gerrit.example.com/c/project/+/12345
```

### Gerrit 인증 설정 상세

Gerrit HTTP 비밀번호는 Gerrit 웹 UI에서 발급합니다:

1. Gerrit 웹 UI 접속 → **Settings** → **HTTP Credentials**
2. **Generate Password** 클릭
3. 생성된 사용자명과 비밀번호를 환경변수에 설정

```bash
# Gerrit에서 발급받은 값 설정
export GERRIT_USERNAME="your_gerrit_username"
export GERRIT_PASSWORD="your_generated_http_password"
```

- `GERRIT_USERNAME`만 설정하고 `GERRIT_PASSWORD`를 누락하면 경고 메시지가 출력되며, 인증 없이 접속을 시도합니다.
- 공개(anonymous) 접근이 가능한 Gerrit 서버라면 인증 환경변수를 설정하지 않아도 됩니다.

### 설정 확인

환경변수가 올바르게 설정되었는지 확인합니다:

```bash
echo "GERRIT_USERNAME:  ${GERRIT_USERNAME:-<not set>}"
echo "GERRIT_PASSWORD:  ${GERRIT_PASSWORD:+****}"
echo "OPENAI_API_KEY:   ${OPENAI_API_KEY:+****}"
echo "OPENAI_API_BASE:  ${OPENAI_API_BASE:-<not set>}"
echo "METIS_MODEL:      ${METIS_MODEL:-<not set>}"
which metis 2>/dev/null && metis --version || echo "Metis: not installed"
```

## Usage

### Full Pipeline (fetch -> analyze -> generate -> fuzz)

```bash
# 환경변수에 인증 정보가 설정되어 있으면 자동으로 사용
gerrit-fuzzer run https://gerrit.example.com/c/project/+/12345

# 또는 CLI 옵션으로 직접 지정 (환경변수보다 우선)
gerrit-fuzzer run https://gerrit.example.com/c/project/+/12345 \
    --gerrit-user myuser --gerrit-pass mypass
```

### Options

```bash
gerrit-fuzzer run <GERRIT_URL> \
    --output-dir ./fuzz_output \       # Output directory
    --llm-provider openai \            # LLM provider for Metis
    --model gpt-4 \                    # LLM model
    --fuzz-time 600 \                  # Fuzzing duration (seconds)
    --jobs 4 \                         # Parallel fuzzing jobs
    --gerrit-user myuser \             # Gerrit auth (default: $GERRIT_USERNAME)
    --gerrit-pass mypass \             # Gerrit auth (default: $GERRIT_PASSWORD)
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
