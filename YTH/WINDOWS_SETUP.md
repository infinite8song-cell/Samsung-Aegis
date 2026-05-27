# Windows에서 DOCX → HWP 변환 환경 구축 가이드

Windows에서 `docx_to_hwp.py`를 `pyhwpx` 백엔드로 돌리기 위한 처음부터 끝까지
가이드다. 파이썬이 처음 설치되는 PC를 가정한다.

> **사전 준비**: 한글과컴퓨터 **한컴오피스(아래아한글)** 이 설치되어 있어야 한다.
> `pyhwpx`는 설치된 한컴 한글 본체를 COM 자동화로 호출하므로, 한컴 한글이 없으면
> 동작하지 않는다. (한컴 뷰어 무료판으로는 안 된다 — 정식 한컴오피스가 필요하다.)

---

## 1. Python 설치

### 1-1. 설치 파일 다운로드

1. 브라우저에서 <https://www.python.org/downloads/windows/> 접속
2. **"Latest Python 3 Release"** 의 *Windows installer (64-bit)* 를 내려받는다.
   (현 시점 기준 3.12.x 또는 3.13.x 권장)

### 1-2. 설치 실행

1. 받은 `python-3.x.x-amd64.exe` 를 더블클릭한다.
2. 설치 마법사 첫 화면에서 **하단 체크박스 두 개를 반드시 켠다.**
   - [x] **Use admin privileges when installing py.exe**
   - [x] **Add python.exe to PATH**   ← 이게 꺼져 있으면 `cmd`에서 `python`이 안 잡힌다.
3. **Install Now** 클릭 → 설치 완료까지 대기.
4. 설치 마지막 화면의 **Disable path length limit** 버튼이 보이면 한 번 눌러둔다.
   (윈도우 260자 경로 제한 해제 — 한글 경로 트러블 예방용)

### 1-3. 설치 확인

`Win + R` → `cmd` 입력 → Enter 로 명령 프롬프트를 연 뒤:

```bat
python --version
pip --version
```

각각 `Python 3.x.x`, `pip 24.x ...` 같은 줄이 보이면 성공이다.
`'python'은(는) 내부 또는 외부 명령... 이 아닙니다` 라고 나오면 **PATH 추가**를
빠뜨린 것이다 — 제어판에서 Python을 제거 후 1-2 의 체크박스를 켜고 다시 설치한다.

---

## 2. 작업 폴더 준비

명령 프롬프트(`cmd`)에서:

```bat
cd %USERPROFILE%\Documents
mkdir docx2hwp
cd docx2hwp
```

이제 `C:\Users\<사용자명>\Documents\docx2hwp` 가 작업 폴더가 된다.

---

## 3. 가상환경(venv) 만들기 — 권장

전역 파이썬에 라이브러리를 막 깔지 말고 프로젝트별 가상환경에 격리한다.

```bat
python -m venv .venv
.venv\Scripts\activate
```

활성화되면 프롬프트 앞에 `(.venv)` 가 붙는다. 이 상태에서 설치하는 모든 패키지는
`.venv` 폴더 안에만 들어간다.

> **PowerShell을 쓴다면**: `python -m venv .venv` 다음에
> `.\.venv\Scripts\Activate.ps1` 를 친다. "스크립트 실행 정책" 에러가 나면
> 관리자 PowerShell에서 한 번만
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` 를 실행하면 된다.

---

## 4. pyhwpx 및 의존 패키지 설치

```bat
python -m pip install --upgrade pip
pip install pyhwpx pywin32
```

`pywin32`는 COM 자동화에 필요한 윈도우 바인딩이다. `pyhwpx` 가 의존성으로 함께
끌어오는 경우가 많지만, 명시적으로 한 번 더 깔아두면 안전하다.

설치 확인:

```bat
python -c "import pyhwpx; print(pyhwpx.__version__)"
```

버전 번호가 보이면 OK다.

> **참고 — 한컴오피스 자동화 한 번 활성화**: pyhwpx는 내부적으로 한컴의 보안 경고
> 다이얼로그를 만나면 멈춘다. 한 번은 직접 한글 본체를 실행한 뒤
> *도구 → 환경 설정 → 보안 → 매크로 보안* 에서 보안 수준을 *낮음/중간* 으로
> 바꿔두면 스크립트가 자동화 호출을 막힘 없이 수행한다.

---

## 5. 변환 스크립트 가져오기

이 저장소를 그대로 받을 거라면 Git 설치 후:

```bat
git clone https://github.com/infinite8song-cell/Samsung-Aegis.git
cd Samsung-Aegis\YTH
```

또는 GitHub 웹페이지에서 `YTH/docx_to_hwp.py` 만 우클릭 → *다른 이름으로 저장*
으로 받아 작업 폴더에 그대로 둬도 된다.

---

## 6. 변환 실행

작업 폴더에 변환할 `샘플.docx` 를 둔 상태에서:

```bat
python docx_to_hwp.py 샘플.docx
```

성공하면 다음 줄이 찍히고, 같은 폴더에 `샘플.hwp` 가 생성된다.

```
변환 완료 (pyhwpx): 샘플.hwp
```

출력 경로를 지정하려면:

```bat
python docx_to_hwp.py 샘플.docx -o C:\Users\me\Desktop\result.hwp
```

여러 파일을 한 번에 돌리려면 `for` 루프:

```bat
for %f in (*.docx) do python docx_to_hwp.py "%f"
```

---

## 7. 자주 만나는 오류와 해결법

| 증상 | 원인 / 해결 |
| --- | --- |
| `'python'은(는) ... 명령이 아닙니다` | 1-2 단계의 **Add python.exe to PATH** 체크 누락. Python 재설치. |
| `ModuleNotFoundError: No module named 'pyhwpx'` | 가상환경을 활성화하지 않았거나 `pip install pyhwpx` 누락. `.venv\Scripts\activate` 후 재설치. |
| `pywintypes.com_error: ... 클래스가 등록되지 않았습니다` | 한컴오피스(한글)가 설치되지 않았거나, 32/64bit 비트 수가 파이썬과 어긋남. 한컴오피스를 정상 설치하고, 가능하면 둘 다 64bit로 맞춘다. |
| 변환 도중 한글 본체가 떠서 다이얼로그 대기 | 매크로 보안 경고. 4단계 끝 *참고* 박스대로 보안 수준을 낮춘다. |
| 한글이 자동으로 닫히지 않음 | 다른 한글 창이 이미 열려 있는 경우. 한글을 모두 종료한 뒤 다시 실행. |
| `소스 파일을 열 수 없습니다` | docx 경로에 한글/공백/특수문자 문제. 경로 전체를 큰따옴표로 감싸기: `python docx_to_hwp.py "내 문서\샘플 (1).docx"` |

---

## 8. 한 줄 정리

```bat
:: 처음 한 번만
python -m venv .venv && .venv\Scripts\activate && pip install pyhwpx pywin32

:: 매번
python docx_to_hwp.py 입력.docx
```

여기까지 따라왔다면 Windows + 한컴오피스 + pyhwpx 조합으로 docx → hwp 변환이
스크립트 한 줄로 끝난다.
