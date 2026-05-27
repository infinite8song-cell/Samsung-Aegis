"""DOCX(워드) 파일을 HWP(한글) 파일로 변환하는 스크립트.

HWP는 한글과컴퓨터의 독점 바이너리 포맷이라 순수 파이썬만으로는 손실 없이
.docx를 .hwp 로 직접 기록하기 어렵다. 본 스크립트는 시스템에 설치된 외부 변환
엔진을 백엔드로 사용한다. 다음 순서대로 시도한다.

    1. pyhwpx  : Windows + 한컴오피스(아래아한글)가 설치된 환경에서 COM 자동화로
                 docx를 열고 hwp로 저장한다. 변환 품질이 가장 좋다.
    2. soffice : LibreOffice headless 모드. 빌드에 따라 hwp export 필터가 없을
                 수도 있고, 그 경우 마지막 단계에서 실패한다.

사용법:
    python docx_to_hwp.py input.docx                  # input.hwp 로 저장
    python docx_to_hwp.py input.docx -o out.hwp       # 출력 경로 지정
    python docx_to_hwp.py input.docx --backend pyhwpx # 백엔드 강제 지정

의존성 설치 예시:
    pip install pyhwpx        # Windows + 한컴오피스 필요
    # Linux: apt install libreoffice  (hwp 필터 포함 빌드여야 함)
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


class ConversionError(RuntimeError):
    """변환 실패를 나타내는 예외."""


def convert_with_pyhwpx(docx: Path, hwp: Path) -> None:
    """한컴오피스 COM 자동화를 통해 변환한다. (Windows 전용)"""
    try:
        from pyhwpx import Hwp  # type: ignore
    except ImportError as exc:
        raise ConversionError("pyhwpx가 설치되어 있지 않습니다.") from exc

    app = Hwp(visible=False)
    try:
        # pyhwpx 는 한컴 변환 필터를 통해 docx 를 열 수 있다.
        if not app.open(str(docx.resolve())):
            raise ConversionError(f"한컴오피스가 docx를 열지 못했습니다: {docx}")
        if not app.save_as(str(hwp.resolve()), format="HWP"):
            raise ConversionError(f"HWP로 저장하지 못했습니다: {hwp}")
    finally:
        try:
            app.quit()
        except Exception:
            pass


def convert_with_soffice(docx: Path, hwp: Path) -> None:
    """LibreOffice headless 변환. hwp export 필터가 있는 빌드여야 한다."""
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if soffice is None:
        raise ConversionError("soffice/libreoffice 실행 파일을 찾을 수 없습니다.")

    outdir = hwp.parent.resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [soffice, "--headless", "--convert-to", "hwp",
         "--outdir", str(outdir), str(docx.resolve())],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise ConversionError(
            f"soffice 변환 실패 (exit={result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    # soffice는 입력파일명.hwp 로 저장하므로 사용자가 지정한 경로로 옮긴다.
    produced = outdir / (docx.stem + ".hwp")
    if not produced.exists():
        raise ConversionError(
            "soffice가 .hwp 파일을 만들지 못했습니다. "
            "현재 LibreOffice 빌드에 hwp export 필터가 없을 수 있습니다."
        )
    if produced.resolve() != hwp.resolve():
        produced.replace(hwp)


BACKENDS = {
    "pyhwpx": convert_with_pyhwpx,
    "soffice": convert_with_soffice,
}


def convert(docx: Path, hwp: Path, backend: str | None = None) -> str:
    """선택된(또는 자동 탐색된) 백엔드로 변환을 수행하고, 사용한 백엔드명을 반환한다."""
    order = [backend] if backend else ["pyhwpx", "soffice"]
    errors: list[str] = []
    for name in order:
        fn = BACKENDS.get(name)
        if fn is None:
            errors.append(f"{name}: 알 수 없는 백엔드")
            continue
        try:
            fn(docx, hwp)
            return name
        except ConversionError as e:
            errors.append(f"{name}: {e}")
    raise ConversionError(
        "모든 변환 백엔드가 실패했습니다.\n  - " + "\n  - ".join(errors)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="DOCX(워드) 파일을 HWP(한글) 파일로 변환합니다."
    )
    parser.add_argument("docx", type=Path, help="입력 .docx 파일 경로")
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="출력 .hwp 경로 (기본: 입력파일명.hwp)",
    )
    parser.add_argument(
        "--backend", choices=list(BACKENDS), default=None,
        help="변환 백엔드를 강제로 지정합니다 (기본: 자동 탐색).",
    )
    args = parser.parse_args(argv)

    if not args.docx.is_file():
        print(f"에러: 입력 파일을 찾을 수 없습니다 - {args.docx}", file=sys.stderr)
        return 1
    if args.docx.suffix.lower() != ".docx":
        print(f"경고: 입력 확장자가 .docx 가 아닙니다: {args.docx.suffix}",
              file=sys.stderr)

    output = args.output or args.docx.with_suffix(".hwp")

    try:
        used = convert(args.docx, output, args.backend)
    except ConversionError as e:
        print(f"변환 실패: {e}", file=sys.stderr)
        return 2

    print(f"변환 완료 ({used}): {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
