"""Excel 파일을 마크다운 표로 변환하는 스크립트.

사용 예시:
    python excel_to_markdown.py input.xlsx
    python excel_to_markdown.py input.xlsx -o output.md
    python excel_to_markdown.py input.xlsx --sheet Sheet1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd


def _escape_cell(value: object) -> str:
    """마크다운 표 셀 안에서 안전하게 표시되도록 값을 문자열화한다."""
    if pd.isna(value):
        return ""
    text = str(value)
    # 표 구분자(|)와 줄바꿈은 셀을 깨뜨리므로 치환한다.
    text = text.replace("|", "\\|")
    text = text.replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>")
    return text


def dataframe_to_markdown(df: pd.DataFrame) -> str:
    """DataFrame을 GitHub Flavored Markdown 표 문자열로 변환한다."""
    if df.empty:
        return "_(빈 시트)_\n"

    headers = [_escape_cell(c) for c in df.columns]
    header_line = "| " + " | ".join(headers) + " |"
    separator_line = "| " + " | ".join(["---"] * len(headers)) + " |"

    body_lines = []
    for _, row in df.iterrows():
        cells = [_escape_cell(v) for v in row.tolist()]
        body_lines.append("| " + " | ".join(cells) + " |")

    return "\n".join([header_line, separator_line, *body_lines]) + "\n"


def excel_to_markdown(excel_path: Path, sheet: str | None = None) -> str:
    """Excel 파일을 읽어 모든 시트(또는 지정한 시트)를 마크다운으로 변환한다."""
    sheets: dict[str, pd.DataFrame] = pd.read_excel(
        excel_path,
        sheet_name=sheet if sheet is not None else None,
    )
    # sheet_name=None 이면 dict, 단일 시트 지정이면 DataFrame이 반환된다.
    if isinstance(sheets, pd.DataFrame):
        sheets = {sheet or "Sheet1": sheets}

    parts: list[str] = [f"# {excel_path.name}\n"]
    for name, df in sheets.items():
        parts.append(f"## 시트: {name}\n")
        parts.append(dataframe_to_markdown(df))
        parts.append("")
    return "\n".join(parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Excel 파일을 마크다운 표로 변환합니다."
    )
    parser.add_argument("excel", type=Path, help="입력 Excel 파일 경로 (.xlsx/.xls)")
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="출력 마크다운 파일 경로 (기본: 입력파일명.md)",
    )
    parser.add_argument(
        "--sheet", default=None,
        help="변환할 시트 이름. 생략 시 모든 시트를 변환합니다.",
    )
    args = parser.parse_args(argv)

    if not args.excel.is_file():
        print(f"에러: 입력 파일을 찾을 수 없습니다 - {args.excel}", file=sys.stderr)
        return 1

    output_path = args.output or args.excel.with_suffix(".md")
    markdown = excel_to_markdown(args.excel, args.sheet)
    output_path.write_text(markdown, encoding="utf-8")
    print(f"변환 완료: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
