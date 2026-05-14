#!/usr/bin/env python3
"""Read a 1-D expect file of 0/1 values, reshape to 2-D, and count 1s in the
left/right border columns of each row.
"""
import argparse
import sys

WIDTH = 8448
HEIGHT = 160
BOARDL = 16
BOARDR = 16


def load_bits(path):
    """Parse a file containing only 0/1 values in any common layout."""
    with open(path, "r") as f:
        text = f.read()

    # Works for: one value per line, whitespace/comma separated, or one
    # continuous string of digits.
    tokens = text.split()
    if len(tokens) == 1 and len(tokens[0]) > 1:
        tokens = list(tokens[0])
    elif any("," in t for t in tokens):
        tokens = [t for tok in tokens for t in tok.split(",") if t]

    bits = []
    for t in tokens:
        if t in ("0", "1"):
            bits.append(int(t))
        else:
            raise ValueError(f"unexpected token in expect file: {t!r}")
    return bits


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("expect_file", help="path to the 1-D 0/1 expect file")
    ap.add_argument("--width", type=int, default=WIDTH)
    ap.add_argument("--height", type=int, default=HEIGHT)
    ap.add_argument("--boardl", type=int, default=BOARDL,
                    help="number of left border columns to check")
    ap.add_argument("--boardr", type=int, default=BOARDR,
                    help="number of right border columns to check")
    ap.add_argument("--per-row", action="store_true",
                    help="also print the per-row counts")
    args = ap.parse_args()

    bits = load_bits(args.expect_file)
    expected = args.width * args.height
    if len(bits) != expected:
        print(f"ERROR: got {len(bits)} values, expected "
              f"{expected} ({args.width} x {args.height})", file=sys.stderr)
        sys.exit(1)

    rows = [bits[r * args.width:(r + 1) * args.width] for r in range(args.height)]

    left_total = 0
    right_total = 0
    for idx, row in enumerate(rows):
        left = sum(row[:args.boardl])
        right = sum(row[args.width - args.boardr:])
        left_total += left
        right_total += right
        if args.per_row:
            print(f"row {idx:4d}: left={left:3d} right={right:3d}")

    print(f"width={args.width} height={args.height} "
          f"boardl={args.boardl} boardr={args.boardr}")
    print(f"left  {args.boardl} cols: {left_total} ones")
    print(f"right {args.boardr} cols: {right_total} ones")
    print(f"total border ones: {left_total + right_total}")


if __name__ == "__main__":
    main()
