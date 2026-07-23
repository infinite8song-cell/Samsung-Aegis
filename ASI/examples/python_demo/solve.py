#!/usr/bin/env python3
"""Target program. Reads one test vector (a file containing "a b OP") and
prints the result. Exercises mathlib.add / mathlib.sub / Helper.used_method.

Usage (as ASI drives it):  solve.py <vector-file>
"""

import sys

import mathlib


def main():
    with open(sys.argv[1], "r") as f:
        a_str, b_str, op = f.read().split()
    a, b = int(a_str), int(b_str)

    if op == "add":
        print(mathlib.add(a, b))
    elif op == "sub":
        print(mathlib.sub(a, b))
    elif op == "inc":
        print(mathlib.Helper().used_method(a))
    else:
        raise SystemExit("unknown op: %s" % op)


if __name__ == "__main__":
    main()
