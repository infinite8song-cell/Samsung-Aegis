"""A tiny library with a mix of used and unused functions.

`add` and `sub` are exercised by the test vectors via solve.py.
`unused_multiply`, `unused_power` and `Helper.unused_method` are never reached
by any vector -> ASI should flag them as dead.
"""


def add(a, b):
    return a + b


def sub(a, b):
    return a - b


def unused_multiply(a, b):        # dead: no vector path calls this
    return a * b


def unused_power(a, b):           # dead: no vector path calls this
    result = 1
    for _ in range(b):
        result = unused_multiply(result, a)
    return result


class Helper:
    def used_method(self, x):
        return add(x, 1)

    def unused_method(self, x):    # dead: never called
        return sub(x, 1)
