/* Tiny C program with a mix of used and dead functions.
 *
 * A vector is a text file containing "a b op". main() dispatches to add/sub;
 * mul(), dead_mod() and dead_negate() are never reached by any vector, so ASI's
 * gcov backend should report them as dead code.
 */
#include <stdio.h>
#include <stdlib.h>

static int add(int a, int b) { return a + b; }
static int sub(int a, int b) { return a - b; }

/* dead: no vector uses "mul" */
static int mul(int a, int b) { return a * b; }

/* dead: never referenced anywhere */
static int dead_mod(int a, int b) { return b ? a % b : 0; }

/* dead: never referenced anywhere */
static int dead_negate(int a) { return -a; }

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: calc <vector>\n"); return 1; }

    FILE *f = fopen(argv[1], "r");
    if (!f) { perror("fopen"); return 2; }

    int a = 0, b = 0;
    char op[16] = {0};
    if (fscanf(f, "%d %d %15s", &a, &b, op) != 3) { fclose(f); return 3; }
    fclose(f);

    if      (op[0] == 'a') printf("%d\n", add(a, b));
    else if (op[0] == 's') printf("%d\n", sub(a, b));
    else { fprintf(stderr, "unknown op: %s\n", op); return 4; }

    return 0;
}
