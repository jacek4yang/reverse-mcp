// Deep-analysis fixture (#10): a 3-level call chain where callee prototype
// recovery improves caller pseudocode, plus an indirect (function-pointer)
// call site for heuristic dataflow, and a mutual-recursion pair to prove
// cycle safety.
#include <stdio.h>

// Level 3 (leaf): computes a byte transform. If IDA recovers
// transform(x, key) the level-2 caller's prototype improves.
int transform(int x, unsigned char key) {
    return (x ^ key) & 0xFF;
}

// Level 2: applies the transform to a buffer.
int apply_stream(unsigned char *buf, int len, unsigned char key) {
    int sum = 0;
    for (int i = 0; i < len; i++) {
        buf[i] = (unsigned char)transform(buf[i], key);
        sum += buf[i];
    }
    return sum;
}

// Level 2b: mutual recursion pair (cycle) with level2a below.
int level2b(int n);

int level2a(int n) {
    if (n <= 0) return 0;
    return 1 + level2b(n - 1);
}

int level2b(int n) {
    if (n <= 0) return 0;
    return 2 + level2a(n - 1);
}

// Level 1: orchestrates both streams and an indirect call.
int process(unsigned char *buf, int len, unsigned char key, int (*op)(unsigned char *, int, unsigned char)) {
    int a = apply_stream(buf, len, key);
    // Indirect call: op may be apply_stream (heuristic dataflow evidence).
    int b = op(buf, len, key);
    int c = level2a(4);
    return a + b + c;
}

// Entry (level 0).
int main(void) {
    unsigned char data[8];
    for (int i = 0; i < 8; i++) data[i] = (unsigned char)i;
    int r = process(data, 8, 0x5A, apply_stream);
    printf("process=%d\n", r);
    return 0;
}
