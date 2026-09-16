// Deobfuscation fixture (#9): obfuscated patterns for the analysis-only
// pass engine. Unoptimized so all junk/branches survive.
#include <stdio.h>

// --- junk no-ops: mov reg,reg / add reg,0 survive /Od ---
static volatile int g_sink;

__declspec(noinline) int junk_calc(int x) {
    int y = x;
    y = y;               // mov reg,reg candidate
    y += 0;              // add reg,0 candidate
    g_sink = y;
    return y * 2 + 1;
}

// --- opaque/redundant branch: self-comparison + constant condition ---
__declspec(noinline) int opaque_check(int x) {
    int r = 0;
    if (x == x) {        // always true (self comparison)
        r += 1;
    }
    if (1) {             // constant condition
        r += 10;
    }
    if (0) {             // dead branch
        r += 100;
    }
    return r;
}

// --- control-flow-flattening shape: dense switch loop (dispatcher) ---
__declspec(noinline) int flattened(int x) {
    int state = 0, out = 0;
    for (int i = 0; i < 8; i++) {
        switch (state) {
            case 0: out += 1; state = 3; break;
            case 3: out += x; state = 1; break;
            case 1: out -= 2; state = (x > 0) ? 2 : 4; break;
            case 2: out *= 2; state = 4; break;
            case 4: out ^= 0x5A; state = 5; break;
            case 5: out += i; state = 0; break;
            default: state = 4; break;
        }
    }
    return out;
}

// --- indirect call via function pointer (call reg) ---
typedef int (*fn_t)(int);
static int add_one(int v) { return v + 1; }
static int add_two(int v) { return v + 2; }

__declspec(noinline) int indirect_call(int v, int which) {
    fn_t table[2] = { add_one, add_two };
    fn_t f = table[which & 1];
    return f(v);         // call reg / call [reg]
}

int main(void) {
    int r = 0;
    r += junk_calc(3);
    r += opaque_check(5);
    r += flattened(2);
    r += indirect_call(10, 0);
    printf("r=%d\n", r);
    return 0;
}
