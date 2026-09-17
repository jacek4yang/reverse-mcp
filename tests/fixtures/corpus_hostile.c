// #57 hostile/complex static-analysis corpus: synthetic, inert PE fixture.
// NEVER executed by tests or agents - every sample here is a static byte
// input for IDA/idalib parsing only (see docs/CORPUS.md provenance notes).
//
// This fixture packs several hostile-analysis stressors into one inert
// binary, all compiled to ordinary code (no execution of any real payload):
//   - deep recursion + wide call graph (huge CFG)
//   - opaque predicates (analysis-hostile branches that MSVC cannot fold)
//   - API-hash style dispatch (hash computed over constant names)
//   - encrypted-string decoder (XOR over an embedded blob)
//   - vtable-like indirect call table
//   - flattened control flow via a computed-jump-style switch dispatcher
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// --- stressor 1: deep recursion (call depth 64, wide-ish graph) ---
static unsigned int deep_sum(unsigned int n) {
    if (n == 0) return 0;
    return n + deep_sum(n - 1);
}

// --- stressor 2: wide call graph: fan-out 8, fan-in 8 ---
static unsigned int leaf_a(unsigned int x) { return x + 1; }
static unsigned int leaf_b(unsigned int x) { return x * 2; }
static unsigned int leaf_c(unsigned int x) { return x ^ 3; }
static unsigned int leaf_d(unsigned int x) { return x + 7; }
static unsigned int leaf_e(unsigned int x) { return x - 1; }
static unsigned int leaf_f(unsigned int x) { return x | 8; }
static unsigned int leaf_g(unsigned int x) { return x & 0xF; }
static unsigned int leaf_h(unsigned int x) { return x << 1; }

static unsigned int wide_hub(unsigned int x, unsigned int which) {
    unsigned int r = x;
    r = leaf_a(r); r = leaf_b(r); r = leaf_c(r); r = leaf_d(r);
    r = leaf_e(r); r = leaf_f(r); r = leaf_g(r); r = leaf_h(r);
    if (which > 4) r = leaf_a(leaf_b(leaf_c(r)));
    return r;
}

// --- stressor 3: opaque predicates MSVC cannot fold at compile time ---
// (volatile defeats constant folding; the predicates are ALWAYS true, but
//  the analyzer must prove it dynamically - hostile to symbolic execution)
static volatile unsigned int g_opaque = 1;

static unsigned int opaque_chain(unsigned int x) {
    unsigned int r = x;
    if (g_opaque * g_opaque >= g_opaque) {           // always true (n>=1)
        r = r + 0x1337;
    } else {
        r = r + 0xDEAD;                              // dead in practice
    }
    if ((g_opaque | 1) == g_opaque + 1 - (g_opaque & 1) - 1 + (g_opaque & 1) + 1) {
        r = r ^ 0x5A5A;                              // reachable branch
    }
    if (g_opaque < 0) {                              // never (unsigned)
        r = 0xBADC0DE;                               // dead branch
    }
    return r;
}

// --- stressor 4: API-hash dispatch over constant names (ror13-add) ---
static unsigned int ror13(unsigned int h, const char *s) {
    while (*s) {
        h = (h >> 13) | (h << 19);
        h += (unsigned char)*s;
        s++;
    }
    return h;
}

static const char *const API_NAMES[] = {
    "kernel32.dll!VirtualAlloc",
    "kernel32.dll!VirtualProtect",
    "kernel32.dll!CreateFileA",
    "advapi32.dll!RegOpenKeyA",
    "ws2_32.dll!WSAStartup",
};

static int hash_dispatch(unsigned int want) {
    for (unsigned i = 0; i < 5; i++) {
        if (ror13(0x4C4C554E, API_NAMES[i]) == want) return (int)i;
    }
    return -1;
}

// --- stressor 5: encrypted-string blob + decoder (static XOR key stream) ---
static const unsigned char ENC_BLOB[32] = {
    0x2C,0x0D,0x36,0x2F,0x73,0x2F,0x2C,0x0D,0x36,0x2F,0x36,0x37,0x71,0x71,0x00,0x11,
    0x19,0x0E,0x2F,0x36,0x2F,0x0A,0x33,0x28,0x73,0x2F,0x0A,0x0A,0x31,0x2F,0x36,0x73
};

static int decode_blob(char *out, int outcap) {
    unsigned char key = 0x42;
    int n = 0;
    for (int i = 0; i < 32 && n < outcap - 1; i++) {
        unsigned char c = ENC_BLOB[i] ^ key;
        key = (unsigned char)(key * 31 + 7);         // rolling key: hostile to naive XOR scan
        if (c >= 32 && c < 127) { out[n++] = (char)c; }
    }
    out[n] = 0;
    return n;
}

// --- stressor 6: vtable-like indirect calls through a table ---
typedef unsigned int (*fnptr_t)(unsigned int);
static fnptr_t VTABLE[4] = { leaf_a, leaf_c, leaf_f, leaf_h };

static unsigned int vtable_dispatch(unsigned int x, unsigned int slot) {
    return VTABLE[slot & 3](x);                      // indirect call IDA must resolve
}

// --- stressor 7: flattened dispatcher (state machine control flow) ---
static unsigned int flattened(unsigned int seed) {
    unsigned int state = seed & 7, acc = 0;
    for (int guard = 0; guard < 64; guard++) {       // bounded, but CFG-hostile
        switch (state) {
            case 0: acc += 0x1000; state = 3; break;
            case 1: acc ^= 0x0F0F; state = 5; break;
            case 2: acc = acc * 3 + 1; state = 7; break;
            case 3: acc -= 7; state = 1; break;
            case 4: acc = ~acc; state = 2; break;
            case 5: acc += 0x77; state = (acc & 1) ? 6 : 2; break;
            case 6: acc = acc >> 1; state = 0; break;
            default: acc += seed; state = 4; break;
        }
        if (acc & 0x80000000) break;                 // escape hatch
    }
    return acc;
}

// --- stressor 8: heavy constants (crypto-marker noise for the scanner) ---
static const unsigned int FAKE_AES_ROUNDS[4] = {
    0x637C777B, 0xF26B6FC5, 0x30010167, 0x2BF26B6F
};

static unsigned int const_noise(unsigned int x) {
    return x ^ FAKE_AES_ROUNDS[x & 3] ^ deep_sum(4);
}

int main(void) {
    // Compute everything but never do anything dangerous: results only go
    // to a checksum printed to stdout. NO sample here is ever executed as
    // hostile code - the binary is the static-analysis INPUT.
    unsigned int r = deep_sum(64);
    r += wide_hub(r, 2);
    r += opaque_chain(r);
    r += (unsigned int)hash_dispatch(ror13(0x4C4C554E, "kernel32.dll!VirtualAlloc"));
    char dec[64];
    r += (unsigned int)decode_blob(dec, sizeof(dec));
    r += vtable_dispatch(r, 2);
    r += flattened(r);
    r += const_noise(r);
    printf("corpus checksum: %08x (%s)\n", r, dec);
    return 0;
}
