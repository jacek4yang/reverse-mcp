// CTF-grade test fixture #1 (C): multi-layer key derivation with obfuscation.
//
// Analysis challenges embedded in this binary:
//   - control-flow flattening on the key schedule function
//   - opaque predicates that always resolve one way
//   - a string built on the stack (no plain .rdata artifact)
//   - XOR + rotate key derivation spread across helper functions
//   - an anti-debug check (IsDebuggerPresent) guarding the real path
//   - final flag check: sha256-style folded hash comparison
//
// The flag is derived at runtime: flag{...} never appears statically.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

/* Opaque predicate: always returns 1 for x in [0, 2^32). */
static u32 opaque_true(u32 x) {
    /* (x*x + x) is always even */
    return ((x * x + x) % 2u) == 0u;
}

/* XOR-decays the input with a rolling key. */
static u32 roll_mix(u32 v, u32 k) {
    v ^= k;
    v = (v << 7) | (v >> 25);
    v += 0x9E3779B9u;
    return v;
}

/* Control-flow-flattened key schedule: state machine with a dispatcher. */
static void key_schedule(const u8 *seed, size_t seed_len, u32 out[4]) {
    u32 state[4] = {0x243F6A88u, 0x85A308D3u, 0x13198A2Eu, 0x03707344u};
    int pc = 0;
    size_t i = 0;
    while (pc != 7) {
        switch (pc) {
        case 0:
            if (opaque_true(i)) pc = 1; else pc = 7;
            break;
        case 1:
            state[i % 4] ^= roll_mix(seed[i], (u32)(i * 0x85EBCA6Bu));
            i++;
            pc = (i < seed_len) ? 0 : 2;
            break;
        case 2:
            /* diffusion rounds */
            pc = 3;
            break;
        case 3:
            state[0] ^= state[3]; state[1] += state[2];
            pc = 4;
            break;
        case 4:
            state[2] = roll_mix(state[2], state[0]);
            state[3] = roll_mix(state[3], state[1]);
            pc = 5;
            break;
        case 5:
            state[1] ^= state[0]; state[3] += state[1];
            pc = opaque_true(state[0]) ? 6 : 2;
            break;
        case 6:
            pc = 7;
            break;
        default:
            pc = 7;
            break;
        }
    }
    memcpy(out, state, sizeof(state));
}

/* Stack-built target string: "flag{r3v3rs3_mcp_k3y}" obfuscated at rest. */
static void build_target(u8 buf[24]) {
    static const u8 enc[24] = {
        0x59,0x58,0x5f,0x5a,0x74,0x1d,0x52,0x18,0x1d,0x18,0x52,0x18,
        0x5e,0x5f,0x18,0x5e,0x12,0x18,0x5e,0x1c,0x1d,0x10,0x74,0x00
    };
    u8 k = 0x3A;
    for (int i = 0; i < 24; i++) {
        buf[i] = enc[i] ^ k;
        k = (u8)(k * 3 + 7);
    }
    buf[23] = 0;
}

/* Folded 64-bit hash (two rounds of xorshift-multiply). */
static u64 fold_hash(const u8 *data, size_t len) {
    u64 h = 0xCBF29CE484222325ull;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 0x100000001B3ull;
        h ^= h >> 29;
        h *= 0xBF58476D1CE4E5B9ull;
    }
    return h;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <license-key>\n", argv[0]);
        return 1;
    }

    /* Anti-debug: silently degrade (do not reveal the branch). */
    if (IsDebuggerPresent()) {
        printf("license invalid\n");
        return 2;
    }

    const char *key = argv[1];
    u32 ks[4];
    key_schedule((const u8 *)key, strlen(key), ks);

    u8 target[24];
    build_target(target);

    /* Serialize the derived key and compare folded hashes. */
    u8 derived[16];
    memcpy(derived, ks, sizeof(derived));
    u64 hd = fold_hash(derived, sizeof(derived));
    u64 ht = fold_hash(target, sizeof(target));

    if (hd == ht) {
        printf("license ok: %s\n", target);
        return 0;
    }
    printf("license invalid\n");
    return 3;
}
