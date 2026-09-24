// ABI fact dumper — runtime counterpart of abi_probe.cpp.
//
// Prints every sizeof/alignof/offsetof fact as a JSON object so a new
// backend's expected-<key>.json can be GENERATED from the real SDK headers
// instead of being hand-copied from an older version. Compiled with the
// same flags as the probe (-D__NT__ -D__EA64__); nothing is linked from
// the SDK (types are only measured, never used), so it runs anywhere.
//
//   clang++ -std=c++17 -D__NT__=1 -D__EA64__=1 -Wno-invalid-offsetof \
//     -I<sdk>/src/include backends/abi/abi_dump.cpp -o abi_dump && ./abi_dump

#include "pro.h"
#include "range.hpp"
#include "nalt.hpp"
#include "xref.hpp"
#include "ua.hpp"
#include "typeinf.hpp"
#include "hexrays.hpp"

#include <cstddef>
#include <cstdio>

namespace abi_dump {

#define P_SIZEOF(T) std::printf("sizeof %s %zu\n", #T, sizeof(T))
#define P_ALIGNOF(T) std::printf("alignof %s %zu\n", #T, alignof(T))
#define P_OFFSET(T, M) std::printf("offsetof %s.%s %zu\n", #T, #M, offsetof(T, M))

void dump() {
    P_SIZEOF(range_t);
    P_SIZEOF(op_t);
    P_SIZEOF(insn_t);
    P_SIZEOF(argloc_t);
    P_SIZEOF(vdloc_t);
    P_SIZEOF(tinfo_t);
    P_SIZEOF(lvar_locator_t);
    P_SIZEOF(lvar_t);
    P_SIZEOF(qstring);
    P_SIZEOF(citem_t);
    P_SIZEOF(cinsn_t);
    P_SIZEOF(cblock_t);
    P_SIZEOF(cexpr_t);
    P_SIZEOF(cswitch_t);
    P_SIZEOF(ctry_t);
    P_SIZEOF(cthrow_t);
    P_SIZEOF(cfunc_t);

    P_ALIGNOF(range_t);
    P_ALIGNOF(op_t);
    P_ALIGNOF(insn_t);
    P_ALIGNOF(argloc_t);
    P_ALIGNOF(tinfo_t);
    P_ALIGNOF(lvar_t);
    P_ALIGNOF(qstring);
    P_ALIGNOF(citem_t);
    P_ALIGNOF(cexpr_t);
    P_ALIGNOF(cfunc_t);

    P_OFFSET(op_t, n);
    P_OFFSET(op_t, type);
    P_OFFSET(op_t, reg);
    P_OFFSET(op_t, value);
    P_OFFSET(op_t, addr);
    P_OFFSET(op_t, specval);
    P_OFFSET(op_t, specflag1);
    P_OFFSET(op_t, specflag4);
    P_OFFSET(insn_t, ops);
    P_OFFSET(lvar_t, location);
    P_OFFSET(lvar_t, defea);
    P_OFFSET(lvar_t, name);
    P_OFFSET(lvar_t, tif);
    P_OFFSET(citem_t, ea);
    P_OFFSET(citem_t, op);
    P_OFFSET(cexpr_t, type);
    P_OFFSET(cexpr_t, exflags);
    P_OFFSET(cfunc_t, entry_ea);
    P_OFFSET(cfunc_t, mba);
    P_OFFSET(cfunc_t, body);
    P_OFFSET(cfunc_t, maturity);
}

} // namespace abi_dump

int main() {
    abi_dump::dump();
    return 0;
}
