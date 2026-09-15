// ABI probe for the IDA 9.2 SDK — compile-time contract.
//
// This TU is COMPILED against the exact SDK headers this workspace vendors
// (`vendor/idalib-sys/sdk/src/include`, gitignored proprietary material)
// and static_asserts every sizeof/alignof/offsetof fact against the values
// recorded in `expected-9_2.json` (passed in as macros by
// scripts/run-abi-probe.ps1, which generates `expected_facts.inc` from the
// JSON). If any layout changes — different SDK, compiler, or platform
// flags — compilation fails with the offending fact in the error message.
//
// Nothing here is linked or run, so no proprietary SDK symbols (get_hexdsp,
// qfree, ...) are needed and the probe works with any C++ driver (clang++,
// zig c++, ...):
//   clang++ -std=c++17 -D__NT__=1 -D__EA64__=1 -c \
//     -Ivendor/idalib-sys/sdk/src/include -Ibackends/abi \
//     backends/abi/abi_probe.cpp
// On Linux/macOS replace __NT__ with __LINUX__ / __MACOS__ (keep __EA64__).
//
// The same JSON feeds the Rust layout tests in `crates/reverse-ida-sys`,
// so both sides are checked against one source of truth.

#include "expected_facts.inc"

#include "pro.h"        // platform macros, ea_t, qstring, idaman, svalvec_t
#include "range.hpp"    // range_t
#include "nalt.hpp"     // enables the casevec_t section of xref.hpp
#include "xref.hpp"     // casevec_t (needed by hexrays.hpp)
#include "ua.hpp"       // op_t, insn_t
#include "typeinf.hpp"  // argloc_t, tinfo_t, vdloc_t, lvar_locator_t, qstring
#include "hexrays.hpp"  // lvar_t, citem_t, cinsn_t, cexpr_t, cfunc_t, ...

#include <cstddef>

namespace abi_probe {

#define ABI_ASSERT_SIZEOF(T, WANT) \
    static_assert(sizeof(T) == (WANT), "sizeof(" #T ") == " #WANT)
#define ABI_ASSERT_ALIGNOF(T, WANT) \
    static_assert(alignof(T) == (WANT), "alignof(" #T ") == " #WANT)
#define ABI_ASSERT_OFFSET(T, M, WANT) \
    static_assert(offsetof(T, M) == (WANT), "offsetof(" #T "::" #M ") == " #WANT)

// --- sizeof ---------------------------------------------------------------
ABI_ASSERT_SIZEOF(range_t, FACT_RANGE_T_SIZEOF);
ABI_ASSERT_SIZEOF(op_t, FACT_OP_T_SIZEOF);
ABI_ASSERT_SIZEOF(insn_t, FACT_INSN_T_SIZEOF);
ABI_ASSERT_SIZEOF(argloc_t, FACT_ARGLOC_T_SIZEOF);
ABI_ASSERT_SIZEOF(vdloc_t, FACT_VDLOC_T_SIZEOF);
ABI_ASSERT_SIZEOF(tinfo_t, FACT_TINFO_T_SIZEOF);
ABI_ASSERT_SIZEOF(lvar_locator_t, FACT_LVAR_LOCATOR_T_SIZEOF);
ABI_ASSERT_SIZEOF(lvar_t, FACT_LVAR_T_SIZEOF);
ABI_ASSERT_SIZEOF(qstring, FACT_QSTRING_SIZEOF);
ABI_ASSERT_SIZEOF(citem_t, FACT_CITEM_T_SIZEOF);
ABI_ASSERT_SIZEOF(cinsn_t, FACT_CINSN_T_SIZEOF);
ABI_ASSERT_SIZEOF(cblock_t, FACT_CBLOCK_T_SIZEOF);
ABI_ASSERT_SIZEOF(cexpr_t, FACT_CEXPR_T_SIZEOF);
ABI_ASSERT_SIZEOF(cswitch_t, FACT_CSWITCH_T_SIZEOF);
ABI_ASSERT_SIZEOF(ctry_t, FACT_CTRY_T_SIZEOF);
ABI_ASSERT_SIZEOF(cthrow_t, FACT_CTHROW_T_SIZEOF);
ABI_ASSERT_SIZEOF(cfunc_t, FACT_CFUNC_T_SIZEOF);

// --- alignof --------------------------------------------------------------
ABI_ASSERT_ALIGNOF(range_t, FACT_RANGE_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(op_t, FACT_OP_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(insn_t, FACT_INSN_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(argloc_t, FACT_ARGLOC_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(tinfo_t, FACT_TINFO_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(lvar_t, FACT_LVAR_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(qstring, FACT_QSTRING_ALIGNOF);
ABI_ASSERT_ALIGNOF(citem_t, FACT_CITEM_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(cexpr_t, FACT_CEXPR_T_ALIGNOF);
ABI_ASSERT_ALIGNOF(cfunc_t, FACT_CFUNC_T_ALIGNOF);

// --- offsetof -------------------------------------------------------------
ABI_ASSERT_OFFSET(op_t, n, FACT_OP_T_N_OFFSET);
ABI_ASSERT_OFFSET(op_t, type, FACT_OP_T_TYPE_OFFSET);
ABI_ASSERT_OFFSET(op_t, reg, FACT_OP_T_REG_OFFSET);
ABI_ASSERT_OFFSET(op_t, value, FACT_OP_T_VALUE_OFFSET);
ABI_ASSERT_OFFSET(op_t, addr, FACT_OP_T_ADDR_OFFSET);
ABI_ASSERT_OFFSET(op_t, specval, FACT_OP_T_SPECVAL_OFFSET);
ABI_ASSERT_OFFSET(op_t, specflag1, FACT_OP_T_SPECFLAG1_OFFSET);
ABI_ASSERT_OFFSET(op_t, specflag4, FACT_OP_T_SPECFLAG4_OFFSET);
ABI_ASSERT_OFFSET(insn_t, ops, FACT_INSN_T_OPS_OFFSET);
ABI_ASSERT_OFFSET(lvar_t, location, FACT_LVAR_T_LOCATION_OFFSET);
ABI_ASSERT_OFFSET(lvar_t, defea, FACT_LVAR_T_DEFEA_OFFSET);
ABI_ASSERT_OFFSET(lvar_t, name, FACT_LVAR_T_NAME_OFFSET);
ABI_ASSERT_OFFSET(lvar_t, tif, FACT_LVAR_T_TIF_OFFSET);
ABI_ASSERT_OFFSET(citem_t, ea, FACT_CITEM_T_EA_OFFSET);
ABI_ASSERT_OFFSET(citem_t, op, FACT_CITEM_T_OP_OFFSET);
ABI_ASSERT_OFFSET(cexpr_t, type, FACT_CEXPR_T_TYPE_OFFSET);
ABI_ASSERT_OFFSET(cexpr_t, exflags, FACT_CEXPR_T_EXFLAGS_OFFSET);
ABI_ASSERT_OFFSET(cfunc_t, entry_ea, FACT_CFUNC_T_ENTRY_EA_OFFSET);
ABI_ASSERT_OFFSET(cfunc_t, mba, FACT_CFUNC_T_MBA_OFFSET);
ABI_ASSERT_OFFSET(cfunc_t, body, FACT_CFUNC_T_BODY_OFFSET);
ABI_ASSERT_OFFSET(cfunc_t, maturity, FACT_CFUNC_T_MATURITY_OFFSET);

}  // namespace abi_probe

// Keep the TU non-empty without generating code.
namespace abi_probe {
using abi_probe_tu_sentinel = int;
}  // namespace abi_probe
