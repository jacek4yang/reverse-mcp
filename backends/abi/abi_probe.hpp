// ABI probe for the IDA 9.2 SDK.
//
// Layout facts are extracted at COMPILE time: this header is included by
// `abi_probe.cpp`, which captures sizeof/alignof/offsetof into compile-time
// constants and prints them. No SDK inline functions are instantiated and
// no SDK library is linked, so the probe stays free of proprietary runtime
// symbols (get_hexdsp/qfree/... would otherwise be undefined at link time
// because clang emits used-implicit-instantiations in the same TU).
//
// Compiled against the exact SDK headers this workspace vendors
// (`vendor/idalib-sys/sdk/src/include`, gitignored proprietary material).
// Build (see scripts/run-abi-probe.ps1):
//   clang++ -std=c++17 -D__NT__=1 -D__EA64__=1 -c \
//     -Ivendor/idalib-sys/sdk/src/include backends/abi/abi_probe.cpp
//   clang++ abi_probe.o -o abi_probe
// On Linux/macOS replace __NT__ with __LINUX__ / __MACOS__ (keep __EA64__).
//
// The output is compared by scripts/run-abi-probe.ps1 against
// backends/abi/expected-9_2.json, and the same JSON is consumed by the
// Rust layout tests in `crates/reverse-ida-sys`, so both sides are checked
// against one source of truth.

#pragma once

#include "pro.h"        // platform macros, ea_t, qstring, idaman, svalvec_t
#include "range.hpp"    // range_t
#include "nalt.hpp"     // enables the casevec_t section of xref.hpp
#include "xref.hpp"     // casevec_t (needed by hexrays.hpp)
#include "ua.hpp"       // op_t, insn_t
#include "typeinf.hpp"  // argloc_t, tinfo_t, vdloc_t, lvar_locator_t, qstring
#include "hexrays.hpp"  // lvar_t, citem_t, cinsn_t, cexpr_t, cfunc_t, ...

#include <cstddef>
#include <cstdint>

namespace abi_probe {

// sizeof facts, captured as compile-time constants.
struct Sizes {
    static constexpr size_t range_t_ = sizeof(::range_t);
    static constexpr size_t op_t_ = sizeof(::op_t);
    static constexpr size_t insn_t_ = sizeof(::insn_t);
    static constexpr size_t argloc_t_ = sizeof(::argloc_t);
    static constexpr size_t vdloc_t_ = sizeof(::vdloc_t);
    static constexpr size_t tinfo_t_ = sizeof(::tinfo_t);
    static constexpr size_t lvar_locator_t_ = sizeof(::lvar_locator_t);
    static constexpr size_t lvar_t_ = sizeof(::lvar_t);
    static constexpr size_t qstring_ = sizeof(::qstring);
    static constexpr size_t citem_t_ = sizeof(::citem_t);
    static constexpr size_t cinsn_t_ = sizeof(::cinsn_t);
    static constexpr size_t cblock_t_ = sizeof(::cblock_t);
    static constexpr size_t cexpr_t_ = sizeof(::cexpr_t);
    static constexpr size_t cswitch_t_ = sizeof(::cswitch_t);
    static constexpr size_t ctry_t_ = sizeof(::ctry_t);
    static constexpr size_t cthrow_t_ = sizeof(::cthrow_t);
    static constexpr size_t cfunc_t_ = sizeof(::cfunc_t);
};

// alignof facts.
struct Aligns {
    static constexpr size_t range_t_ = alignof(::range_t);
    static constexpr size_t op_t_ = alignof(::op_t);
    static constexpr size_t insn_t_ = alignof(::insn_t);
    static constexpr size_t argloc_t_ = alignof(::argloc_t);
    static constexpr size_t tinfo_t_ = alignof(::tinfo_t);
    static constexpr size_t lvar_t_ = alignof(::lvar_t);
    static constexpr size_t qstring_ = alignof(::qstring);
    static constexpr size_t citem_t_ = alignof(::citem_t);
    static constexpr size_t cexpr_t_ = alignof(::cexpr_t);
    static constexpr size_t cfunc_t_ = alignof(::cfunc_t);
};

// offsetof facts.
struct Offsets {
    static constexpr size_t op_t_n = offsetof(::op_t, n);
    static constexpr size_t op_t_type = offsetof(::op_t, type);
    static constexpr size_t op_t_reg = offsetof(::op_t, reg);
    static constexpr size_t op_t_value = offsetof(::op_t, value);
    static constexpr size_t op_t_addr = offsetof(::op_t, addr);
    static constexpr size_t op_t_specval = offsetof(::op_t, specval);
    static constexpr size_t op_t_specflag1 = offsetof(::op_t, specflag1);
    static constexpr size_t op_t_specflag4 = offsetof(::op_t, specflag4);
    static constexpr size_t insn_t_ops = offsetof(::insn_t, ops);
    static constexpr size_t lvar_t_location = offsetof(::lvar_t, location);
    static constexpr size_t lvar_t_defea = offsetof(::lvar_t, defea);
    static constexpr size_t lvar_t_name = offsetof(::lvar_t, name);
    static constexpr size_t lvar_t_tif = offsetof(::lvar_t, tif);
    static constexpr size_t citem_t_ea = offsetof(::citem_t, ea);
    static constexpr size_t citem_t_op = offsetof(::citem_t, op);
    static constexpr size_t cexpr_t_type = offsetof(::cexpr_t, type);
    static constexpr size_t cexpr_t_exflags = offsetof(::cexpr_t, exflags);
    static constexpr size_t cfunc_t_entry_ea = offsetof(::cfunc_t, entry_ea);
    static constexpr size_t cfunc_t_mba = offsetof(::cfunc_t, mba);
    static constexpr size_t cfunc_t_body = offsetof(::cfunc_t, body);
    static constexpr size_t cfunc_t_maturity = offsetof(::cfunc_t, maturity);
};

}  // namespace abi_probe
