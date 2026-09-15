#pragma once

#include "bytes.hpp"

#include "cxx.h"

std::uint8_t idalib_get_byte(ea_t ea) { return get_byte(ea); }
std::uint16_t idalib_get_word(ea_t ea) { return get_word(ea); }
std::uint32_t idalib_get_dword(ea_t ea) { return get_dword(ea); }
std::uint64_t idalib_get_qword(ea_t ea) { return get_qword(ea); }

std::size_t idalib_get_bytes(ea_t ea, rust::Vec<rust::u8> &buf) {
  if (auto sz = get_bytes(buf.data(), buf.capacity(), ea, GMB_READALL);
      sz >= 0) {
    return sz;
  } else {
    return 0;
  }
}

// ---- #16: patching ----
// patch_bytes (unlike put_bytes) records the change so it shows up in
// visit_patched_bytes and is included in undo records.
bool idalib_patch_bytes(ea_t ea, const rust::Vec<rust::u8> &bytes) {
  if (bytes.empty()) {
    return false;
  }
  patch_bytes(ea, bytes.data(), bytes.size());
  return true;
}

// Original (unpatched) byte of the input file at ea — lets the audit trail
// record what a patch overwrote and lets agents diff before/after. Returns
// the raw item value; per SDK semantics "no original value" is not
// distinguishable, so callers treat it as a best-effort record.
std::uint64_t idalib_get_original_byte(ea_t ea) { return get_original_byte(ea); }
