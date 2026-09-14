#pragma once

#include "bytes.hpp"
#include "ida.hpp"
#include "lines.hpp"
#include "loader.hpp"
#include "name.hpp"
#include "pro.h"
#include "ua.hpp"

#include <cstdint>
#include <string>

// Save the current database to its current path (thin wrapper over
// save_database, which is not otherwise bridged).
inline bool idalib_save_database() {
  return save_database(nullptr, -1, nullptr, nullptr);
}

// Rename the item at `ea`. Thin wrapper over set_name with SN_CHECK.
inline bool idalib_set_name(ea_t ea, const char *name) {
  return set_name(ea, name, SN_CHECK);
}

// Generate one cleaned line of disassembly at `ea` (tags removed).
inline rust::String idalib_disasm_line(ea_t ea) {
  qstring buf;
  if (!generate_disasm_line(&buf, ea, GENDSM_REMOVE_TAGS)) {
    return rust::String();
  }
  return rust::String(buf.c_str());
}

// Get the name of the item at `ea` (empty string if none).
inline rust::String idalib_get_name(ea_t ea) {
  qstring n;
  get_name(&n, ea, 0);
  return rust::String(n.c_str());
}
