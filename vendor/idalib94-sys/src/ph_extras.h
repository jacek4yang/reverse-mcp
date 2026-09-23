#pragma once

#include "pro.h"
#include "idp.hpp"
#include "segregs.hpp"

#include "cxx.h"

// processor_t::get_proc_index() expands the SDK's INTERR macro, which
// references the `under_debugger` data export of ida.dll — a data import
// that is incompatible with delay-loading ida.dll. Use our own lookup
// without the INTERR path (0 is a safe fallback, same as psnames[0]).
inline int idalib_proc_index(const processor_t *ph) {
  qstring curproc = inf_get_procname();
  for (size_t i = 0; ph->psnames[i] != nullptr; ++i) {
    const char *p = ph->psnames[i];
    if (p[0] == '-') { // obsolete processor names start with a '-'
      ++p;
    }
    if (curproc == p) {
      return static_cast<int>(i);
    }
  }
  return 0;
}

std::int32_t idalib_ph_id(const processor_t *ph) {
  return ph->id;
}

rust::String idalib_ph_short_name(const processor_t *ph) {
  auto name = ph->psnames[idalib_proc_index(ph)];
  return rust::String(name);
}

rust::String idalib_ph_long_name(const processor_t *ph) {
  auto name = ph->plnames[idalib_proc_index(ph)];
  return rust::String(name);
}

bool idalib_is_thumb_at(const processor_t *ph, ea_t ea) {
  const auto T = 20;

  if (ph->id == PLFM_ARM && !inf_is_64bit()) {
    auto tbit = get_sreg(ea, T);
    return tbit != 0 && tbit != BADSEL;
  }
  return false;
}
