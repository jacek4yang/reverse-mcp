#pragma once

#include "undo.hpp"

// #16: IDB snapshot/rollback. The SDK undo API creates a restore point in the
// IDB's undo history; perform_undo() rolls the database back to the last
// restore point. These are core (idaman) exports — no UI dependency.
bool idalib_create_undo_point() { return create_undo_point(nullptr, 0); }
bool idalib_perform_undo() { return perform_undo(); }
rust::String idalib_undo_action_label() {
  auto buf = qstring();
  if (get_undo_action_label(&buf)) {
    return rust::String(buf.c_str());
  }
  return rust::String();
}
