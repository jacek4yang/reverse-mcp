//! Synthetic minimal ELF fixtures for issue #66 cross-arch tests.
//!
//! Each fixture is a self-contained, statically-declared byte array shaped
//! like a minimal executable for its architecture: ELF header + one
//! executable PT_LOAD program header + the architecture's canonical
//! function-prologue encoding repeated a few times, then terminated. They
//! are pure static analysis inputs - nothing is ever executed.

/// 32-bit little-endian MIPS: minimal ELF32 + one executable PT_LOAD.
/// body: `jr ra; nop` repeated (0x03e00008, 0x00000000).
pub fn mips32_elf() -> Vec<u8> {
    with_machine(elf32(0x03e00008u32, 0x00000000u32, 8), 8) // EM_MIPS
}

/// 32-bit little-endian x86: minimal ELF32 + executable PT_LOAD.
/// body: `ret` (0xC3) repeated.
pub fn x86_elf() -> Vec<u8> {
    with_machine(elf32(0x000000C3u32, 0x000000C3u32, 8), 3) // EM_386
}

/// 32-bit ARM: minimal ELF32 + executable PT_LOAD.
/// body: `bx lr` (0xE12FFF1E) repeated.
pub fn arm_elf() -> Vec<u8> {
    with_machine(elf32(0xE12FFF1Eu32, 0xE12FFF1Eu32, 8), 40) // EM_ARM
}

fn elf32(body_word: u32, filler: u32, repeat: usize) -> Vec<u8> {
    // e_machine per caller would need a param; keep simple: callers set
    // the machine by patching the returned vec via `with_machine`.
    let mut v = Vec::new();
    // ---- ELF32 header (52 bytes) ----
    v.extend_from_slice(b"\x7fELF");
    v.push(1); // EI_CLASS: ELFCLASS32
    v.push(1); // EI_DATA: little endian
    v.push(1); // EI_VERSION
    v.push(0); // EI_OSABI
    v.extend_from_slice(&[0u8; 8]); // padding
    v.extend_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
    v.extend_from_slice(&[0u8; 2]); // e_machine: PATCH via with_machine
    v.extend_from_slice(&1u32.to_le_bytes()); // e_version
    v.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // e_entry
    v.extend_from_slice(&52u32.to_le_bytes()); // e_phoff
    v.extend_from_slice(&0u32.to_le_bytes()); // e_shoff
    v.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    v.extend_from_slice(&32u16.to_le_bytes()); // e_ehsize
    v.extend_from_slice(&32u16.to_le_bytes()); // e_phentsize
    v.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    v.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    v.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    v.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
    debug_assert_eq!(v.len(), 52);
    // ---- program header (32 bytes) ----
    v.extend_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
    v.extend_from_slice(&0u32.to_le_bytes()); // p_offset
    v.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // p_vaddr
    v.extend_from_slice(&0x0040_0000u32.to_le_bytes()); // p_paddr
    let body_len = (repeat * 8 + 4) as u32;
    v.extend_from_slice(&body_len.to_le_bytes()); // p_filesz
    v.extend_from_slice(&body_len.to_le_bytes()); // p_memsz
    v.extend_from_slice(&5u32.to_le_bytes()); // p_flags: R+X
    v.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align
    // ---- body ----
    for _ in 0..repeat {
        v.extend_from_slice(&body_word.to_le_bytes());
        v.extend_from_slice(&filler.to_le_bytes());
    }
    v
}

/// Patch e_machine (offset 18..20, ELF32) to `machine`.
pub fn with_machine(mut elf: Vec<u8>, machine: u16) -> Vec<u8> {
    elf[18..20].copy_from_slice(&machine.to_le_bytes());
    elf
}
