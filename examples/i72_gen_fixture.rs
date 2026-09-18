//! #72 audit fixture: a giant flattened-dispatcher state machine.
//!
//! Source-grounded shape: N states, a dispatcher loop with an indirect jump
//! table (giant switch), thousands of basic blocks, many direct calls.
//! Built at -O0 so every state survives as its own basic-block cluster; the
//! generated function is ~N*40 bytes of code with N+ case blocks.
//!
//! Params: state count (default 3000). The .c is emitted next to the exe for
//! ground-truth provenance (state transitions are `calls[state % 8]`).

use std::fmt::Write as _;

fn emit_c(n_states: usize) -> String {
    let mut c = String::new();
    c.push_str("// #72 giant flattened-dispatcher state machine fixture\n");
    c.push_str("// states, one dispatcher switch, 8 helper callees\n");
    c.push_str("typedef unsigned int u32;\n");
    c.push_str("extern volatile u32 in_events[];\n");
    c.push_str("extern volatile u32 out_results[];\n");
    c.push_str("static u32 s1(u32 x){ return x ^ 0x11111111u; }\n");
    c.push_str("static u32 s2(u32 x){ return x + 0x22222222u; }\n");
    c.push_str("static u32 s3(u32 x){ return x * 3u + 1u; }\n");
    c.push_str("static u32 s4(u32 x){ return x - 0x44444444u; }\n");
    c.push_str("static u32 s5(u32 x){ return (x << 3) | (x >> 29); }\n");
    c.push_str("static u32 s6(u32 x){ return x & 0x55555555u; }\n");
    c.push_str("static u32 s7(u32 x){ return x | 0x66666666u; }\n");
    c.push_str("static u32 s8(u32 x){ return ~(x + 7u); }\n");
    c.push_str("static u32 (*const calls[8])(u32) = {s1,s2,s3,s4,s5,s6,s7,s8};\n");
    let _ = writeln!(c, "#define STATES {n_states}u\n");
    c.push_str("u32 run(u32 seed){\n    u32 state = 0, acc = seed;\n    while (1) {\n        switch (state) {\n");
    for s in 0..n_states {
        let callee = s % 8 + 1;
        let _ = writeln!(
            c,
            "        case {s}: acc = calls[{}](acc + in_events[{s}]); out_results[{s}] = acc; state = (acc ^ {s}) % STATES; break;",
            callee - 1
        );
    }
    c.push_str("        default: return acc;\n        }\n    }\n}\n");
    c
}

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(3000);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/largefn");
    std::fs::create_dir_all(&dir).unwrap();
    let src = emit_c(n);
    let cpath = dir.join(format!("giant_switch_{n}.c"));
    std::fs::write(&cpath, &src).unwrap();
    println!("wrote {}", cpath.display());
}
