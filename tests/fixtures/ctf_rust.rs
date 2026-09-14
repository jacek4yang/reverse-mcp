// CTF-grade test fixture #2 (Rust): trait-object dispatch + iterator chains
// + panic paths. Challenges: monomorphized generics explode into many small
// functions; enum discriminants drive state; String formatting on stack.

use std::env;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Add,
    Xor,
    Rotl(u32),
    Fold,
}

struct Stage {
    op: Op,
    mask: u64,
}

impl Stage {
    fn apply(&self, v: u64) -> u64 {
        match self.op {
            Op::Add => v.wrapping_add(self.mask),
            Op::Xor => v ^ self.mask,
            Op::Rotl(n) => {
                let n = (n % 64) as u32;
                v.rotate_left(n)
            }
            Op::Fold => {
                let lo = (v & 0xFFFF_FFFF) as u64;
                let hi = v >> 32;
                (lo ^ hi).wrapping_mul(self.mask | 1)
            }
        }
    }
}

fn pipeline(v0: u64, stages: &[Stage]) -> u64 {
    stages.iter().fold(v0, |acc, s| s.apply(acc))
}

fn build_stages(key: u64) -> Vec<Stage> {
    vec![
        Stage { op: Op::Add, mask: key & 0xFFFF },
        Stage { op: Op::Rotl(13), mask: 0 },
        Stage { op: Op::Xor, mask: key.rotate_left(32) },
        Stage { op: Op::Fold, mask: 0x9E37_79B9_7F4A_7C15 },
        Stage { op: Op::Rotl(41), mask: 0 },
        Stage { op: Op::Add, mask: key >> 16 },
    ]
}

const TARGET: u64 = 0x6C0D_A3E7_9921_44B0;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: ctf_rust <token>");
        std::process::exit(2);
    }
    // Token must be 16 hex chars.
    let token = &args[1];
    if token.len() != 16 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("bad token");
        std::process::exit(3);
    }
    let key = u64::from_str_radix(&token[..8], 16).expect("hi");
    let key2 = u64::from_str_radix(&token[8..], 16).expect("lo");
    let combined = (key << 32) | key2;

    let stages = build_stages(combined);
    let out = pipeline(0x1234_5678_9ABC_DEF0, &stages);

    if out == TARGET {
        println!("flag{{rust_p1pel1ne_{combined:016x}}}");
    } else {
        println!("denied ({out:016x})");
        std::process::exit(4);
    }
}
