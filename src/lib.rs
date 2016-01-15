//! Bindings to the Capstone Engine (http://www.capstone-engine.org)
#![feature(clone_from_slice)]
extern crate libc;

#[macro_use]
extern crate bitflags;

mod ffi;
mod handle;
mod error;

pub use handle::{Handle,HandleBuilder,Instructions};
pub use ffi::{Insn,InsnDetail,CsArch,CsGroup,mode,detail};
pub use mode::CsMode;
pub use error::CsError;

#[cfg(test)]
mod test {
    use super::*;
    static CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

    #[test]
    fn test_x86_simple() {
    match capstone::Capstone::new(constants::CsArch::ARCH_X86,
                                  constants::CsMode::MODE_64) {
        Some(cs) => {
            if let Some(insns) = cs.disasm(CODE, 0x1000, 0) {
                assert_eq!(insns.len(), 2);
                let is: Vec<_> = insns.iter().collect();
                assert_eq!(is[0].mnemonic().unwrap(), "push");
                assert_eq!(is[1].mnemonic().unwrap(), "mov");

                assert_eq!(is[0].address, 0x1000);
                assert_eq!(is[1].address, 0x1001);
            } else {
                assert!(false, "Couldn't disasm instructions")
            }
        },
        None => {
            assert!(false, "Couldn't create a cs engine");
        }
    }
}
}
