use libc;
use instruction::Insn;
use constants::{CsArch, CsMode, CsErr, CsOptType, CsGroup};
use csh;

#[allow(dead_code)]
#[link(name = "capstone")]
extern "C" {
    pub fn cs_open(arch: CsArch, mode: CsMode, handle: *mut csh) -> CsErr;
    pub fn cs_close(handle: *mut csh) -> CsErr;
    pub fn cs_malloc(handle: *mut csh) -> *mut Insn;
    pub fn cs_disasm(handle: csh, code: *const u8, code_size: libc::size_t,
                     address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
    pub fn cs_disasm_ex(handle: csh, code: *const u8, code_size: libc::size_t,
                        address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
    pub fn cs_disasm_iter(handle: csh, code: *mut *const u8, code_size: *mut libc::size_t,
                          address: *mut u64, insn: *const Insn) -> bool;
    pub fn cs_free(insn: *const Insn, count: libc::size_t);
    pub fn cs_option(handle: csh, opt: CsOptType, val: libc::size_t) -> CsErr;
    pub fn cs_errno(handle: csh) -> CsErr;
    pub fn cs_group_name(handle: csh, name: CsGroup) -> *const libc::c_char;
}
