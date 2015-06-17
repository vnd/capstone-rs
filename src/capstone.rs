use libc;
use std::ptr;
use constants::*;
use std::ffi::CStr;
use ffi::{cs_close,cs_open,cs_disasm,cs_option,cs_errno,cs_group_name,cs_disasm_iter,cs_malloc,cs_free};

use instruction::{Insn,Instructions};

pub struct Capstone {
    csh: libc::size_t, // Opaque handle to cs_engine
}

impl Capstone {
    pub fn new(arch: CsArch, mode: CsMode) -> Option<Capstone> {
        let mut handle: libc::size_t = 0;
        if let CsErr::CS_ERR_OK = unsafe { cs_open(arch, mode, &mut handle) } {
            println!("got cs: {:#x}", handle);
            Some(Capstone {
                csh: handle
            })
        } else {
            None
        }
    }

    pub fn disasm(&self, code: &[u8], addr: u64, count: isize) -> Option<Instructions> {
        let mut ptr: *const Insn = ptr::null();
        let insn_count = unsafe { cs_disasm(self.csh, code.as_ptr(), code.len() as libc::size_t,
                                            addr, count as libc::size_t, &mut ptr) };
        let err = unsafe { cs_errno(self.csh) };
        println!("err is {:?}", err);
        if insn_count == 0 {
            // TODO  On failure, call cs_errno() for error code.
            return None
        }

        Some(Instructions::from_raw_parts(ptr, insn_count as isize))
    }

    #[must_use]
    pub fn walk_insts<F>(&mut self, code: &[u8], mut addr: u64, mut f: F) -> Result<(), CsErr> where F: FnMut(&Insn) {
        let mut code_ptr = code.as_ptr();
        let mut code_sz = code.len() as u64;
        unsafe {
            let insn = cs_malloc(&mut self.csh);
            while cs_disasm_iter(self.csh, &mut code_ptr, &mut code_sz, &mut addr, insn) {
                f(&*insn);
            }
            cs_free(insn, 1);
        }
        Ok(())
    }

    pub fn detail(&mut self, active: bool) -> Result<(), CsErr> {
        unsafe {
            match cs_option(self.csh, CsOptType::CS_OPT_DETAIL, match active {
                true => CsOptValue::CS_OPT_ON as libc::size_t,
                false => CsOptValue::CS_OPT_OFF as libc::size_t,
            }) {
                CsErr::CS_ERR_OK => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn skipdata(&mut self, active: bool) -> Result<(), CsErr> {
        unsafe {
            match cs_option(self.csh, CsOptType::CS_OPT_SKIPDATA, match active {
                true => CsOptValue::CS_OPT_ON as libc::size_t,
                false => CsOptValue::CS_OPT_OFF as libc::size_t,
            }) {
                CsErr::CS_ERR_OK => Ok(()),
                e => Err(e),
            }
        }
    }

    pub fn group_name(&self, group: CsGroup) -> Option<&str> {
        unsafe {
            let name = cs_group_name(self.csh, group);
            if name.is_null() {
                None
            } else {
                match CStr::from_ptr(name).to_str() {
                    Ok(str) => Some(str),
                    Err(_) => None,
                }
            }
        }
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
