use libc;
use std;
use std::ptr;
use ffi;

/// Handle to Capstone Engine instance
pub struct Handle(ffi::CsHandle);

impl Handle {
    /// Disassemble all instructions into a buffer
    pub fn disasm(&self, code: &[u8], addr: u64, count: isize) -> Result<Instructions, ::CsError> {
        let mut ptr: *const ffi::Insn = ptr::null();
        let insn_count = unsafe { ffi::cs_disasm(self.0, code.as_ptr(), code.len() as libc::size_t,
                                            addr, count as libc::size_t, &mut ptr) };
        if insn_count == 0 {
            let err = unsafe { ffi::cs_errno(self.0) };
            return Err(err)
        }

        Ok(Instructions::from_parts(ptr, count as usize))
    }

    #[must_use]
    /// Walk over disassembled instructions, one at a time (fixed memory
    /// usage)
    pub fn walk_insts<F>(&mut self, code: &[u8], mut addr: u64, mut f: F) -> Result<(), ::CsError> where F: FnMut(&ffi::Insn) {
        let mut code_ptr = code.as_ptr();
        let mut code_sz = code.len() as u64;
        unsafe {
            let insn = ffi::cs_malloc(&mut self.0);
            while ffi::cs_disasm_iter(self.0, &mut code_ptr, &mut code_sz, &mut addr, insn) {
                f(&*insn);
            }
            ffi::cs_free(insn, 1);
        }
        Ok(())
    }
    /// Get the human-readable name of an instruction group
    pub fn group_name(&self, group: ffi::CsGroup) -> Option<&str> {
        ffi::group_name(self.0, group)
    }
}

#[doc(hidden)]
impl From<ffi::CsHandle> for Handle {
    fn from(csh: ffi::CsHandle) -> Handle {
        Handle(csh)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { ffi::cs_close(&mut self.0) };
    }
}

/// Utility struct to construct a configured Capstone Engine Handle
pub struct HandleBuilder {
    arch: ffi::CsArch,
    mode: ffi::CsMode,
    detail: bool,
    skipdata: bool,
}

impl HandleBuilder {
    /// Create a new HandleBuilder with all options defaulting to off
    pub fn new(arch: ffi::CsArch, mode: ffi::CsMode) -> HandleBuilder {
        HandleBuilder {
            arch: arch,
            mode: mode,
            detail: false,
            skipdata: false,
        }
    }
    /// Enable CS_OPT_SKIPDATA
    pub fn skipdata(mut self) -> HandleBuilder {
        self.skipdata = true;
        self
    }
    /// Enable CS_OPT_DETAIL
    pub fn detail(mut self) -> HandleBuilder {
        self.detail = true;
        self
    }
    /// Create and configure the Handle
    pub fn build(self) -> Result<Handle, ::CsError> {
        let csh = try!(ffi::new_csh(self.arch, self.mode));
        try!(ffi::set_opt(csh.0, ffi::CsOptType::CS_OPT_DETAIL, match self.detail {
            true => ffi::optval::CS_OPT_ON,
            false => ffi::optval::CS_OPT_OFF,
        }));
        try!(ffi::set_opt(csh.0, ffi::CsOptType::CS_OPT_SKIPDATA, match self.skipdata {
            true => ffi::optval::CS_OPT_ON,
            false => ffi::optval::CS_OPT_OFF,
        }));
        Ok(csh)
    }
}

/// Disassembled Capstone instructions
pub struct Instructions {
    ptr: *const ffi::Insn,
    count: usize,
}

impl Instructions {
    #[doc(hidden)]
    pub fn from_parts(ptr: *const ffi::Insn, count: usize) -> Instructions {
        Instructions {
            ptr: ptr,
            count: count,
        }
    }

    pub fn as_slice(&self) -> &[ffi::Insn] {
        unsafe {
            std::slice::from_raw_parts(self.ptr, self.count)
        }
    }
}

impl Drop for Instructions {
    fn drop(&mut self) {
        unsafe {
            ffi::cs_free(self.ptr, self.count as libc::size_t);
        }
    }
}
