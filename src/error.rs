use ffi;
use std;
use std::fmt;
use std::error::Error;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
/// Capstone library error
pub enum CsError {
    /// No error: everything was fine
    CS_ERR_OK = 0,
    /// Out-Of-Memory error: cs_open(), cs_disasm(), cs_disasm_iter()
    CS_ERR_MEM,
    /// Unsupported architecture: cs_open()
    CS_ERR_ARCH,
    /// Invalid handle: cs_op_count(), cs_op_index()
    CS_ERR_HANDLE,
    /// Invalid csh argument: cs_close(), cs_errno(), cs_option()
    CS_ERR_CSH,
    /// Invalid/unsupported mode: cs_open()
    CS_ERR_MODE,
    /// Invalid/unsupported option: cs_option()
    CS_ERR_OPTION,
    /// Information is unavailable because detail option is OFF
    CS_ERR_DETAIL,
    /// Dynamic memory management uninitialized (see CS_OPT_MEM)
    CS_ERR_MEMSETUP,
    /// Unsupported version (bindings)
    CS_ERR_VERSION,
    /// Access irrelevant data in "diet" engine
    CS_ERR_DIET,
    /// Access irrelevant data for "data" instruction in SKIPDATA mode
    CS_ERR_SKIPDATA,
    /// X86 AT&T syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_ATT,
    /// X86 Intel syntax is unsupported (opt-out at compile time)
    CS_ERR_X86_INTEL,
}

impl Error for CsError {
    fn description(&self) -> &str {
        unsafe {
            let ptr = ffi::cs_strerror(*self);
            if ptr.is_null() {
                "(null)"
            } else {
                std::ffi::CStr::from_ptr(ptr).to_str().unwrap_or("(invalid)")
            }
        }
    }
}

impl fmt::Debug for CsError {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        let str = match *self {
            CsError::CS_ERR_OK => "CS_ERR_OK",
            CsError::CS_ERR_MEM => "CS_ERR_MEM",
            CsError::CS_ERR_ARCH => "CS_ERR_ARCH",
            CsError::CS_ERR_HANDLE => "CS_ERR_HANDLE",
            CsError::CS_ERR_CSH => "CS_ERR_CSH",
            CsError::CS_ERR_MODE => "CS_ERR_MODE",
            CsError::CS_ERR_OPTION => "CS_ERR_OPTION",
            CsError::CS_ERR_DETAIL => "CS_ERR_DETAIL",
            CsError::CS_ERR_MEMSETUP => "CS_ERR_MEMSETUP",
            CsError::CS_ERR_VERSION => "CS_ERR_VERSION",
            CsError::CS_ERR_DIET => "CS_ERR_DIET",
            CsError::CS_ERR_SKIPDATA => "CS_ERR_SKIPDATA",
            CsError::CS_ERR_X86_ATT => "CS_ERR_X86_ATT",
            CsError::CS_ERR_X86_INTEL => "CS_ERR_X86_INTEL",
        };
        write!(w, "{}", str)
    }
}

impl fmt::Display for CsError {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        write!(w, "{}", self.description())
    }
}
