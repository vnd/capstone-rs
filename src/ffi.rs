use std;
use libc;
use std::fmt;
use std::mem;
use std::str;

/// Opaque Capstone pointer
pub type CsHandle = libc::size_t;

#[repr(C)]
#[derive(Debug)]
/// Capstone architectures
pub enum CsArch {
    /// ARM architecture (including Thumb, Thumb-2)
    ARCH_ARM = 0,
    /// ARM-64, also called AArch64
    ARCH_ARM64,
    /// Mips architecture
    ARCH_MIPS,
    /// X86 architecture (including x86 & x86-64)
    ARCH_X86,
    /// PowerPC architecture
    ARCH_PPC,
    /// Sparc architecture
    ARCH_SPARC,
    /// SystemZ architecture
    ARCH_SYSZ,
    /// XCore architecture
    ARCH_XCORE,
    /// All architectures - for cs_support()
    ARCH_ALL = 0xFFFF,
}

pub use ffi::mode::CsMode;
/// Capstone architecture modes
pub mod mode {
    bitflags! {
        #[repr(C)]
        #[doc="Capstone architecture mode flags"]
        flags CsMode: u32 {
            #[doc="little-endian mode (default mode)"]
            const LITTLE_ENDIAN = 0,
            #[doc="32-bit ARM"]
            const ARM = 0,
            #[doc="16-bit mode (X86)"]
            const W16 = 1 << 1,
            #[doc="32-bit mode (X86)"]
            const W32 = 1 << 2,
            #[doc="64-bit mode (X86, PPC)"]
            const W64 = 1 << 3,
            #[doc="ARM's Thumb mode, including Thumb-2"]
            const THUMB = 1 << 4,
            #[doc="ARM's Cortex-M series"]
            const MCLASS = 1 << 5,
            #[doc="ARMv8 A32 encodings for ARM"]
            const V8 = 1 << 6,
            #[doc="MicroMips mode (MIPS)"]
            const MICRO = 1 << 4,
            #[doc="Mips III ISA"]
            const MIPS3 = 1 << 5,
            #[doc="Mips32r6 ISA"]
            const MIPS32R6 = 1 << 6,
            #[doc="General Purpose Registers are 64-bit wide (MIPS)"]
            const MIPSGP64 = 1 << 7,
            #[doc="SparcV9 mode (Sparc)"]
            const V9 = 1 << 4,
            #[doc="big-endian mode"]
            const BIG_ENDIAN = 1 << 31,
            #[doc="Mips32 ISA (Mips)"]
            const MIPS32 = W32.bits,
            #[doc="Mips64 ISA (Mips)"]
            const MIPS64 = W64.bits,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
#[allow(dead_code)]
/// Capstone engine option
pub enum CsOptType {
    /// Assembly output syntax
    CS_OPT_SYNTAX = 1,
    /// Break down instruction structure into details
    CS_OPT_DETAIL,
    /// Change engine's mode at run-time
    CS_OPT_MODE,
    /// User-defined dynamic memory related functions
    CS_OPT_MEM,
    /// Skip data when disassembling
    CS_OPT_SKIPDATA,
    /// Setup user-defined functions for data skipping
    CS_OPT_SKIPDATA_SETUP,
}

pub use ffi::optval::CsOptValue;
#[allow(dead_code)]
pub mod optval {
    use std::fmt;
    #[repr(C)]
    pub struct CsOptValue(u32);
    /// Turn OFF an option
    pub const CS_OPT_OFF: CsOptValue = CsOptValue(0);
    /// Turn ON an option
    pub const CS_OPT_ON: CsOptValue = CsOptValue(3);
    /// Default asm syntax
    pub const CS_OPT_SYNTAX_DEFAULT: CsOptValue = CsOptValue(0);
    /// X86 Intel asm syntax - default on X86
    pub const CS_OPT_SYNTAX_INTEL: CsOptValue = CsOptValue(1);
    /// X86 ATT asm syntax
    pub const CS_OPT_SYNTAX_ATT: CsOptValue = CsOptValue(2);
    /// Print numbers instead of register names
    pub const CS_OPT_SYNTAX_NOREGNAME: CsOptValue = CsOptValue(3);

    impl fmt::Debug for CsOptValue {
        fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
            write!(w, "{}", self.0)
        }
    }
    impl fmt::Display for CsOptValue {
        fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
            let str = match *self {
                CS_OPT_OFF => "CS_OPT_OFF | CS_OPT_SYNTAX_DEFAULT",
                CS_OPT_ON => "CS_OPT_ON | CS_OPT_SYNTAX_NOREGNAME",
                CS_OPT_SYNTAX_INTEL => "CS_OPT_SYNTAX_INTEL",
                CS_OPT_SYNTAX_ATT => "CS_OPT_SYNTAX_ATT",
                _ => "CS_OPT_UNKNOWN",
            };
            write!(w, "{}", str)
        }
    }
}

//FIXME Debug print shows unknown groups as IRET
#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Capstone instruction group
pub enum CsGroup {
    /// Invalid group
    CS_GRP_INVALID = 0,
    /// Jump instruction (jmp, bl, xbegin, etc)
    CS_GRP_JUMP,
    /// Procedure call instruction (call)
    CS_GRP_CALL,
    /// Procedure return instruction (ret)
    CS_GRP_RET,
    /// Interrupt instruction (int, swi)
    CS_GRP_INT,
    /// Interrupt return instruction (iret)
    CS_GRP_IRET,
}

#[repr(C)]
/// Architecture independent instruction detail
pub struct InsnDetail {
    regs_read: [u8; 12],
    regs_read_count: u8,
    regs_write: [u8; 20],
    regs_write_count: u8,
    groups: [CsGroup; 8],
    groups_count: u8,

    arch_data: [u64; 185],
}

impl Clone for InsnDetail {
    fn clone(&self) -> InsnDetail {
        let mut new_arr = [0; 185];
        new_arr.clone_from_slice(&self.arch_data);
        InsnDetail {
            regs_read: self.regs_read.clone(),
            regs_read_count: self.regs_read_count.clone(),
            regs_write: self.regs_write.clone(),
            regs_write_count: self.regs_write_count.clone(),
            groups: self.groups.clone(),
            groups_count: self.groups_count.clone(),
            arch_data: new_arr,
        }
    }
}

impl InsnDetail {
    /// Retrieve list of groups this instruction belongs to
    pub fn groups(&self) -> &[CsGroup] {
        &self.groups[0..self.groups_count as usize]
    }
    /// Retrieve architecture-specific data for X86
    pub unsafe fn data_x86(&self) -> &detail::X86Detail {
        mem::transmute(&self.arch_data)
    }

    pub unsafe fn data_arm(&self) -> &detail::ARMDetail {
        mem::transmute(&self.arch_data)
    }
    pub unsafe fn data_ppc(&self) -> &detail::PPCDetail {
        mem::transmute(&self.arch_data)
    }
}

impl fmt::Debug for InsnDetail {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        w.debug_struct("InsnDetail")
            .field("regs_read_count", &self.regs_read_count)
            .field("regs_write_count", &self.regs_write_count)
            .field("groups_count", &self.groups_count)
            .finish()
    }
}

/// Instruction platform-specific details
pub mod detail {
    use std::mem;
    use std::fmt;

    #[repr(C)]
    #[derive(Debug)]
    /// Platform-specific instruction detail for Intel x86 family
    pub struct X86Detail {
        pub prefix: [u8; 4],
        pub opcode: [u8; 4],
        pub rex: u8,
        pub addr_size: u8,
        pub modrm: u8,
        pub sib: u8,
        pub disp: u32,
        pub sib_index: u32,
        pub sib_scale: u8,
        pub sib_base: u32,
        pub sse_cc: u32,
        pub avx_cc: u32,
        pub avx_sae: u8,
        pub avx_rm: u32,
        op_count: u8,
        operands: [X86Op; 8],
    }

    impl X86Detail {
        pub fn operands(&self) -> &[X86Op] {
            &self.operands[0..self.op_count as usize]
        }
    }

    #[repr(C)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    /// Instruction operand type for Intel x86 family
    pub enum X86OpType {
        /// Uninitialized
        X86_OP_INVALID = 0,
        /// Register operand
        X86_OP_REG,
        /// Immediate operand
        X86_OP_IMM,
        /// Memory operand
        X86_OP_MEM,
        /// Floating-Point operand
        X86_OP_FP,
    }

    #[derive(Debug)]
    /// Instruction operand for Intel x86 family
    pub struct X86Op {
        pub ty: X86OpType,
        pub data: [u64; 3],
        pub size: u8,
        pub avx_bcase: u32,
        pub avx_zero_opmask: u32,
    }

    #[derive(Copy, Clone, Debug)]
    /// Instruction operand data for Intel x86 family
    pub enum X86OpData {
        /// Immediate operand
        Imm(i64),
        /// Other operand
        Other,
    }

    impl X86Op {
        unsafe fn data_imm(&self) -> i64 {
            *mem::transmute::<&[u64; 3], &i64>(&self.data)
        }
        pub fn data(&self) -> X86OpData {
            match self.ty {
                X86OpType::X86_OP_IMM => X86OpData::Imm(unsafe { self.data_imm() }),
                _ => X86OpData::Other, // TODO this
            }
        }
    }

    #[repr(C)]
    #[derive(PartialEq, Eq)]
    pub enum PPCOpType {
        PPC_OP_INVALID = 0,
        PPC_OP_REG,
        PPC_OP_IMM,
        PPC_OP_MEM,
    }

    pub enum PPCOpData {
        /// Immediate operand
        Imm(u32),
        Other,
    }

    pub struct PPCOp {
        pub ty: PPCOpType,
        pub data: [u32; 3],
    }

    impl PPCOp {
        unsafe fn data_imm(&self) -> u32 {
            *mem::transmute::<_, &u32>(&self.data)
        }
        pub fn data(&self) -> PPCOpData {
            match self.ty {
                PPCOpType::PPC_OP_IMM => PPCOpData::Imm(unsafe { self.data_imm() }),
                _ => PPCOpData::Other, // TODO this
            }
        }
    }

    pub struct PPCDetail {
        pub ppc_bc: u32,
        pub ppc_bh: u32,
        pub update_cr0: bool,
        op_count: u8,
        operands: [PPCOp; 8],
    }

    impl PPCDetail {
        pub fn operands(&self) -> &[PPCOp] {
            &self.operands[0..self.op_count as usize]
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMOpType {
        ARM_OP_INVALID = 0,
        ARM_OP_REG,
        ARM_OP_IMM,
        ARM_OP_MEM,
        ARM_OP_FP,
        ARM_OP_CIMM = 64,
        ARM_OP_PIMM,
        ARM_OP_SETEND,
        ARM_OP_SYSREG,
    }

    #[repr(C)]
    #[derive(Debug, PartialEq, Eq)]
    pub enum ARMSetendType {
        ARM_SETEND_INVALID = 0,
        ARM_SETEND_BE,
        ARM_SETEND_LE,
    }

    #[repr(C)]
    #[derive(Debug)]
    pub struct ARMOpMem {
        pub base: u32,
        pub index: u32,
        pub scale: i32,
        pub disp: i32,
    }

    #[repr(C)]
    #[derive(Debug)]
    pub struct ARMOp {
        pub vector_index: i32,
        pub shift_type: u32,
        pub value: u32,
        pub ty: ARMOpType,
        pub data: [u64; 2],
        pub subtracted: bool,
    }

    #[derive(Debug)]
    /// Instruction operand data for ARM
    pub enum ARMOpData {
        /// Immediate operand
        Imm(u32),
        Other,
    }

    impl ARMOp {
        unsafe fn data_imm(&self) -> u32 {
            *mem::transmute::<&[u64; 2], &u32>(&self.data)
        }
        pub fn data(&self) -> ARMOpData {
            match self.ty {
                ARMOpType::ARM_OP_IMM => ARMOpData::Imm(unsafe { self.data_imm() }),
                _ => ARMOpData::Other, // TODO this
            }
        }
    }

    #[repr(C)]
    pub struct ARMDetail {
        pub usermode: bool,
        pub vector_size: i32,
        pub vector_data: u32,
        pub cps_mode: u32,
        pub cps_flag: u32,
        pub cc: u32,
        pub update_flags: bool,
        pub writeback: bool,
        pub mem_barrier: u32,
        op_count: u32,
        operands: [ARMOp; 36],
    }


    impl ARMDetail {
        pub fn operands(&self) -> &[ARMOp] {
            &self.operands[0..self.op_count as usize]
        }
    }

    impl fmt::Debug for ARMDetail {
        fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
            w.debug_struct("ARMDetail")
                .field("usermode", &self.usermode)
                .field("vector_size", &self.vector_size)
                .field("vector_data", &self.vector_data)
                .field("cps_mode", &self.cps_mode)
                .field("cps_flag", &self.cps_flag)
                .field("cc", &self.cc)
                .field("update_flags", &self.update_flags)
                .field("writeback", &self.writeback)
                .field("mem_barrier", &self.mem_barrier)
                .field("op_count", &self.op_count)
                .field("operands", &self.operands())
                .finish()
        }
    }

}

#[repr(C)]
/// A disassembled Capstone instruction
pub struct Insn {
    id: ::libc::c_uint,
    address: u64,
    size: u16,
    bytes: [u8; 16usize],
    mnemonic: [::libc::c_char; 32usize],
    op_str: [::libc::c_char; 160usize],
    detail: *mut InsnDetail,
}

impl Insn {
    /// Address of this instruction (relative to default base)
    pub fn address(&self) -> u64 {
        self.address
    }
    /// Size of this instruction
    pub fn size(&self) -> u16 {
        self.size
    }
    /// Instruction mnemonic (e.g., 'mov', 'push')
    pub fn mnemonic(&self) -> Option<&str> {
        let cstr = unsafe { std::ffi::CStr::from_ptr(self.mnemonic.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }

    /// Instruction operation string (e.g., 'rax', 'esp, 11')
    pub fn op_str(&self) -> Option<&str> {
        let cstr = unsafe { std::ffi::CStr::from_ptr(self.op_str.as_ptr()) };
        str::from_utf8(cstr.to_bytes()).ok()
    }
    /// Architecture-independent instruction detail
    pub fn detail(&self) -> Option<&InsnDetail> {
        if self.detail.is_null() {
            None
        } else {
            unsafe {
                Some(&*self.detail)
            }
        }
    }
}

impl fmt::Debug for Insn {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt.debug_struct("Insn")
            .field("address", &self.address)
            .field("size", &self.size)
            .field("mnemonic", &self.mnemonic())
            .field("op_str", &self.op_str())
            .finish()
    }
}

pub fn set_opt(csh: CsHandle, opt: CsOptType, val: CsOptValue) -> Result<(), ::CsError> {
    unsafe {
        match cs_option(csh, opt, val) {
            ::CsError::CS_ERR_OK => Ok(()),
            e => Err(e),
        }
    }
}

pub fn group_name<'a>(csh: CsHandle, group: CsGroup) -> Option<&'a str> {
    unsafe {
        let name = cs_group_name(csh, group);
        if name.is_null() {
            None
        } else {
            match std::ffi::CStr::from_ptr(name).to_str() {
                Ok(str) => Some(str),
                Err(_) => None,
            }
        }
    }
}

pub fn new_csh(arch: CsArch, mode: CsMode) -> Result<::Handle, ::CsError> {
    let mut handle = 0;
    let err = unsafe { cs_open(arch, mode, &mut handle) };
    if err == ::CsError::CS_ERR_OK {
        Ok(::Handle::from(handle))
    } else {
        Err(err)
    }
}


#[link(name = "capstone")]
extern "C" {
    pub fn cs_open(arch: CsArch, mode: CsMode, handle: *mut CsHandle) -> ::CsError;
    pub fn cs_close(handle: *mut CsHandle) -> ::CsError;
    pub fn cs_malloc(handle: CsHandle) -> *mut Insn;
    pub fn cs_disasm(handle: CsHandle, code: *const u8, code_size: libc::size_t,
                     address: u64, count: libc::size_t, insn: &mut *const Insn) -> libc::size_t;
    pub fn cs_disasm_iter(handle: CsHandle, code: *mut *const u8, code_size: *mut libc::size_t,
                          address: *mut u64, insn: *const Insn) -> bool;
    pub fn cs_free(insn: *const Insn, count: libc::size_t);
    pub fn cs_option(handle: CsHandle, opt: CsOptType, val: CsOptValue) -> ::CsError;
    pub fn cs_errno(handle: CsHandle) -> ::CsError;
    pub fn cs_group_name(handle: CsHandle, name: CsGroup) -> *const libc::c_char;
    pub fn cs_strerror(code: ::CsError) -> *const libc::c_char;
}
