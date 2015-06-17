use std::fmt;
use std::mem;

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

bitflags! {
    #[repr(C)]
    #[doc="Capstone architecture mode flags"]
    flags CsMode: u32 {
        #[doc="little-endian mode (default mode)"]
        const MODE_LITTLE_ENDIAN = 0,
        #[doc="32-bit ARM"]
        const MODE_ARM = 0,
        #[doc="16-bit mode (X86)"]
        const MODE_16 = 1 << 1,
        #[doc="32-bit mode (X86)"]
        const MODE_32 = 1 << 2,
        #[doc="64-bit mode (X86, PPC)"]
        const MODE_64 = 1 << 3,
        #[doc="ARM's Thumb mode, including Thumb-2"]
        const MODE_THUMB = 1 << 4,
        #[doc="ARM's Cortex-M series"]
        const MODE_MCLASS = 1 << 5,
        #[doc="ARMv8 A32 encodings for ARM"]
        const MODE_V8 = 1 << 6,
        #[doc="MicroMips mode (MIPS)"]
        const MODE_MICRO = 1 << 4,
        #[doc="Mips III ISA"]
        const MODE_MIPS3 = 1 << 5,
        #[doc="Mips32r6 ISA"]
        const MODE_MIPS32R6 = 1 << 6,
        #[doc="General Purpose Registers are 64-bit wide (MIPS)"]
        const MODE_MIPSGP64 = 1 << 7,
        #[doc="SparcV9 mode (Sparc)"]
        const MODE_V9 = 1 << 4,
        #[doc="big-endian mode"]
        const MODE_BIG_ENDIAN = 1 << 31,
        #[doc="Mips32 ISA (Mips)"]
        const MODE_MIPS32 = MODE_32.bits,
        #[doc="Mips64 ISA (Mips)"]
        const MODE_MIPS64 = MODE_64.bits,
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum CsOptType {
    CS_OPT_SYNTAX = 1,
    CS_OPT_DETAIL,
    CS_OPT_MODE,
    CS_OPT_MEM,
    CS_OPT_SKIPDATA,
    CS_OPT_SKIPDATA_SETUP,
}

#[repr(C)]
#[derive(Debug)]
pub enum CsOptValue {
    CS_OPT_OFF = 0,
    CS_OPT_ON = 3,
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CsGroup {
    CS_GRP_INVALID = 0,
    CS_GRP_JUMP,
    CS_GRP_CALL,
    CS_GRP_RET,
    CS_GRP_INT,
    CS_GRP_IRET,
}

#[repr(C)]
pub struct CsDetail {
    regs_read: [u8; 12],
    regs_read_count: u8,
    regs_write: [u8; 20],
    regs_write_count: u8,
    groups: [CsGroup; 8],
    groups_count: u8,

    arch_data: [u64; 185],
}

impl Clone for CsDetail {
    fn clone(&self) -> CsDetail {
        let mut new_arr = [0; 185];
        for i in 0..185 {
            new_arr[i] = self.arch_data[i]
        }
        CsDetail {
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

impl CsDetail {
    pub fn groups(&self) -> &[CsGroup] {
        &self.groups[0..self.groups_count as usize]
    }
    pub fn data_x86(&self) -> &X86Detail {
        unsafe { mem::transmute(&self.arch_data) }
    }
}

impl fmt::Debug for CsDetail {
    fn fmt(&self, w: &mut fmt::Formatter) -> fmt::Result {
        w.debug_struct("CsDetail")
            .field("regs_read_count", &self.regs_read_count)
            .field("regs_write_count", &self.regs_write_count)
            .field("groups_count", &self.groups_count)
            .finish()
    }
}

#[repr(C)]
#[derive(Debug)]
pub enum X86OpType {
	X86_OP_INVALID = 0, // = CS_OP_INVALID (Uninitialized).
	X86_OP_REG, // = CS_OP_REG (Register operand).
	X86_OP_IMM, // = CS_OP_IMM (Immediate operand).
	X86_OP_MEM, // = CS_OP_MEM (Memory operand).
	X86_OP_FP,  //  = CS_OP_FP  (Floating-Point operand).
}

#[derive(Debug)]
pub struct X86Op {
    pub ty: X86OpType,
    pub data: [u64; 3],
    pub size: u8,
    pub avx_bcase: u32,
    pub avx_zero_opmask: u32,
}

impl X86Op {
    pub fn data_imm(&self) -> i64 {
        unsafe { *mem::transmute::<&[u64; 3], &i64>(&self.data) }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct X86Detail {
    pub prefix: [::libc::uint8_t; 4],
    pub opcode: [::libc::uint8_t; 4],
    pub rex: ::libc::uint8_t,
    pub addr_size: ::libc::uint8_t,
    pub modrm: ::libc::uint8_t,
    pub sib: ::libc::uint8_t,
    pub disp: ::libc::uint32_t,
    pub sib_index: ::libc::uint32_t,
    pub sib_scale: ::libc::uint8_t,
    pub sib_base: ::libc::uint32_t,
    pub sse_cc: ::libc::uint32_t,
    pub avx_cc: ::libc::uint32_t,
    pub avx_sae: ::libc::uint8_t,
    pub avx_rm: ::libc::uint32_t,
    pub op_count: ::libc::uint8_t,
    pub operands: [X86Op; 8],
}

#[repr(C)]
#[derive(Debug)]
/// Capstone errors
pub enum CsErr {
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
