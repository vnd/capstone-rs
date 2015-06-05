#[repr(C)]
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
