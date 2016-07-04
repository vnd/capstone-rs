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
        pub flags CsMode: u32 {
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
    #[derive(PartialEq, Eq)]
    pub struct CsOptValue(pub u32);
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

    pub arch_data: [u64; 185],
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
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMCC {
        ARM_CC_INVALID = 0,
        ARM_CC_EQ,            // Equal                      Equal
        ARM_CC_NE,            // Not equal                  Not equal, or unordered
        ARM_CC_HS,            // Carry set                  >, ==, or unordered
        ARM_CC_LO,            // Carry clear                Less than
        ARM_CC_MI,            // Minus, negative            Less than
        ARM_CC_PL,            // Plus, positive or zero     >, ==, or unordered
        ARM_CC_VS,            // Overflow                   Unordered
        ARM_CC_VC,            // No overflow                Not unordered
        ARM_CC_HI,            // Unsigned higher            Greater than, or unordered
        ARM_CC_LS,            // Unsigned lower or same     Less than or equal
        ARM_CC_GE,            // Greater than or equal      Greater than or equal
        ARM_CC_LT,            // Less than                  Less than, or unordered
        ARM_CC_GT,            // Greater than               Greater than
        ARM_CC_LE,            // Less than or equal         <, ==, or unordered
        ARM_CC_AL             // Always (unconditional)     Always (unconditional)
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMCPSMode {
        ARM_CPSMODE_INVALID = 0,
        ARM_CPSMODE_IE = 2,
        ARM_CPSMODE_ID = 3
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMCPSFlag {
        ARM_CPSFLAG_INVALID = 0,
        ARM_CPSFLAG_F = 1,
        ARM_CPSFLAG_I = 2,
        ARM_CPSFLAG_A = 4,
        ARM_CPSFLAG_NONE = 16,	// no flag
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMReg {
        ARM_REG_INVALID = 0,
        ARM_REG_APSR,
        ARM_REG_APSR_NZCV,
        ARM_REG_CPSR,
        ARM_REG_FPEXC,
        ARM_REG_FPINST,
        ARM_REG_FPSCR,
        ARM_REG_FPSCR_NZCV,
        ARM_REG_FPSID,
        ARM_REG_ITSTATE,
        ARM_REG_LR,
        ARM_REG_PC,
        ARM_REG_SP,
        ARM_REG_SPSR,
        ARM_REG_D0,
        ARM_REG_D1,
        ARM_REG_D2,
        ARM_REG_D3,
        ARM_REG_D4,
        ARM_REG_D5,
        ARM_REG_D6,
        ARM_REG_D7,
        ARM_REG_D8,
        ARM_REG_D9,
        ARM_REG_D10,
        ARM_REG_D11,
        ARM_REG_D12,
        ARM_REG_D13,
        ARM_REG_D14,
        ARM_REG_D15,
        ARM_REG_D16,
        ARM_REG_D17,
        ARM_REG_D18,
        ARM_REG_D19,
        ARM_REG_D20,
        ARM_REG_D21,
        ARM_REG_D22,
        ARM_REG_D23,
        ARM_REG_D24,
        ARM_REG_D25,
        ARM_REG_D26,
        ARM_REG_D27,
        ARM_REG_D28,
        ARM_REG_D29,
        ARM_REG_D30,
        ARM_REG_D31,
        ARM_REG_FPINST2,
        ARM_REG_MVFR0,
        ARM_REG_MVFR1,
        ARM_REG_MVFR2,
        ARM_REG_Q0,
        ARM_REG_Q1,
        ARM_REG_Q2,
        ARM_REG_Q3,
        ARM_REG_Q4,
        ARM_REG_Q5,
        ARM_REG_Q6,
        ARM_REG_Q7,
        ARM_REG_Q8,
        ARM_REG_Q9,
        ARM_REG_Q10,
        ARM_REG_Q11,
        ARM_REG_Q12,
        ARM_REG_Q13,
        ARM_REG_Q14,
        ARM_REG_Q15,
        ARM_REG_R0,
        ARM_REG_R1,
        ARM_REG_R2,
        ARM_REG_R3,
        ARM_REG_R4,
        ARM_REG_R5,
        ARM_REG_R6,
        ARM_REG_R7,
        ARM_REG_R8,
        ARM_REG_R9,
        ARM_REG_R10,
        ARM_REG_R11,
        ARM_REG_R12,
        ARM_REG_S0,
        ARM_REG_S1,
        ARM_REG_S2,
        ARM_REG_S3,
        ARM_REG_S4,
        ARM_REG_S5,
        ARM_REG_S6,
        ARM_REG_S7,
        ARM_REG_S8,
        ARM_REG_S9,
        ARM_REG_S10,
        ARM_REG_S11,
        ARM_REG_S12,
        ARM_REG_S13,
        ARM_REG_S14,
        ARM_REG_S15,
        ARM_REG_S16,
        ARM_REG_S17,
        ARM_REG_S18,
        ARM_REG_S19,
        ARM_REG_S20,
        ARM_REG_S21,
        ARM_REG_S22,
        ARM_REG_S23,
        ARM_REG_S24,
        ARM_REG_S25,
        ARM_REG_S26,
        ARM_REG_S27,
        ARM_REG_S28,
        ARM_REG_S29,
        ARM_REG_S30,
        ARM_REG_S31,

        ARM_REG_ENDING,		// <-- mark the end of the list or registers

        //> alias registers
        /*
        ARM_REG_R13 = ARM_REG_SP,
        ARM_REG_R14 = ARM_REG_LR,
        ARM_REG_R15 = ARM_REG_PC,

        ARM_REG_SB = ARM_REG_R9,
        ARM_REG_SL = ARM_REG_R10,
        ARM_REG_FP = ARM_REG_R11,
        ARM_REG_IP = ARM_REG_R12,
        */
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMSysreg {
        //> Special registers for MSR
        ARM_SYSREG_INVALID = 0,

        // SPSR* registers can be OR combined
        ARM_SYSREG_SPSR_C = 1,
        ARM_SYSREG_SPSR_X = 2,
        ARM_SYSREG_SPSR_S = 4,
        ARM_SYSREG_SPSR_F = 8,

        // CPSR* registers can be OR combined
        ARM_SYSREG_CPSR_C = 16,
        ARM_SYSREG_CPSR_X = 32,
        ARM_SYSREG_CPSR_S = 64,
        ARM_SYSREG_CPSR_F = 128,

        // independent registers
        ARM_SYSREG_APSR = 256,
        ARM_SYSREG_APSR_G,
        ARM_SYSREG_APSR_NZCVQ,
        ARM_SYSREG_APSR_NZCVQG,

        ARM_SYSREG_IAPSR,
        ARM_SYSREG_IAPSR_G,
        ARM_SYSREG_IAPSR_NZCVQG,

        ARM_SYSREG_EAPSR,
        ARM_SYSREG_EAPSR_G,
        ARM_SYSREG_EAPSR_NZCVQG,

        ARM_SYSREG_XPSR,
        ARM_SYSREG_XPSR_G,
        ARM_SYSREG_XPSR_NZCVQG,

        ARM_SYSREG_IPSR,
        ARM_SYSREG_EPSR,
        ARM_SYSREG_IEPSR,

        ARM_SYSREG_MSP,
        ARM_SYSREG_PSP,
        ARM_SYSREG_PRIMASK,
        ARM_SYSREG_BASEPRI,
        ARM_SYSREG_BASEPRI_MAX,
        ARM_SYSREG_FAULTMASK,
        ARM_SYSREG_CONTROL,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ARMInsn {
        ARM_INS_INVALID = 0,

        ARM_INS_ADC,
        ARM_INS_ADD,
        ARM_INS_ADR,
        ARM_INS_AESD,
        ARM_INS_AESE,
        ARM_INS_AESIMC,
        ARM_INS_AESMC,
        ARM_INS_AND,
        ARM_INS_BFC,
        ARM_INS_BFI,
        ARM_INS_BIC,
        ARM_INS_BKPT,
        ARM_INS_BL,
        ARM_INS_BLX,
        ARM_INS_BX,
        ARM_INS_BXJ,
        ARM_INS_B,
        ARM_INS_CDP,
        ARM_INS_CDP2,
        ARM_INS_CLREX,
        ARM_INS_CLZ,
        ARM_INS_CMN,
        ARM_INS_CMP,
        ARM_INS_CPS,
        ARM_INS_CRC32B,
        ARM_INS_CRC32CB,
        ARM_INS_CRC32CH,
        ARM_INS_CRC32CW,
        ARM_INS_CRC32H,
        ARM_INS_CRC32W,
        ARM_INS_DBG,
        ARM_INS_DMB,
        ARM_INS_DSB,
        ARM_INS_EOR,
        ARM_INS_VMOV,
        ARM_INS_FLDMDBX,
        ARM_INS_FLDMIAX,
        ARM_INS_VMRS,
        ARM_INS_FSTMDBX,
        ARM_INS_FSTMIAX,
        ARM_INS_HINT,
        ARM_INS_HLT,
        ARM_INS_ISB,
        ARM_INS_LDA,
        ARM_INS_LDAB,
        ARM_INS_LDAEX,
        ARM_INS_LDAEXB,
        ARM_INS_LDAEXD,
        ARM_INS_LDAEXH,
        ARM_INS_LDAH,
        ARM_INS_LDC2L,
        ARM_INS_LDC2,
        ARM_INS_LDCL,
        ARM_INS_LDC,
        ARM_INS_LDMDA,
        ARM_INS_LDMDB,
        ARM_INS_LDM,
        ARM_INS_LDMIB,
        ARM_INS_LDRBT,
        ARM_INS_LDRB,
        ARM_INS_LDRD,
        ARM_INS_LDREX,
        ARM_INS_LDREXB,
        ARM_INS_LDREXD,
        ARM_INS_LDREXH,
        ARM_INS_LDRH,
        ARM_INS_LDRHT,
        ARM_INS_LDRSB,
        ARM_INS_LDRSBT,
        ARM_INS_LDRSH,
        ARM_INS_LDRSHT,
        ARM_INS_LDRT,
        ARM_INS_LDR,
        ARM_INS_MCR,
        ARM_INS_MCR2,
        ARM_INS_MCRR,
        ARM_INS_MCRR2,
        ARM_INS_MLA,
        ARM_INS_MLS,
        ARM_INS_MOV,
        ARM_INS_MOVT,
        ARM_INS_MOVW,
        ARM_INS_MRC,
        ARM_INS_MRC2,
        ARM_INS_MRRC,
        ARM_INS_MRRC2,
        ARM_INS_MRS,
        ARM_INS_MSR,
        ARM_INS_MUL,
        ARM_INS_MVN,
        ARM_INS_ORR,
        ARM_INS_PKHBT,
        ARM_INS_PKHTB,
        ARM_INS_PLDW,
        ARM_INS_PLD,
        ARM_INS_PLI,
        ARM_INS_QADD,
        ARM_INS_QADD16,
        ARM_INS_QADD8,
        ARM_INS_QASX,
        ARM_INS_QDADD,
        ARM_INS_QDSUB,
        ARM_INS_QSAX,
        ARM_INS_QSUB,
        ARM_INS_QSUB16,
        ARM_INS_QSUB8,
        ARM_INS_RBIT,
        ARM_INS_REV,
        ARM_INS_REV16,
        ARM_INS_REVSH,
        ARM_INS_RFEDA,
        ARM_INS_RFEDB,
        ARM_INS_RFEIA,
        ARM_INS_RFEIB,
        ARM_INS_RSB,
        ARM_INS_RSC,
        ARM_INS_SADD16,
        ARM_INS_SADD8,
        ARM_INS_SASX,
        ARM_INS_SBC,
        ARM_INS_SBFX,
        ARM_INS_SDIV,
        ARM_INS_SEL,
        ARM_INS_SETEND,
        ARM_INS_SHA1C,
        ARM_INS_SHA1H,
        ARM_INS_SHA1M,
        ARM_INS_SHA1P,
        ARM_INS_SHA1SU0,
        ARM_INS_SHA1SU1,
        ARM_INS_SHA256H,
        ARM_INS_SHA256H2,
        ARM_INS_SHA256SU0,
        ARM_INS_SHA256SU1,
        ARM_INS_SHADD16,
        ARM_INS_SHADD8,
        ARM_INS_SHASX,
        ARM_INS_SHSAX,
        ARM_INS_SHSUB16,
        ARM_INS_SHSUB8,
        ARM_INS_SMC,
        ARM_INS_SMLABB,
        ARM_INS_SMLABT,
        ARM_INS_SMLAD,
        ARM_INS_SMLADX,
        ARM_INS_SMLAL,
        ARM_INS_SMLALBB,
        ARM_INS_SMLALBT,
        ARM_INS_SMLALD,
        ARM_INS_SMLALDX,
        ARM_INS_SMLALTB,
        ARM_INS_SMLALTT,
        ARM_INS_SMLATB,
        ARM_INS_SMLATT,
        ARM_INS_SMLAWB,
        ARM_INS_SMLAWT,
        ARM_INS_SMLSD,
        ARM_INS_SMLSDX,
        ARM_INS_SMLSLD,
        ARM_INS_SMLSLDX,
        ARM_INS_SMMLA,
        ARM_INS_SMMLAR,
        ARM_INS_SMMLS,
        ARM_INS_SMMLSR,
        ARM_INS_SMMUL,
        ARM_INS_SMMULR,
        ARM_INS_SMUAD,
        ARM_INS_SMUADX,
        ARM_INS_SMULBB,
        ARM_INS_SMULBT,
        ARM_INS_SMULL,
        ARM_INS_SMULTB,
        ARM_INS_SMULTT,
        ARM_INS_SMULWB,
        ARM_INS_SMULWT,
        ARM_INS_SMUSD,
        ARM_INS_SMUSDX,
        ARM_INS_SRSDA,
        ARM_INS_SRSDB,
        ARM_INS_SRSIA,
        ARM_INS_SRSIB,
        ARM_INS_SSAT,
        ARM_INS_SSAT16,
        ARM_INS_SSAX,
        ARM_INS_SSUB16,
        ARM_INS_SSUB8,
        ARM_INS_STC2L,
        ARM_INS_STC2,
        ARM_INS_STCL,
        ARM_INS_STC,
        ARM_INS_STL,
        ARM_INS_STLB,
        ARM_INS_STLEX,
        ARM_INS_STLEXB,
        ARM_INS_STLEXD,
        ARM_INS_STLEXH,
        ARM_INS_STLH,
        ARM_INS_STMDA,
        ARM_INS_STMDB,
        ARM_INS_STM,
        ARM_INS_STMIB,
        ARM_INS_STRBT,
        ARM_INS_STRB,
        ARM_INS_STRD,
        ARM_INS_STREX,
        ARM_INS_STREXB,
        ARM_INS_STREXD,
        ARM_INS_STREXH,
        ARM_INS_STRH,
        ARM_INS_STRHT,
        ARM_INS_STRT,
        ARM_INS_STR,
        ARM_INS_SUB,
        ARM_INS_SVC,
        ARM_INS_SWP,
        ARM_INS_SWPB,
        ARM_INS_SXTAB,
        ARM_INS_SXTAB16,
        ARM_INS_SXTAH,
        ARM_INS_SXTB,
        ARM_INS_SXTB16,
        ARM_INS_SXTH,
        ARM_INS_TEQ,
        ARM_INS_TRAP,
        ARM_INS_TST,
        ARM_INS_UADD16,
        ARM_INS_UADD8,
        ARM_INS_UASX,
        ARM_INS_UBFX,
        ARM_INS_UDF,
        ARM_INS_UDIV,
        ARM_INS_UHADD16,
        ARM_INS_UHADD8,
        ARM_INS_UHASX,
        ARM_INS_UHSAX,
        ARM_INS_UHSUB16,
        ARM_INS_UHSUB8,
        ARM_INS_UMAAL,
        ARM_INS_UMLAL,
        ARM_INS_UMULL,
        ARM_INS_UQADD16,
        ARM_INS_UQADD8,
        ARM_INS_UQASX,
        ARM_INS_UQSAX,
        ARM_INS_UQSUB16,
        ARM_INS_UQSUB8,
        ARM_INS_USAD8,
        ARM_INS_USADA8,
        ARM_INS_USAT,
        ARM_INS_USAT16,
        ARM_INS_USAX,
        ARM_INS_USUB16,
        ARM_INS_USUB8,
        ARM_INS_UXTAB,
        ARM_INS_UXTAB16,
        ARM_INS_UXTAH,
        ARM_INS_UXTB,
        ARM_INS_UXTB16,
        ARM_INS_UXTH,
        ARM_INS_VABAL,
        ARM_INS_VABA,
        ARM_INS_VABDL,
        ARM_INS_VABD,
        ARM_INS_VABS,
        ARM_INS_VACGE,
        ARM_INS_VACGT,
        ARM_INS_VADD,
        ARM_INS_VADDHN,
        ARM_INS_VADDL,
        ARM_INS_VADDW,
        ARM_INS_VAND,
        ARM_INS_VBIC,
        ARM_INS_VBIF,
        ARM_INS_VBIT,
        ARM_INS_VBSL,
        ARM_INS_VCEQ,
        ARM_INS_VCGE,
        ARM_INS_VCGT,
        ARM_INS_VCLE,
        ARM_INS_VCLS,
        ARM_INS_VCLT,
        ARM_INS_VCLZ,
        ARM_INS_VCMP,
        ARM_INS_VCMPE,
        ARM_INS_VCNT,
        ARM_INS_VCVTA,
        ARM_INS_VCVTB,
        ARM_INS_VCVT,
        ARM_INS_VCVTM,
        ARM_INS_VCVTN,
        ARM_INS_VCVTP,
        ARM_INS_VCVTT,
        ARM_INS_VDIV,
        ARM_INS_VDUP,
        ARM_INS_VEOR,
        ARM_INS_VEXT,
        ARM_INS_VFMA,
        ARM_INS_VFMS,
        ARM_INS_VFNMA,
        ARM_INS_VFNMS,
        ARM_INS_VHADD,
        ARM_INS_VHSUB,
        ARM_INS_VLD1,
        ARM_INS_VLD2,
        ARM_INS_VLD3,
        ARM_INS_VLD4,
        ARM_INS_VLDMDB,
        ARM_INS_VLDMIA,
        ARM_INS_VLDR,
        ARM_INS_VMAXNM,
        ARM_INS_VMAX,
        ARM_INS_VMINNM,
        ARM_INS_VMIN,
        ARM_INS_VMLA,
        ARM_INS_VMLAL,
        ARM_INS_VMLS,
        ARM_INS_VMLSL,
        ARM_INS_VMOVL,
        ARM_INS_VMOVN,
        ARM_INS_VMSR,
        ARM_INS_VMUL,
        ARM_INS_VMULL,
        ARM_INS_VMVN,
        ARM_INS_VNEG,
        ARM_INS_VNMLA,
        ARM_INS_VNMLS,
        ARM_INS_VNMUL,
        ARM_INS_VORN,
        ARM_INS_VORR,
        ARM_INS_VPADAL,
        ARM_INS_VPADDL,
        ARM_INS_VPADD,
        ARM_INS_VPMAX,
        ARM_INS_VPMIN,
        ARM_INS_VQABS,
        ARM_INS_VQADD,
        ARM_INS_VQDMLAL,
        ARM_INS_VQDMLSL,
        ARM_INS_VQDMULH,
        ARM_INS_VQDMULL,
        ARM_INS_VQMOVUN,
        ARM_INS_VQMOVN,
        ARM_INS_VQNEG,
        ARM_INS_VQRDMULH,
        ARM_INS_VQRSHL,
        ARM_INS_VQRSHRN,
        ARM_INS_VQRSHRUN,
        ARM_INS_VQSHL,
        ARM_INS_VQSHLU,
        ARM_INS_VQSHRN,
        ARM_INS_VQSHRUN,
        ARM_INS_VQSUB,
        ARM_INS_VRADDHN,
        ARM_INS_VRECPE,
        ARM_INS_VRECPS,
        ARM_INS_VREV16,
        ARM_INS_VREV32,
        ARM_INS_VREV64,
        ARM_INS_VRHADD,
        ARM_INS_VRINTA,
        ARM_INS_VRINTM,
        ARM_INS_VRINTN,
        ARM_INS_VRINTP,
        ARM_INS_VRINTR,
        ARM_INS_VRINTX,
        ARM_INS_VRINTZ,
        ARM_INS_VRSHL,
        ARM_INS_VRSHRN,
        ARM_INS_VRSHR,
        ARM_INS_VRSQRTE,
        ARM_INS_VRSQRTS,
        ARM_INS_VRSRA,
        ARM_INS_VRSUBHN,
        ARM_INS_VSELEQ,
        ARM_INS_VSELGE,
        ARM_INS_VSELGT,
        ARM_INS_VSELVS,
        ARM_INS_VSHLL,
        ARM_INS_VSHL,
        ARM_INS_VSHRN,
        ARM_INS_VSHR,
        ARM_INS_VSLI,
        ARM_INS_VSQRT,
        ARM_INS_VSRA,
        ARM_INS_VSRI,
        ARM_INS_VST1,
        ARM_INS_VST2,
        ARM_INS_VST3,
        ARM_INS_VST4,
        ARM_INS_VSTMDB,
        ARM_INS_VSTMIA,
        ARM_INS_VSTR,
        ARM_INS_VSUB,
        ARM_INS_VSUBHN,
        ARM_INS_VSUBL,
        ARM_INS_VSUBW,
        ARM_INS_VSWP,
        ARM_INS_VTBL,
        ARM_INS_VTBX,
        ARM_INS_VCVTR,
        ARM_INS_VTRN,
        ARM_INS_VTST,
        ARM_INS_VUZP,
        ARM_INS_VZIP,
        ARM_INS_ADDW,
        ARM_INS_ASR,
        ARM_INS_DCPS1,
        ARM_INS_DCPS2,
        ARM_INS_DCPS3,
        ARM_INS_IT,
        ARM_INS_LSL,
        ARM_INS_LSR,
        ARM_INS_ASRS,
        ARM_INS_LSRS,
        ARM_INS_ORN,
        ARM_INS_ROR,
        ARM_INS_RRX,
        ARM_INS_SUBS,
        ARM_INS_SUBW,
        ARM_INS_TBB,
        ARM_INS_TBH,
        ARM_INS_CBNZ,
        ARM_INS_CBZ,
        ARM_INS_MOVS,
        ARM_INS_POP,
        ARM_INS_PUSH,

        // special instructions
        ARM_INS_NOP,
        ARM_INS_YIELD,
        ARM_INS_WFE,
        ARM_INS_WFI,
        ARM_INS_SEV,
        ARM_INS_SEVL,
        ARM_INS_VPUSH,
        ARM_INS_VPOP,

        ARM_INS_ENDING,	// <-- mark the end of the list of instructions
    }

    #[repr(C)]
    #[derive(Debug, PartialEq)]
    pub struct ARMOpMem {
        pub base: u32,
        pub index: u32,
        pub scale: i32,
        pub disp: i32,
    }

    #[repr(C)]
    #[derive(Debug, PartialEq)]
    pub enum ARMShifter {
        ARM_SFT_INVALID = 0,
        ARM_SFT_ASR,	// shift with immediate const
        ARM_SFT_LSL,	// shift with immediate const
        ARM_SFT_LSR,	// shift with immediate const
        ARM_SFT_ROR,	// shift with immediate const
        ARM_SFT_RRX,	// shift with immediate const
        ARM_SFT_ASR_REG,	// shift with register
        ARM_SFT_LSL_REG,	// shift with register
        ARM_SFT_LSR_REG,	// shift with register
        ARM_SFT_ROR_REG,	// shift with register
        ARM_SFT_RRX_REG,	// shift with register
    }

    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct ARMOp {
        pub vector_index: i32,
        pub shift_type: u32,
        pub shift_value: u32,
        pub ty: ARMOpType,
        pub data: [u64; 2],
        pub subtracted: bool,
    }

    #[derive(Debug, PartialEq)]
    /// Instruction operand data for ARM
    pub enum ARMOpData {
        /// Immediate operand
        Imm(u32),
        Reg(ARMReg),
        Sysreg(ARMSysreg),
        Mem(ARMOpMem),
        Other,
    }

    impl ARMOp {
        unsafe fn data_raw(&self) -> u32 {
            *mem::transmute::<&[u64; 2], &u32>(&self.data)
        }
        pub unsafe fn shifter(&self) -> ARMShifter {
            mem::transmute(self.shift_type)
        }
        pub fn data(&self) -> ARMOpData {
            match self.ty {
                ARMOpType::ARM_OP_IMM => ARMOpData::Imm(unsafe { self.data_raw() }),
                ARMOpType::ARM_OP_REG => ARMOpData::Reg(unsafe { mem::transmute( self.data_raw()) }),
                ARMOpType::ARM_OP_SYSREG => ARMOpData::Sysreg(unsafe { mem::transmute(self.data_raw())}),
                ARMOpType::ARM_OP_MEM => ARMOpData::Mem(unsafe { mem::transmute(self.data)}),
                ARMOpType::ARM_OP_PIMM => ARMOpData::Imm(unsafe { self.data_raw() }),
                ARMOpType::ARM_OP_CIMM => ARMOpData::Imm(unsafe { self.data_raw() }),
                _ => ARMOpData::Other, // TODO this
            }
        }
    }

    #[repr(C)]
    pub struct ARMDetail {
        pub usermode: bool,
        pub vector_size: i32,
        pub vector_data: u32,
        pub cps_mode: ARMCPSMode,
        pub cps_flag: ARMCPSFlag,
        pub cc: ARMCC,
        pub update_flags: bool,
        pub writeback: bool,
        pub mem_barrier: u32,
        pub op_count: u32,
        pub operands: [ARMOp; 36],
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
    pub id: ::libc::c_uint,
    pub address: u64,
    size: u16,
    pub bytes: [u8; 16usize],
    mnemonic: [::libc::c_char; 32usize],
    op_str: [::libc::c_char; 160usize],
    pub detail: *mut InsnDetail,
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
        // ID 0 is skipdata
        if self.detail.is_null() || self.id == 0 {
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
        match cs_option(csh, opt, val.0) {
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
    pub fn cs_option(handle: CsHandle, opt: CsOptType, val: u32) -> ::CsError;
    pub fn cs_errno(handle: CsHandle) -> ::CsError;
    pub fn cs_group_name(handle: CsHandle, name: CsGroup) -> *const libc::c_char;
    pub fn cs_strerror(code: ::CsError) -> *const libc::c_char;
}
