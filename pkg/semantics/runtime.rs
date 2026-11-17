//! Architecture-neutral, typed scalar and native atomic instruction semantics.
//! Ordinary reads observe incoming state. Ordered atomic operations expose
//! typed results to subsequent operations and recipe expressions, with explicit
//! ordering, scope, endian and exclusive-monitor outcomes. Scalar outputs are
//! pending writes; traps terminate later outputs, and pipeline updates retain
//! their explicit predication contract. Barriers and monitor clears remain
//! ordered events. The consumer owns ordinary memory faults, architectural FP
//! execution (including explicit x87 chunk operations), pointer authentication
//! under explicit guest key/address configuration, and atomic observation/commit
//! capability. No host FP environment,
//! plain-memory atomic fallback, interrupt or timing behavior is assumed.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Register {
    pub bank: &'static str,
    pub index: u16,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterSlice {
    pub register: Register,
    pub offset: u8,
    pub width: u8,
    pub parent_width: u8,
}
/// A finite, strided bank of architectural register slices. The concrete
/// register is `bank[base + UInt(index) * stride]`; the index is never wrapped.
/// Each selected parent is a scalar chunk (1..64 bits), even when the bank is
/// a chunked view of wider native state such as an A64 ZA row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexedRegister {
    pub bank: &'static str,
    pub base: u16,
    pub stride: u16,
    pub count: u16,
    pub index: Box<Expr>,
    pub offset: u16,
    pub width: u8,
    pub parent_width: u16,
}
impl IndexedRegister {
    fn valid_dimensions(&self) -> bool {
        !self.bank.is_empty()
            && self.count != 0
            && self.stride != 0
            && self.parent_width > 0
            && self.parent_width <= 64
            && self.width > 0
            && self.width <= 64
            && u32::from(self.offset) + u32::from(self.width) <= u32::from(self.parent_width)
            && (1..=64).contains(&self.index.ty.width)
            && u32::from(self.base)
                + u32::from(self.count.saturating_sub(1)) * u32::from(self.stride)
                <= u32::from(u16::MAX)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signedness {
    Unsigned,
    Signed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Type {
    pub width: u8,
    pub signedness: Signedness,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Little,
    Big,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritePolicy {
    Preserve,
    ZeroUpper,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOp {
    Add,
    Sub,
    Mul,
    /// Total division: zero divisor produces zero; signed overflow wraps.
    Udiv,
    Sdiv,
    Urem,
    Srem,
    UnsignedMultiplyHigh,
    SignedMultiplyHigh,
    And,
    Or,
    Xor,
    Shl,
    Lsr,
    Asr,
    Ror,
    Eq,
    Ult,
    Slt,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOp {
    Not,
    Neg,
    Parity,
    CountLeadingZeros,
    PopulationCount,
    ReverseBits,
    ReverseBytes,
}
/// IEEE value operation, evaluated under explicit architectural controls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatOperation {
    Add,
    Subtract,
    Multiply,
    Divide,
    SquareRoot,
    /// Inputs are addend, multiplicand, multiplier. One rounding only;
    /// sign changes follow the selected architecture's NaN rules.
    FusedMultiplyAdd { negate_product: bool, negate_addend: bool },
    /// A64 FPMulAddH: binary32 addend followed by two binary16
    /// multiplicands, rounded once to binary32. Preserves FPProcessNaNs3H
    /// priority and the separate FPCR.FZ16 input policy. Currently source16 only.
    WideningFusedMultiplyAdd { source_width: u8 },
    /// Four-bit NZCV result (N at bit 3); input format is source_width.
    Compare { source_width: u8, signal_all_nans: bool },
    Convert { source_width: u8, round_to_odd: bool },
    ToInteger { source_width: u8, signed: bool, fractional_bits: u8, rounding: FloatRounding },
    FromInteger { source_width: u8, signed: bool, fractional_bits: u8 },
    MinMax { minimum: bool, numeric: bool },
    RoundToIntegral { rounding: FloatRounding, exact: bool },
    ReciprocalEstimate,
    ReciprocalSquareRootEstimate,
    ReciprocalExponent,
    ReciprocalStep,
    ReciprocalSquareRootStep,
    MultiplyExtended,
    /// x86 GETEXP: unbiased exponent as an IEEE value; half subnormals
    /// normalize and raise DE regardless of DAZ, wider inputs honor DAZ.
    GetExponent,
    /// AVX512-FP16 estimate representative, independent of MXCSR. The native
    /// backend selects nearest-even and rejects inputs for which no half
    /// result meets the documented relative bound. Currently binary16 only.
    X86ReciprocalEstimate,
    X86ReciprocalSquareRootEstimate,
    /// x86 SCALEF: input0 * 2^floor(input1), with unbounded conceptual scaling.
    Scale,
    /// x86 REDUCE: x - 2^-scale * round_integer(x * 2^scale).
    Reduce { scale: u8, rounding: FloatRounding, exact: bool },
    /// x86 RNDSCALE: 2^-scale * round_integer(x * 2^scale).
    RoundScale { scale: u8, rounding: FloatRounding, exact: bool },
    /// x86 GETMANT's two-bit interval and two-bit sign-control selectors.
    GetMantissa { interval: u8, sign_control: u8 },
    /// IEEE binary32 input, explicitly bfloat16 output (not IEEE half).
    ToBFloat16,
    /// Inputs: acc32, a0bf16, a1bf16, b0bf16, b1bf16; effective FPCR.EBF
    /// selects standard or enhanced BF16 dot arithmetic.
    BFloatDotAdd,
    BFloatBinary { operation: BFloatOperation },
    /// Inputs: addendbf16, op1bf16, op2bf16.
    BFloatFused,
    /// Operand and FPMR64; FPCR/FPSR remain explicit architectural inputs.
    /// FP8 widens to half/BF16; half/single narrow to FP8.
    Fp8Convert { source_width: u8, bfloat: bool, source2: bool },
    /// Fused binary32 accumulator plus two BF16 operands. ZA suppresses exceptions and forces DN.
    BFloatWideningFused { za: bool },
    /// FP8 widening fused accumulate: addend16/32, two FP8 operands, FPMR64. No exceptions.
    Fp8WideningFused,
    /// Exact FP8 dot with packed byte operands and a single final rounding.
    Fp8Dot {ways:u8},
    /// Non-widening ZA add/sub: forced default NaNs and suppressed exceptions.
    ZaBinary {bfloat:bool,subtract:bool},
    /// ZA non-widening fused multiply accumulate, one final rounding.
    ZaFused {bfloat:bool},
    /// FP16 pair dot rounded to FP32, then add to the ZA accumulator.
    ZaHalfDot,
    /// Four half operands, pairwise products summed exactly and rounded to binary32.
    HalfDotProduct,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BFloatOperation { Add, Subtract, Multiply, Maximum, Minimum, MaximumNumber, MinimumNumber }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatRounding {
    Environment,
    NearestEven,
    PositiveInfinity,
    NegativeInfinity,
    Zero,
    NearestAway,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatEnvironment {
    A64,
    A32Vfp,
    A32Neon,
    X86Mxcsr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FloatProjection {
    Value,
    Status,
    Trapped,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FloatExpression {
    pub operation: FloatOperation,
    pub environment: FloatEnvironment,
    pub width: u8,
    pub inputs: Vec<Expr>,
    pub control: Box<Expr>,
    pub status: Box<Expr>,
    pub projection: FloatProjection,
}
/// Closed extended-precision arithmetic; no integer or host-FP approximation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X87BinaryOperation {
    Add,
    Subtract,
    Multiply,
    Divide,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X87MathOperation {
    SquareRoot,
    Round,
    Scale,
    Remainder,
    RemainderNearest,
    Extract,
    Sine,
    Cosine,
    SineCosine,
    Tangent,
    Arctangent,
    Exp2MinusOne,
    YLog2X,
    YLog2XPlusOne,
    Examine,
}
impl X87MathOperation {
    pub const fn arity(self) -> usize {
        match self {
            Self::Scale
            | Self::Remainder
            | Self::RemainderNearest
            | Self::Arctangent
            | Self::YLog2X
            | Self::YLog2XPlusOne => 2,
            _ => 1,
        }
    }
    pub const fn pops(self) -> bool {
        matches!(self, Self::Arctangent | Self::YLog2X | Self::YLog2XPlusOne)
    }
    pub const fn pushes(self) -> bool {
        matches!(self, Self::Extract | Self::SineCosine | Self::Tangent)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X87Constant {
    Pi,
    Log2E,
    Log2Ten,
    Log10Two,
    LnTwo,
}
/// The ISA owner's coupled x87 algebra. Register numbers and tag pairs refer
/// to logical ST0..ST7. Stack movement, tags, exceptions and commit belong to
/// the same deterministic operation, not independent arithmetic callbacks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X87Operation {
    Binary {
        operation: X87BinaryOperation,
        source_width: u8,
        reverse: bool,
        destination_register: u8,
        source_register: Option<u8>,
        pop: bool,
    },
    LoadFloat {
        source_width: u8,
    },
    LoadInteger {
        source_width: u8,
    },
    StoreFloat {
        destination_width: u8,
        pop: bool,
    },
    StoreInteger {
        destination_width: u8,
        pop: bool,
    },
    Unary {
        negate: bool,
        register: u8,
    },
    Exchange {
        register: u8,
    },
    Compare {
        ordered: bool,
        pop: bool,
        left_register: u8,
        right_register: u8,
    },
    Math {
        operation: X87MathOperation,
    },
    LoadConstant {
        constant: X87Constant,
    },
    LoadRegister {
        register: u8,
    },
    StoreRegister {
        register: u8,
        pop: bool,
    },
    StoreTruncatedInteger {
        destination_width: u8,
    },
    LoadBcd,
    StoreBcd,
    CompareStatus {
        ordered: bool,
        source_width: u8,
        source_register: Option<u8>,
        pops: u8,
    },
    ConditionalMove {
        register: u8,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X87CompareFlag {
    Zero,
    Parity,
    Carry,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X87Projection {
    /// An available logical 80-bit result: chunk 0 is low64, chunk 1 high16.
    Result {
        register: u8,
        chunk: u8,
    },
    /// One chunk of the operation's memory result, low bits first.
    Store {
        chunk: u8,
    },
    Status,
    Tags,
    Commit,
    CompareFlag(X87CompareFlag),
}
impl X87Operation {
    /// Ordered logical operand widths, before the separate 16-bit environment.
    /// None means a malformed closed operation (invalid register/format/pops).
    pub fn input_widths(self) -> Option<Vec<u8>> {
        let integer = |w| matches!(w, 16 | 32 | 64);
        let float = |w| matches!(w, 32 | 64 | 80);
        match self {
            Self::Binary {
                source_width,
                destination_register,
                source_register,
                ..
            } if float(source_width)
                && destination_register < 8
                && source_register.is_none_or(|r| r < 8) =>
            {
                Some(vec![80, source_width])
            }
            Self::LoadFloat { source_width } if float(source_width) => Some(vec![source_width]),
            Self::LoadInteger { source_width } if integer(source_width) => Some(vec![source_width]),
            Self::StoreFloat {
                destination_width, ..
            } if float(destination_width) => Some(vec![80]),
            Self::StoreInteger {
                destination_width, ..
            }
            | Self::StoreTruncatedInteger { destination_width }
                if integer(destination_width) =>
            {
                Some(vec![80])
            }
            Self::Unary { register, .. }
            | Self::LoadRegister { register }
            | Self::StoreRegister { register, .. }
                if register < 8 =>
            {
                Some(vec![80])
            }
            Self::Exchange { register } if register < 8 => Some(vec![80, 80]),
            Self::Compare {
                left_register,
                right_register,
                ..
            } if left_register < 8 && right_register < 8 => Some(vec![80, 80]),
            Self::Math { operation } => Some(vec![80; operation.arity()]),
            Self::LoadConstant { .. } => Some(vec![]),
            Self::LoadBcd | Self::StoreBcd => Some(vec![80]),
            Self::CompareStatus {
                source_width,
                source_register,
                pops,
                ..
            } if float(source_width) && source_register.is_none_or(|r| r < 8) && pops <= 2 => {
                Some(vec![80, source_width])
            }
            Self::ConditionalMove { register } if register < 8 => Some(vec![80, 80, 1]),
            _ => None,
        }
    }
    /// Logical result registers permitted by this operation. Availability can
    /// still depend on commit or (for trig pushes) the resulting C2 status bit.
    pub fn result_registers(self) -> u8 {
        if self.input_widths().is_none() {
            return 0;
        }
        match self {
            Self::Binary {
                destination_register,
                ..
            } => 1 << destination_register,
            Self::LoadFloat { .. }
            | Self::LoadInteger { .. }
            | Self::LoadConstant { .. }
            | Self::LoadRegister { .. }
            | Self::LoadBcd
            | Self::ConditionalMove { .. } => 1,
            Self::Unary { register, .. } | Self::StoreRegister { register, .. } => 1 << register,
            Self::Exchange { register } => (1 << register) | 1,
            Self::Math { operation } => {
                if operation == X87MathOperation::Examine {
                    0
                } else if operation.pushes() {
                    3
                } else {
                    1 << u8::from(operation.pops())
                }
            }
            _ => 0,
        }
    }
    pub fn store_width(self) -> Option<u8> {
        match self {
            Self::StoreFloat {
                destination_width, ..
            }
            | Self::StoreInteger {
                destination_width, ..
            }
            | Self::StoreTruncatedInteger { destination_width }
                if self.input_widths().is_some() =>
            {
                Some(destination_width)
            }
            Self::StoreBcd => Some(80),
            _ => None,
        }
    }
    pub fn projection_width(self, projection: X87Projection) -> Option<u8> {
        self.input_widths()?;
        match projection {
            X87Projection::Result { register, chunk }
                if register < 8 && self.result_registers() & (1 << register) != 0 =>
            {
                x87_chunk_width(80, chunk)
            }
            X87Projection::Store { chunk } => x87_chunk_width(self.store_width()?, chunk),
            X87Projection::Status | X87Projection::Tags => Some(16),
            X87Projection::Commit => Some(1),
            X87Projection::CompareFlag(_) if matches!(self, Self::Compare { .. }) => Some(1),
            _ => None,
        }
    }
}
fn x87_chunk_width(width: u8, chunk: u8) -> Option<u8> {
    match (width, chunk) {
        (80, 0) => Some(64),
        (80, 1) => Some(16),
        (1..=64, 0) => Some(width),
        _ => None,
    }
}
/// One logical operand. Formats are determined by X87Operation; an 80-bit
/// float or packed BCD value is transported as exactly [low64, high16].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X87Operand {
    pub width: u8,
    pub chunks: Vec<Expr>,
}
impl X87Operand {
    pub fn scalar(value: Expr) -> Self {
        Self {
            width: value.ty.width,
            chunks: vec![value],
        }
    }
    pub fn extended(low: Expr, high: Expr) -> Self {
        Self {
            width: 80,
            chunks: vec![low, high],
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X87Expression {
    pub operation: X87Operation,
    pub inputs: Vec<X87Operand>,
    pub control: Box<Expr>,
    pub status: Box<Expr>,
    /// Complete logical ST0..ST7 tag word, not an abridged physical bitmap.
    pub tags: Box<Expr>,
    pub projection: X87Projection,
}
impl X87Expression {
    pub fn validate_dimensions(&self) -> Result<u8, EvalError> {
        let expected = self
            .operation
            .input_widths()
            .ok_or(EvalError::InvalidExpression)?;
        if self.inputs.len() != expected.len()
            || self.control.ty.width != 16
            || self.status.ty.width != 16
            || self.tags.ty.width != 16
        {
            return Err(EvalError::InvalidExpression);
        }
        for (input, width) in self.inputs.iter().zip(expected) {
            let chunks = if width == 80 { 2 } else { 1 };
            if input.width != width
                || input.chunks.len() != chunks
                || input
                    .chunks
                    .iter()
                    .enumerate()
                    .any(|(i, c)| Some(c.ty.width) != x87_chunk_width(width, i as u8))
            {
                return Err(EvalError::InvalidExpression);
            }
        }
        self.operation
            .projection_width(self.projection)
            .ok_or(EvalError::InvalidExpression)
    }
}

/// Closed A64 operations; configuration/keys/VA/TBI are explicit backend
/// capabilities. Generic authentication computes a code, never a pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerAuthOperation { Sign, Authenticate, Strip, StripData, Generic }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PointerAuthKey { InstructionA, InstructionB, DataA, DataB, None, Generic }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointerAuthenticationExpression {
    pub operation: PointerAuthOperation,
    pub key: PointerAuthKey,
    pub inputs: Vec<Expr>,
}
impl PointerAuthenticationExpression {
    fn valid_dimensions(&self) -> bool {
        let arity = self.inputs.len();
        self.inputs.iter().all(|input| input.ty.width == 64) && match self.operation {
            PointerAuthOperation::Strip | PointerAuthOperation::StripData => self.key == PointerAuthKey::None && arity == 1,
            PointerAuthOperation::Generic => self.key == PointerAuthKey::Generic && arity == 2,
            PointerAuthOperation::Sign | PointerAuthOperation::Authenticate => {
                matches!(self.key,PointerAuthKey::InstructionA|PointerAuthKey::InstructionB|PointerAuthKey::DataA|PointerAuthKey::DataB)
                && (arity == 2 || (arity == 3 && matches!(self.key,PointerAuthKey::InstructionA|PointerAuthKey::InstructionB)))
            }
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expr {
    pub ty: Type,
    pub kind: ExprKind,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExprKind {
    PointerAuthentication(PointerAuthenticationExpression),
    Constant(u64),
    Register(RegisterSlice),
    /// A selected incoming-state read from an explicit finite register bank.
    IndexedRegister(IndexedRegister),
    Temporary(usize),
    /// A result from an earlier ordered atomic step, evaluated exactly once.
    AtomicResult {
        step: usize,
        projection: AtomicProjection,
    },
    /// Numeric chunk of one original-width ordinary memory read.
    WideLoadChunk { step: usize, chunk: usize },
    /// Success of an earlier ordered read. A skipped read is unavailable.
    WideLoadSuccess { step: usize },
    /// One explicitly supplied entropy choice, captured once before outputs.
    ChoiceResult { step: usize },
    Undefined(&'static str),
    /// Reject an unsupported execution context without choosing architecture
    /// behavior nondeterministically. Evaluated only when this node is selected.
    RequireContext {
        condition: Box<Expr>,
        reason: &'static str,
    },
    Unary {
        op: UnaryOp,
        value: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Cast {
        value: Box<Expr>,
        signed: bool,
    },
    Extract {
        value: Box<Expr>,
        offset: u8,
    },
    Select {
        condition: Box<Expr>,
        yes: Box<Expr>,
        no: Box<Expr>,
    },
    Load(Memory),
    /// Four-bit allocation metadata for one 16-byte Arm tag granule. It is
    /// distinct from data memory even at an identical numeric address.
    LoadAllocationTag { address: Box<Expr>, privilege: MemoryPrivilege },
    Float(FloatExpression),
    X87(X87Expression),
    AddCarry {
        left: Box<Expr>,
        right: Box<Expr>,
        carry: Box<Expr>,
    },
    SubBorrow {
        left: Box<Expr>,
        right: Box<Expr>,
        borrow: Box<Expr>,
    },
    Overflow {
        subtract: bool,
        left: Box<Expr>,
        right: Box<Expr>,
        result: Box<Expr>,
    },
}
/// Architectural privilege-selection policy retained by every access.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryPrivilege {
    #[default]
    Current,
    /// Resolve AArch64_IsUnprivAccessPriv, including EL, nested virtualization
    /// and UAO overrides. This is not an ordinary current-privilege transfer.
    AArch64Unprivileged,
}
/// Target access identity, independent of privilege and byte order.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryKind {
    #[default]
    Data,
    GuardedControlStack,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Memory {
    pub kind: MemoryKind,
    pub privilege: MemoryPrivilege,
    pub address: Box<Expr>,
    pub width: u8,
    pub endian: Endian,
}
/// Closed architectural memory-fault classes. Generic backend failures and
/// missing capabilities must never be reported as a recoverable memory fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MemoryFaultKind {
    Translation,
    Permission,
    Alignment,
    Access,
    TagCheck,
    ExternalAbort,
    Atomicity,
}
/// One original-width ordinary access. Numeric chunks run least-significant
/// first; endian serializes the complete value. No atomicity is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WideMemory {
    pub kind: MemoryKind,
    pub privilege: MemoryPrivilege,
    pub address: Box<Expr>,
    pub width: u16,
    pub endian: Endian,
}
impl WideMemory {
    pub fn chunk_width(&self, chunk: usize) -> Option<u8> {
        let offset = chunk.checked_mul(64)?;
        (offset < usize::from(self.width))
            .then(|| (usize::from(self.width) - offset).min(64) as u8)
    }
    pub fn chunk_count(&self) -> usize { usize::from(self.width).div_ceil(64) }
    fn valid_width(&self) -> bool {
        self.kind==MemoryKind::Data && self.width > 64 && self.width <= 2048 && self.width % 8 == 0
    }
    fn valid_read_width(&self) -> bool {
        self.width > 0 && self.width <= 2048 && self.width % 8 == 0 && (self.kind==MemoryKind::Data || self.width==64)
    }
}
/// Atomic modification order and synchronization are never inferred from the
/// host or replaced with ordinary loads/stores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryOrdering {
    Monotonic,
    Acquire,
    Release,
    AcquireRelease,
    SequentiallyConsistent,
    /// Arm acquire-RCpc: local acquire ordering without RCsc cumulativity.
    AcquireRcpc,
    /// Arm limited-order acquire, governed by the configured LORegions.
    AcquireLimited,
    /// Arm limited-order release, governed by the configured LORegions.
    ReleaseLimited,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryScope {
    System,
    SingleThread,
    Named(&'static str),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicRmwOp {
    Exchange,
    Add,
    Subtract,
    And,
    Or,
    Xor,
    SignedMax,
    SignedMin,
    UnsignedMax,
    UnsignedMin,
}
/// Closed LSFE floating read-modify-write domain.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum AtomicFloatRmwOp { Add, Maximum, Minimum, MaximumNumber, MinimumNumber }
/// Closed pair RMW domain. Each operation is one indivisible 128-bit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicPairRmwOp { Exchange, And, Or }
/// Arm RCW update before the explicit hard/soft protection checks.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum AtomicRcwOp { Clear, Set, Exchange, CompareExchange }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicOperationKind {
    /// One indivisible 128-bit access. Chunks are numeric bits 0..63 and
    /// 64..127; memory.endian controls serialization of the whole value.
    LoadPair,
    ReadModifyWritePair { operation: AtomicPairRmwOp, low: Expr, high: Expr },
    StorePair { low: Expr, high: Expr },
    CompareExchangePair {
        expected_low: Expr,
        expected_high: Expr,
        replacement_low: Expr,
        replacement_high: Expr,
        failure_ordering: MemoryOrdering,
    },
    LoadLinkedPair,
    /// Two 64-bit observations tied to one 128-bit exclusive reservation.
    /// This access does not promise pair single-copy atomicity.
    LoadLinkedPairSplit,
    StoreConditionalPair { low: Expr, high: Expr },
    Load,
    Store {
        value: Expr,
    },
    ReadModifyWrite {
        operation: AtomicRmwOp,
        value: Expr,
    },
    /// Arm MemAtomicFP. Source and FPCR are independent explicit inputs;
    /// no host FP environment, FPSR write or non-atomic fallback is permitted.
    FloatingPointReadModifyWrite { operation: AtomicFloatRmwOp, bfloat: bool, value: Expr, control: Expr },
    /// One RCW event, with effective numeric masks and explicit protection state.
    /// Both chunks are always 64 bits; scalar forms require zero high chunks.
    RestrictedReadModifyWrite { operation: AtomicRcwOp, soft: bool, expected: [Expr;2], operand: [Expr;2], mask: [Expr;2], soft_mask: [Expr;2], protection: Expr },
    /// Strong CAS: comparison failure is the only unsuccessful outcome.
    CompareExchange {
        expected: Expr,
        replacement: Expr,
        failure_ordering: MemoryOrdering,
    },
    LoadLinked,
    /// Success is a one-bit true value, independent of an ISA's status encoding.
    StoreConditional {
        value: Expr,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicOperation {
    pub memory: Memory,
    pub ordering: MemoryOrdering,
    pub scope: MemoryScope,
    pub kind: AtomicOperationKind,
}
/// One architectural LS64 transfer. Chunks are address-ordered little-endian
/// words; the instruction builder applies each word's guest byte order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Block64Kind {
    Load,
    Store { chunks: [Expr; 8], with_status: bool },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block64Operation { pub address: Expr, pub tagchecked:bool, pub kind: Block64Kind }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Block64RequestKind { Load, Store { chunks: [Value;8], with_status: bool } }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block64Request { pub address:u64, pub tagchecked:bool, pub kind:Block64RequestKind }
/// The provider observes once and stages any write; it must not commit guest
/// state until its enclosing transition commits. A witness identifies this
/// single indivisible event. No eight-access fallback is permitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Block64Observation {
    Load {chunks:[Value;8], clear_reservation:bool, witness:u64},
    Store {status:Option<Value>, committed:bool, clear_reservation:bool, witness:u64},
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block64Transition {pub request:Block64Request,pub observation:Block64Observation}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicStep {
    Block64(Block64Operation),
    Memory(AtomicOperation),
    ClearExclusive,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicProjection {
    BlockChunk(u8),
    Value,
    ValueHigh,
    Success,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicResults {
    pub value: Option<Expr>,
    pub value_high: Option<Expr>,
    pub success: Option<Expr>,
}
impl AtomicOperation {
    fn result_type(&self, projection: AtomicProjection) -> Option<Type> {
        if matches!(self.kind, AtomicOperationKind::RestrictedReadModifyWrite { .. }) {
            return match projection {
                AtomicProjection::Value => Some(Type {width:64,signedness:Signedness::Unsigned}),
                AtomicProjection::ValueHigh if self.memory.width==128 => Some(Type {width:64,signedness:Signedness::Unsigned}),
                _ => None,
            };
        }
        let width = match (projection, &self.kind) {
            (AtomicProjection::Value | AtomicProjection::ValueHigh,
                AtomicOperationKind::LoadPair | AtomicOperationKind::ReadModifyWritePair { .. }
                | AtomicOperationKind::CompareExchangePair { .. } | AtomicOperationKind::LoadLinkedPair | AtomicOperationKind::LoadLinkedPairSplit) => 64,
            (AtomicProjection::Success, AtomicOperationKind::CompareExchangePair { .. }
                | AtomicOperationKind::StoreConditionalPair { .. }) => 1,
            (
                AtomicProjection::Value,
                AtomicOperationKind::Load
                | AtomicOperationKind::ReadModifyWrite { .. }
                | AtomicOperationKind::FloatingPointReadModifyWrite { .. }
                | AtomicOperationKind::CompareExchange { .. }
                | AtomicOperationKind::LoadLinked,
            ) => self.memory.width,
            (
                AtomicProjection::Success,
                AtomicOperationKind::CompareExchange { .. }
                | AtomicOperationKind::StoreConditional { .. },
            ) => 1,
            _ => return None,
        };
        Some(Type {
            width,
            signedness: Signedness::Unsigned,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierKind {
    DataMemory,
    DataSynchronization,
    InstructionSynchronization,
    Speculation,
    ConsumptionSpeculativeData,
    ClearBranchHistory,
    DataGatheringHint,
    StoreConcurrentPriorityHint,
    StoreSharedKeepHint,
    StoreSharedStreamHint,
    SharedUpdateHint,
    SharedUpdatePriorityHint,
    ProfilingSynchronization,
    TraceSynchronization,
    StoreBypass,
    PhysicalStoreBypass,
    DataSynchronizationNoXS,
    GuardedControlStackSynchronization,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierScope {
    System,
    InnerShareable,
    OuterShareable,
    NonShareable,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierAccess {
    All,
    Reads,
    Writes,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Barrier {
    pub kind: BarrierKind,
    pub scope: BarrierScope,
    pub access: BarrierAccess,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    /// A selected WFET/WFIT suspend boundary after incoming event, interrupt
    /// and virtual-time readiness checks. The environment resolves wakeup,
    /// delayed trapping and debug behavior without committing guest state.
    TimedWait { interrupt:bool, source:u8, deadline:Expr, condition:Expr },
    /// Closed wait boundary: fall through, or an environment-selected
    /// Protection trap only when that outcome is explicitly admitted.
    Wait { allow_protection_trap: bool },
    /// Publish a local or all-PE event; the environment acknowledges delivery.
    SendEvent { local: bool },
    Barrier {
        kind: BarrierKind,
        scope: BarrierScope,
        access: BarrierAccess,
        /// Additional instruction-local predicate, evaluated only if the recipe executes.
        condition: Option<Expr>,
    },
    ExclusiveMonitorClear,
    WriteRegister {
        destination: RegisterSlice,
        policy: WritePolicy,
        value: Expr,
    },
    /// A false condition suppresses value evaluation, parent preservation
    /// reads and the write itself. The entire graph remains validated.
    WriteRegisterConditional {
        condition: Expr,
        destination: RegisterSlice,
        policy: WritePolicy,
        value: Expr,
    },
    /// Write exactly one selected concrete register slice. Invalid/unknown
    /// selected indices reject; unselected recipe guards suppress all access.
    WriteIndexedRegister {
        destination: IndexedRegister,
        policy: WritePolicy,
        value: Expr,
    },
    /// Update one allocation tag. A false condition suppresses address and
    /// tag evaluation; publication remains ordered with data stores.
    StoreAllocationTag { address: Expr, tag: Expr, privilege: MemoryPrivilege, condition: Option<Expr> },
    Store {
        memory: Memory,
        value: Expr,
    },
    /// A predicated ordinary access. A false condition suppresses address and
    /// value evaluation, including any loads nested in those expressions.
    StoreConditional {
        condition: Expr,
        memory: Memory,
        value: Expr,
    },
    StoreWide { memory: WideMemory, chunks: Vec<Expr> },
    /// False suppresses the complete original-width access, including all
    /// address/chunk evaluation. The graph is still checked before execution.
    StoreWideConditional { condition: Expr, memory: WideMemory, chunks: Vec<Expr> },
    /// A synchronous architectural exception. Later outputs do not commit.
    Trap {
        kind: TrapKind,
        condition: Expr,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapKind {
    /// A64 branch-target identification check failure before instruction effects.
    AArch64BranchTarget,
    /// A64 GCSSTR/GCSSTTR effective STREn trap before memory access.
    AArch64GcsStore,
    /// GCS ordinary return record mismatch.
    AArch64GcsReturn,
    /// GCS procedure record format mismatch.
    AArch64GcsPop,
    /// GCS key-A return record mismatch.
    AArch64GcsReturnA,
    /// GCS key-B return record mismatch.
    AArch64GcsReturnB,
    /// GCS incoming valid capability mismatch.
    AArch64GcsSwitch1,
    /// GCS in-progress capability mismatch.
    AArch64GcsSwitch2,
    /// GCS exception record comparison mismatch.
    AArch64GcsPopCompareException,
    /// GCS exception record format mismatch.
    AArch64GcsPopException,
    /// MOPS main instruction option mismatch.
    AArch64MopsWrongOption,
    /// MOPS invalid parameters or incomplete epilogue.
    AArch64MopsParameters,

    /// Architecture-defined synchronous exception.
    Named(&'static str),
    InvalidInstruction,
    Breakpoint,
    IntegerDivideByZero,
    IntegerOverflow,
    Protection,
    FloatingPoint,
}
/// A pipeline-state write performed even when instruction predication fails.
/// Its value observes the incoming state and cannot reference recipe bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterUpdate {
    pub destination: RegisterSlice,
    pub policy: WritePolicy,
    pub value: Expr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKind {
    Next,
    Branch,
    Call,
    Return,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlFlow {
    pub kind: FlowKind,
    pub condition: Expr,
    pub target: Expr,
    pub fallthrough: Expr,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Support {
    Full,
    Partial(&'static str),
    Unsupported(&'static str),
}
/// An ordered entropy draw from the complete unsigned bit-vector domain.
/// A false predicate suppresses the provider call and leaves its result unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChoiceStep {
    pub width: u8,
    pub condition: Option<Expr>,
}
/// A register publication at an ordered-read boundary. Stage zero precedes
/// the first read; stage N follows the Nth read, including a suppressed read.
/// Expressions refer to immutable prefix bindings and already completed reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadUpdate {
    pub after_read: usize,
    pub update: RegisterUpdate,
    pub condition: Option<Expr>,
}
/// Explicit restartable instruction progress. Ordinary recipes remain parallel;
/// only these updates survive a later read fault. Consumers must retain restart
/// PC and publish completed updates together when reporting that fault.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadProgress {
    pub restart: Expr,
    pub updates: Vec<ReadUpdate>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipe {
    pub support: Support,
    /// Instruction-entry checks, before predication or operand evaluation.
    pub entry_traps: Vec<(TrapKind, Expr)>,
    /// Conditional incoming-state updates after successful completion, even
    /// when instruction predication suppresses the ordinary effects.
    pub completion_writes: Vec<(RegisterUpdate, Expr)>,
    /// Explicit entropy choices, before atomics, memory reads, bindings and writes.
    /// Predicates may use incoming state and earlier choices, never later results.
    pub choices: Vec<ChoiceStep>,
    /// Incoming-state traps resolved before choices, atomics or memory access.
    pub preflight_traps:Vec<(TrapKind,Expr)>,
    /// Bindings are evaluated in order, after atomic steps and before scalar
    /// effects. Temporary references point backwards; ordinary register/memory
    /// reads use incoming state, while atomic result expressions use their
    /// already resolved ordered event.
    pub temporaries: Vec<Expr>,
    /// Number of leading immutable bindings evaluated after choices/atomics
    /// and before ordered memory reads. This prefix can use incoming registers,
    /// choices and earlier prefix bindings, never memory/atomic/read results.
    /// Remaining bindings execute after ordered reads as before.
    pub pre_read_bindings: usize,
    /// Ordered atomic steps execute before scalar bindings and outputs. Inputs
    /// may read incoming state and earlier atomic results, never scalar bindings.
    pub atomics: Vec<AtomicStep>,
    /// Ordered original-width ordinary reads, each evaluated once after the
    /// pre-read binding prefix and before remaining bindings.
    /// Scalar entries use read_memory; wider entries use read_wide_memory.
    /// Addresses and predicates may use incoming state, prefix bindings and
    /// earlier read chunks.
    pub wide_loads: Vec<WideMemory>,
    /// One incoming-state predicate per original-width read. False reads yield
    /// unavailable chunks without evaluating the address or calling memory.
    pub wide_load_conditions: Vec<Option<Expr>>,
    /// Explicit fault classes recoverable by each ordered read. An empty list
    /// retains ordinary faulting behavior. Recovery is scalar and returns zero
    /// plus a false success bit; instruction recipes define subsequent effects.
    pub wide_load_recovery: Vec<Vec<MemoryFaultKind>>,
    pub read_progress: Option<ReadProgress>,
    pub effects: Vec<Effect>,
    /// Unconditional pipeline updates, applied after predicated outputs.
    pub always_writes: Vec<RegisterUpdate>,
    pub flow: ControlFlow,
    /// Guard for predicated instructions. A false guard produces only fallthrough.
    pub guard: Expr,
}
impl Expr {
    /// Read the selected finite-bank slice from incoming architectural state.
    pub fn indexed_register(register: IndexedRegister) -> Self {
        Self {
            ty: Type {
                width: register.width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::IndexedRegister(register),
        }
    }
    pub fn require_context(condition: Expr, reason: &'static str) -> Self {
        Self {
            ty: Type {
                width: 1,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::RequireContext {
                condition: Box::new(condition),
                reason,
            },
        }
    }
    pub fn pointer_authentication(expression: PointerAuthenticationExpression) -> Result<Self, EvalError> {
        if !expression.valid_dimensions() { return Err(EvalError::InvalidExpression); }
        Ok(Self { ty:Type{width:64,signedness:Signedness::Unsigned},kind:ExprKind::PointerAuthentication(expression) })
    }
    pub fn float(expression: FloatExpression) -> Self {
        let width = match expression.projection {
            FloatProjection::Value => expression.width,
            FloatProjection::Status => 32,
            FloatProjection::Trapped => 1,
        };
        Self {
            ty: Type {
                width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Float(expression),
        }
    }
    /// Construct a chunk projection without admitting a scalar wider than64.
    /// Local operation/operand/projection dimensions are checked immediately;
    /// recipe validation additionally checks all nested branches and bindings.
    pub fn x87(expression: X87Expression) -> Result<Self, EvalError> {
        let width = expression.validate_dimensions()?;
        Ok(Self {
            ty: Type {
                width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::X87(expression),
        })
    }
    pub fn constant(width: u8, bits: u64) -> Self {
        Self {
            ty: Type {
                width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Constant(bits & mask(width)),
        }
    }
    pub fn register(slice: RegisterSlice) -> Self {
        Self {
            ty: Type {
                width: slice.width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Register(slice),
        }
    }
    pub fn undefined(width: u8, reason: &'static str) -> Self {
        Self {
            ty: Type {
                width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Undefined(reason),
        }
    }
    pub fn unary(op: UnaryOp, value: Self) -> Self {
        let width = if op == UnaryOp::Parity {
            1
        } else {
            value.ty.width
        };
        Self {
            ty: Type {
                width,
                signedness: value.ty.signedness,
            },
            kind: ExprKind::Unary {
                op,
                value: Box::new(value),
            },
        }
    }
    pub fn binary(op: BinaryOp, left: Self, right: Self) -> Self {
        let width = if matches!(op, BinaryOp::Eq | BinaryOp::Ult | BinaryOp::Slt) {
            1
        } else {
            left.ty.width
        };
        Self {
            ty: Type {
                width,
                signedness: left.ty.signedness,
            },
            kind: ExprKind::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
            },
        }
    }
    pub fn cast(value: Self, width: u8, signed: bool) -> Self {
        Self {
            ty: Type {
                width,
                signedness: if signed {
                    Signedness::Signed
                } else {
                    Signedness::Unsigned
                },
            },
            kind: ExprKind::Cast {
                value: Box::new(value),
                signed,
            },
        }
    }
    pub fn extract(value: Self, offset: u8, width: u8) -> Self {
        Self {
            ty: Type {
                width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Extract {
                value: Box::new(value),
                offset,
            },
        }
    }
    pub fn select(condition: Self, yes: Self, no: Self) -> Self {
        Self {
            ty: yes.ty,
            kind: ExprKind::Select {
                condition: Box::new(condition),
                yes: Box::new(yes),
                no: Box::new(no),
            },
        }
    }
    pub fn load_allocation_tag(address: Self, privilege: MemoryPrivilege) -> Self {
        Self {ty: Type {width: 4, signedness: Signedness::Unsigned}, kind: ExprKind::LoadAllocationTag {address: Box::new(address), privilege}}
    }
    pub fn load(memory: Memory) -> Self {
        Self {
            ty: Type {
                width: memory.width,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Load(memory),
        }
    }
    pub fn add_carry(left: Self, right: Self, carry: Self) -> Self {
        Self {
            ty: Type {
                width: 1,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::AddCarry {
                left: Box::new(left),
                right: Box::new(right),
                carry: Box::new(carry),
            },
        }
    }
    pub fn sub_borrow(left: Self, right: Self, borrow: Self) -> Self {
        Self {
            ty: Type {
                width: 1,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::SubBorrow {
                left: Box::new(left),
                right: Box::new(right),
                borrow: Box::new(borrow),
            },
        }
    }
    pub fn overflow(subtract: bool, left: Self, right: Self, result: Self) -> Self {
        Self {
            ty: Type {
                width: 1,
                signedness: Signedness::Unsigned,
            },
            kind: ExprKind::Overflow {
                subtract,
                left: Box::new(left),
                right: Box::new(right),
                result: Box::new(result),
            },
        }
    }
}
impl Recipe {
    pub fn new(fallthrough: u64, address_width: u8) -> Self {
        let next = Expr::constant(address_width, fallthrough);
        Self {
            support: Support::Full,
            entry_traps: vec![],
            completion_writes: vec![],
            choices: vec![],
            preflight_traps:vec![],
            temporaries: vec![],
            pre_read_bindings: 0,
            atomics: vec![],
            wide_loads: vec![],
            wide_load_conditions: vec![],
            wide_load_recovery: vec![],
            read_progress: None,
            effects: vec![],
            always_writes: vec![],
            guard: Expr::constant(1, 1),
            flow: ControlFlow {
                kind: FlowKind::Next,
                condition: Expr::constant(1, 1),
                target: next.clone(),
                fallthrough: next,
            },
        }
    }
    pub fn unsupported(reason: &'static str, fallthrough: u64, address_width: u8) -> Self {
        let mut r = Self::new(fallthrough, address_width);
        r.support = Support::Unsupported(reason);
        r
    }
    /// Request an explicit entropy sample. No implicit host randomness is used.
    /// The step index is the stable per-instruction replay identity, including
    /// skipped steps; a consumer must commit provider state only with the transition.
    pub fn choose(&mut self, width: u8, condition: Option<Expr>) -> Expr {
        let step = self.choices.len();
        self.choices.push(ChoiceStep { width, condition });
        Expr { ty: Type { width, signedness: Signedness::Unsigned }, kind: ExprKind::ChoiceResult { step } }
    }
    /// Append one native atomic operation and expose its available typed outputs.
    /// Stage one allocation metadata update, never a data-memory store.
    pub fn store_allocation_tag(&mut self,address:Expr,tag:Expr,privilege:MemoryPrivilege,condition:Option<Expr>) {
        self.effects.push(Effect::StoreAllocationTag {address,tag,privilege,condition});
    }
    pub fn atomic(&mut self, operation: AtomicOperation) -> AtomicResults {
        let step = self.atomics.len();
        let result = |projection| {
            operation.result_type(projection).map(|ty| Expr {
                ty,
                kind: ExprKind::AtomicResult { step, projection },
            })
        };
        let outputs = AtomicResults {
            value: result(AtomicProjection::Value),
            value_high: result(AtomicProjection::ValueHigh),
            success: result(AtomicProjection::Success),
        };
        self.atomics.push(AtomicStep::Memory(operation));
        outputs
    }
    pub fn load_wide(&mut self, memory: WideMemory) -> Vec<Expr> {
        let step = self.wide_loads.len();
        let results = (0..memory.chunk_count()).map(|chunk| Expr {
            ty: Type { width: memory.chunk_width(chunk).unwrap(), signedness: Signedness::Unsigned },
            kind: ExprKind::WideLoadChunk { step, chunk },
        }).collect();
        self.wide_loads.push(memory);
        self.wide_load_conditions.push(None);
        self.wide_load_recovery.push(Vec::new());
        results
    }
    pub fn load_wide_conditional(&mut self, condition: Expr, memory: WideMemory) -> Vec<Expr> {
        let chunks = self.load_wide(memory);
        *self.wide_load_conditions.last_mut().unwrap() = Some(condition);
        chunks
    }
    pub fn store_wide(&mut self, memory: WideMemory, chunks: Vec<Expr>) {
        self.effects.push(Effect::StoreWide { memory, chunks });
    }
    pub fn store_wide_conditional(&mut self, condition: Expr, memory: WideMemory, chunks: Vec<Expr>) {
        self.effects.push(Effect::StoreWideConditional { condition, memory, chunks });
    }
    /// One original-width scalar read in the same ordered stream as wide reads.
    /// Later read predicates/addresses can use its immutable result. No repeated
    /// callback or widened access is introduced to test a previously read value.
    pub fn load_ordered(&mut self, memory: Memory) -> Result<Expr, EvalError> {
        self.load_ordered_conditional(Expr::constant(1, 1), memory)
    }
    pub fn load_ordered_conditional(&mut self, condition: Expr, memory: Memory) -> Result<Expr, EvalError> {
        if memory.width == 0 || memory.width > 64 || memory.width % 8 != 0 || condition.ty.width != 1 {
            return Err(EvalError::InvalidExpression);
        }
        let chunks = self.load_wide_conditional(condition, WideMemory {kind: memory.kind, privilege: memory.privilege,
            address: memory.address, width: u16::from(memory.width), endian: memory.endian,
        });
        Ok(chunks[0].clone())
    }
    /// Attempt exactly one scalar read in the ordinary ordered read stream.
    /// Only a typed fault in `suppress` is recoverable. A false predicate reads
    /// neither address nor memory, and leaves both projections unavailable.
    pub fn try_load_ordered(&mut self, condition: Expr, memory: Memory, suppress: Vec<MemoryFaultKind>) -> Result<(Expr, Expr), EvalError> {
        if memory.kind!=MemoryKind::Data || !matches!(memory.width, 8 | 16 | 32 | 64) || condition.ty.width != 1
            || suppress.is_empty() || !suppress.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(EvalError::InvalidExpression);
        }
        let step = self.wide_loads.len();
        let value = self.load_ordered_conditional(condition, memory)?;
        self.wide_load_recovery[step] = suppress;
        Ok((value, Expr { ty: Type { width: 1, signedness: Signedness::Unsigned }, kind: ExprKind::WideLoadSuccess { step } }))
    }
    pub fn store_conditional(&mut self, condition: Expr, memory: Memory, value: Expr) {
        self.effects.push(Effect::StoreConditional { condition, memory, value });
    }
    pub fn clear_exclusive(&mut self) {
        self.atomics.push(AtomicStep::ClearExclusive);
    }
    /// Capture a pure incoming-state expression once before ordered reads.
    /// Prefix captures must be appended before any ordinary binding. Inactive
    /// recipe guards skip the complete prefix, and Select arms remain lazy.
    pub fn bind_before_reads(&mut self, value: Expr) -> Result<Expr, EvalError> {
        if self.pre_read_bindings != self.temporaries.len() {
            return Err(EvalError::InvalidExpression);
        }
        let types = self.temporaries.iter().map(|expression| expression.ty).collect::<Vec<_>>();
        validate_expression_graph_inner(&value, &types, &[], &[], &self.choices, true)?;
        let result = self.bind(value);
        self.pre_read_bindings += 1;
        Ok(result)
    }
    pub fn bind(&mut self, value: Expr) -> Expr {
        let ty = value.ty;
        let index = self.temporaries.len();
        self.temporaries.push(value);
        Expr {
            ty,
            kind: ExprKind::Temporary(index),
        }
    }
    pub fn write(&mut self, destination: RegisterSlice, policy: WritePolicy, value: Expr) {
        self.effects.push(Effect::WriteRegister {
            destination,
            policy,
            value,
        });
    }
    pub fn write_conditional(&mut self, condition: Expr, destination: RegisterSlice, policy: WritePolicy, value: Expr) {
        self.effects.push(Effect::WriteRegisterConditional { condition, destination, policy, value });
    }
    /// Write the selected finite-bank slice. Index and value read incoming state;
    /// the transition exposes an ordinary concrete RegisterWrite after selection.
    pub fn write_indexed(&mut self, destination: IndexedRegister, policy: WritePolicy, value: Expr) {
        self.effects.push(Effect::WriteIndexedRegister {
            destination,
            policy,
            value,
        });
    }
    pub fn write_always(&mut self, destination: RegisterSlice, policy: WritePolicy, value: Expr) {
        self.always_writes.push(RegisterUpdate {
            destination,
            policy,
            value,
        });
    }
    pub fn branch(&mut self, kind: FlowKind, condition: Expr, target: Expr) {
        self.flow.kind = kind;
        self.flow.condition = condition;
        self.flow.target = self.bind(target);
    }
}
pub fn register(bank: &'static str, index: u16, width: u8, parent_width: u8) -> RegisterSlice {
    RegisterSlice {
        register: Register { bank, index },
        offset: 0,
        width,
        parent_width,
    }
}
pub fn mask(width: u8) -> u64 {
    if width >= 64 {
        u64::MAX
    } else if width == 0 {
        0
    } else {
        (1u64 << width) - 1
    }
}

/// Defined tracks individual known bits. Undefined architecture results remain
/// explicitly unknown; the evaluator never silently substitutes a defined zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Value {
    pub bits: u64,
    pub defined: u64,
    pub width: u8,
}
impl Value {
    pub fn known(width: u8, bits: u64) -> Self {
        Self {
            bits: bits & mask(width),
            defined: mask(width),
            width,
        }
    }
    pub fn unknown(width: u8) -> Self {
        Self {
            bits: 0,
            defined: 0,
            width,
        }
    }
    pub fn is_known(self) -> bool {
        self.defined & mask(self.width) == mask(self.width)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvalError {
    Unsupported,
    InvalidExpression,
    UnknownAddress,
    /// A selected finite-bank register index is not fully known.
    UnknownRegisterIndex,
    /// A selected register index is outside its declared finite bank.
    RegisterIndexOutOfRange,
    UnknownCondition,
    Memory,
    /// A classified architectural memory fault, distinct from a backend error.
    MemoryFault(MemoryFaultKind),
    UnavailableMemoryResult,
    UnsupportedContext,
    UnknownAtomicValue,
    InvalidAtomicOutcome,
    InvalidEnvironmentOutcome,
    /// Selected entropy must be a fully defined bit vector of the requested width.
    InvalidChoiceOutcome,
    /// A guarded draw was skipped, but its unavailable result was selected.
    UnavailableChoiceResult,
    /// The engine returned a malformed width, out-of-range bits, or unknown result.
    InvalidX87Outcome,
    /// A selected result is unavailable (e.g. no commit or unspecified approximation).
    UnavailableX87Result,
}
/// The consumer supplies the immutable pre-instruction state. Little/big endian
/// conversion belongs to read_memory; width is bits, not bytes.
pub trait Machine {
    fn read_register(&self, register: Register) -> Value;
    /// Observe target allocation metadata. No ordinary-memory fallback is
    /// permitted; a consumer that lacks allocation tags rejects this operation.
    fn read_allocation_tag(&self,_address:u64,_privilege:MemoryPrivilege)->Result<Value,EvalError>{Err(EvalError::Unsupported)}
    fn read_memory(&self, address: u64, width: u8, endian: Endian) -> Result<Value, EvalError>;
    /// GCS reads require an explicit protected-memory implementation. There is
    /// no fallback to ordinary bytes, even when numeric addresses match.
    fn read_guarded_control_stack(&self,_address:u64,_endian:Endian,_privilege:MemoryPrivilege)->Result<Value,EvalError>{Err(EvalError::Unsupported)}
    /// Explicit access-policy boundary. The default accepts Current only;
    /// an unprivileged transfer never falls back to an ordinary read.
    fn read_memory_for_access(&self, address:u64, width:u8, endian:Endian, privilege:MemoryPrivilege)->Result<Value,EvalError> {
        if privilege!=MemoryPrivilege::Current {return Err(EvalError::Unsupported);}
        self.read_memory(address,width,endian)
    }
    fn try_read_memory_for_access(&self, address:u64, width:u8, endian:Endian, privilege:MemoryPrivilege)->Result<Value,EvalError> {
        if privilege!=MemoryPrivilege::Current {return Err(EvalError::Unsupported);}
        self.try_read_memory(address,width,endian)
    }
    fn read_wide_memory_for_access(&self, address:u64, width:u16, endian:Endian, privilege:MemoryPrivilege)->Result<Vec<Value>,EvalError> {
        if privilege!=MemoryPrivilege::Current {return Err(EvalError::Unsupported);}
        self.read_wide_memory(address,width,endian)
    }

    /// Attempt a recoverable architectural scalar read. This explicit capability
    /// must suppress externally visible accesses to Device memory when required
    /// by the instruction family. It may return only a classified synchronous
    /// fault for recovery; unsupported memory attributes remain Unsupported.
    /// There is deliberately no implicit fallback to ordinary read_memory.
    fn try_read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
        Err(EvalError::Unsupported)
    }
    /// Supply one selected entropy choice from explicit guest input or a replayable
    /// bounded model. `sequence` is its stable recipe index, not a draw counter.
    /// This is pending observation: do not commit provider/replay state here.
    /// Return Unsupported when no explicit entropy capability is supplied.
    fn choose(&self, _: usize, _: u8) -> Result<Value, EvalError> { Err(EvalError::Unsupported) }
    /// Resolve the closed wait domain without committing machine state. The
    /// returned transition retains this ordered boundary for eventual commit.
    fn timed_wait(&self,_:&TimedWaitRequest)->Result<TimedWaitOutcome,EvalError>{Err(EvalError::Unsupported)}
    fn wait(&self, _: bool) -> Result<WaitOutcome, EvalError> { Err(EvalError::Unsupported) }
    /// Acknowledge the selected local/all-PE event without committing it here.
    fn send_event(&self, _: bool) -> Result<(), EvalError> { Err(EvalError::Unsupported) }
    /// Apply the complete access's fault/tag/alignment contract and return its
    /// numeric chunks. No implicit sequence of scalar accesses is permitted.
    /// Exact atomic 64-byte target-memory operation, including device status.
    fn evaluate_block64(&self,_:&Block64Request)->Result<Block64Observation,EvalError>{Err(EvalError::Unsupported)}
    fn read_wide_memory(&self, _: u64, _: u16, _: Endian) -> Result<Vec<Value>, EvalError> {
        Err(EvalError::Unsupported)
    }
    /// Resolve one native atomic transaction against the incoming snapshot and
    /// the ordered preceding atomic transitions. This is read-only planning:
    /// do not commit memory or monitor state here. The backend must honor exact
    /// endian/ordering/scope, validate reservations against interference, and
    /// return Unsupported for capabilities it cannot execute. The witness must
    /// let its eventual commit path validate/reserve this observation so atomic
    /// outputs and all architectural writes commit as one coherent transition.
    fn evaluate_atomic(
        &self,
        _: &AtomicRequest,
        _: &[AtomicTransition],
    ) -> Result<AtomicObservation, EvalError> {
        Err(EvalError::Unsupported)
    }
    /// Resolve one indivisible 128-bit access. A single witness covers both
    /// chunks and the pending write; no two-access fallback is permitted.
    /// Existing scalar backends reject this capability by default.
    fn evaluate_atomic_pair(
        &self,
        _: &AtomicRequest,
        _: &[AtomicTransition],
    ) -> Result<AtomicPairObservation, EvalError> {
        Err(EvalError::Unsupported)
    }
    /// Read two independently atomic 64-bit elements under one exclusive
    /// reservation. Each witness identifies the observation at address or
    /// address+8, respectively; the reservation token must detect interference
    /// anywhere in the complete 16-byte reservation, including between reads.
    /// Numeric low/high chunks follow request.endian. No indivisible fallback.
    fn evaluate_exclusive_pair(&self,_:&AtomicRequest,_:&[AtomicTransition]) -> Result<ExclusivePairObservation,EvalError> {
        Err(EvalError::Unsupported)
    }
    fn read_exclusive_monitor(&self) -> Result<Option<ExclusiveReservation>, EvalError> {
        Err(EvalError::Unsupported)
    }
    /// Evaluate one typed PAC operation under explicit guest configuration,
    /// selected key, VA/TBI and authentication policy. Inputs are known64-bit
    /// values. Missing keys/configuration/cipher capability is an error, never
    /// host-state inference or an assumed zero authentication code.
    fn evaluate_pointer_authentication(&self,_:&PointerAuthenticationExpression,_:&[Value])->Result<Value,EvalError>{
        Err(EvalError::Unsupported)
    }
    /// Evaluate the typed operation with architectural rounding, NaN, flush,
    /// exception and sticky-status rules. Never use the host's ambient FP state.
    /// Consumers without an architectural floating-point engine reject it.
    fn evaluate_float(
        &self,
        _: &FloatExpression,
        _: &[Value],
        _: Value,
        _: Value,
    ) -> Result<Value, EvalError> {
        Err(EvalError::Unsupported)
    }
    /// Evaluate a deterministic coupled x87 operation/projection using only its
    /// explicit inputs. Chunks are flattened by logical operand, low bits first;
    /// all chunks and the three 16-bit environment values are known. An 80-bit
    /// value is [low64, high16], never an IEEE 64-bit approximation. This is read-only:
    /// status/tag/commit projections must describe the same transition for the
    /// same inputs. Return UnavailableX87Result for an absent selected output,
    /// and Unsupported for capabilities/approximations the engine cannot supply.
    /// No host control word, floating-point state, or raw opcode is consulted.
    fn evaluate_x87(
        &self,
        _: &X87Expression,
        _: &[Value],
        _: Value,
        _: Value,
        _: Value,
    ) -> Result<Value, EvalError> {
        Err(EvalError::Unsupported)
    }

}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterWrite {
    pub register: Register,
    pub value: Value,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationTagWrite {
    pub privilege: MemoryPrivilege,
    pub address: u64,
    pub tag: Value,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryWrite {
    /// This transfer must be authorized as a guarded-control-stack access.
    pub guarded_control_stack: bool,
    pub privilege: MemoryPrivilege,
    pub address: u64,
    pub value: Value,
    pub endian: Endian,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WideMemoryWrite {
    pub privilege: MemoryPrivilege,
    pub address: u64,
    pub width: u16,
    pub chunks: Vec<Value>,
    pub endian: Endian,
}
/// Opaque backend reservation identity plus the exact access it covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExclusiveReservation {
    pub address: u64,
    pub width: u8,
    pub scope: MemoryScope,
    pub token: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AtomicRequestKind {
    LoadPair,
    ReadModifyWritePair { operation: AtomicPairRmwOp, low: Value, high: Value },
    StorePair { low: Value, high: Value },
    CompareExchangePair {
        expected_low: Value,
        expected_high: Value,
        replacement_low: Value,
        replacement_high: Value,
        failure_ordering: MemoryOrdering,
    },
    LoadLinkedPair,
    /// Two 64-bit observations tied to one 128-bit exclusive reservation.
    /// This access does not promise pair single-copy atomicity.
    LoadLinkedPairSplit,
    StoreConditionalPair { low: Value, high: Value },
    Load,
    Store {
        value: Value,
    },
    ReadModifyWrite {
        operation: AtomicRmwOp,
        value: Value,
    },
    FloatingPointReadModifyWrite { operation: AtomicFloatRmwOp, bfloat: bool, value: Value, control: Value },
    RestrictedReadModifyWrite { operation: AtomicRcwOp, soft: bool, expected: [Value;2], operand: [Value;2], mask: [Value;2], soft_mask: [Value;2], protection: Value },
    CompareExchange {
        expected: Value,
        replacement: Value,
        failure_ordering: MemoryOrdering,
    },
    LoadLinked,
    StoreConditional {
        value: Value,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicRequest {
    pub memory_kind: MemoryKind,
    pub privilege: MemoryPrivilege,
    pub address: u64,
    pub width: u8,
    pub endian: Endian,
    pub ordering: MemoryOrdering,
    pub scope: MemoryScope,
    pub kind: AtomicRequestKind,
    /// Present for store-conditional if a local reservation exists. A matching
    /// reservation is necessary but interference may still make the store fail.
    pub reservation: Option<ExclusiveReservation>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicObservation {
    /// Required exactly for load/RMW/CAS/load-linked; always a fully known value.
    pub old: Option<Value>,
    /// Required exactly for store-conditional; may fail spuriously.
    pub store_succeeded: Option<bool>,
    /// Required exactly for load-linked. Opaque to recipe expressions.
    pub reservation_token: Option<u64>,
    pub witness: u64,
}
/// The scalar observation supplies the low chunk and a single indivisibility
/// witness. The high chunk is present exactly for pair loads/RMW/CAS/load-linked.
/// Scalar observation constructors and Machine::evaluate_atomic stay unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicPairObservation {
    pub observation: AtomicObservation,
    pub old_high: Option<Value>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExclusivePairObservation {
    pub low:Value,
    pub high:Value,
    pub reservation_token:u64,
    pub witnesses:[u64;2],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExclusiveMonitorEffect {
    Preserved,
    Set(ExclusiveReservation),
    Cleared,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtomicTransition {
    /// Separate address-ordered read witnesses for a split exclusive pair.
    pub split_pair_witnesses:Option<[u64;2]>,
    /// A distinct LS64 event; its 512-bit payload cannot alias scalar fields.
    pub block64:Option<Block64Transition>,
    /// None only for a standalone clear-exclusive operation.
    pub request: Option<AtomicRequest>,
    pub observation: Option<AtomicObservation>,
    pub value: Option<Value>,
    pub value_high: Option<Value>,
    pub success: Option<bool>,
    /// The pending write belongs to this atomic event, never ordinary memory.
    pub stored: Option<Value>,
    /// Present together with stored exactly for an indivisible pair write.
    /// Never commit either chunk independently or as an ordinary MemoryWrite.
    pub stored_high: Option<Value>,
    pub monitor: ExclusiveMonitorEffect,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrderedEvent {
    TimedWait { request:TimedWaitRequest, outcome:TimedWaitOutcome },
    Wait { allow_protection_trap: bool, outcome: WaitOutcome },
    SendEvent { local: bool },
    /// Index into Transition.atomics, including ordered clear-exclusive steps.
    Atomic(usize),
    /// Index into Transition.memory.
    Store(usize),
    /// One allocation metadata update in Transition.allocation_tags.
    AllocationTagStore(usize),
    /// One original-width write in Transition.wide_memory.
    WideStore(usize),
    Barrier(Barrier),
    ExclusiveMonitorClear,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitOutcome { FallThrough, ProtectionTrap }
/// Closed outcomes of one selected timed wait. ClearEvent is legal only for
/// WFET; traps preserve architectural registers and the local reservation.
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct TimedWaitRequest{pub interrupt:bool,pub source:u8,pub deadline:u64}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub enum TimedWaitOutcome { FallThrough, ClearEvent, ProtectionTrap, InvalidInstruction }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transition {
    pub registers: Vec<RegisterWrite>,
    pub memory: Vec<MemoryWrite>,
    pub allocation_tags: Vec<AllocationTagWrite>,
    pub wide_memory: Vec<WideMemoryWrite>,
    pub atomics: Vec<AtomicTransition>,
    pub events: Vec<OrderedEvent>,
    pub next_pc: Value,
    pub trap: Option<TrapKind>,
}
fn signed(bits: u64, width: u8) -> i128 {
    ((bits & mask(width)) as i128)
        - if bits & (1u64 << (width - 1)) != 0 {
            1i128 << width
        } else {
            0
        }
}
/// Validate every expression branch without consulting architectural state.
/// Temporaries are the types of earlier, immutable recipe bindings.
pub fn validate_expression(e: &Expr, temps: &[Type]) -> Result<(), EvalError> {
    validate_expression_with_atomics(e, temps, &[])
}
fn validate_expression_with_atomics(e: &Expr, temps: &[Type], atomics: &[AtomicStep]) -> Result<(), EvalError> {
    validate_expression_graph(e, temps, atomics, &[], &[])
}
fn validate_expression_graph(e: &Expr, temps: &[Type], atomics: &[AtomicStep], wide: &[WideMemory], choices: &[ChoiceStep]) -> Result<(), EvalError> {
    validate_expression_graph_inner(e, temps, atomics, wide, choices, false)
}
fn validate_expression_graph_inner(e: &Expr, temps: &[Type], atomics: &[AtomicStep], wide: &[WideMemory], choices: &[ChoiceStep], pre_read: bool) -> Result<(), EvalError> {
    if pre_read && matches!(e.kind, ExprKind::Load(_) | ExprKind::LoadAllocationTag { .. }) { return Err(EvalError::InvalidExpression); }
    let w = e.ty.width;
    if w == 0 || w > 64 {
        return Err(EvalError::InvalidExpression);
    }
    let valid = match &e.kind {
        ExprKind::Unary { op, value } => {
            (*op != UnaryOp::ReverseBytes || value.ty.width % 8 == 0)
                && w == if *op == UnaryOp::Parity {
                    1
                } else {
                    value.ty.width
                }
        }
        ExprKind::Binary { op, left, right } => {
            (left.ty.width == right.ty.width
                || matches!(
                    op,
                    BinaryOp::Shl | BinaryOp::Lsr | BinaryOp::Asr | BinaryOp::Ror
                ))
                && w == if matches!(op, BinaryOp::Eq | BinaryOp::Ult | BinaryOp::Slt) {
                    1
                } else {
                    left.ty.width
                }
        }
        ExprKind::Register(s) => {
            s.width == w
                && s.parent_width > 0
                && s.parent_width <= 64
                && s.offset as u16 + w as u16 <= s.parent_width as u16
        }
        ExprKind::IndexedRegister(s) => s.width == w && s.valid_dimensions(),
        ExprKind::Select { condition, yes, no } => {
            condition.ty.width == 1 && yes.ty.width == w && no.ty.width == w
        }
        ExprKind::RequireContext { condition, .. } => w == 1 && condition.ty.width == 1,
        ExprKind::Load(m) => m.width == w && w % 8 == 0 && (m.kind==MemoryKind::Data || w==64),
        ExprKind::LoadAllocationTag {address,..} => w==4 && address.ty.width==64,
        ExprKind::PointerAuthentication(p) => w == 64 && p.valid_dimensions(),
        ExprKind::X87(f) => f.validate_dimensions().is_ok_and(|width| width == w),
        ExprKind::Float(f) => {
            let format = |width| matches!(width, 16 | 32 | 64);
            let (source, arity, dimensions) = match f.operation {
                FloatOperation::SquareRoot | FloatOperation::RoundToIntegral { .. }
                | FloatOperation::ReciprocalEstimate | FloatOperation::ReciprocalSquareRootEstimate | FloatOperation::ReciprocalExponent => (f.width, 1, format(f.width)),
                FloatOperation::FusedMultiplyAdd { .. } => (f.width, 3, format(f.width)),
                FloatOperation::X86ReciprocalEstimate | FloatOperation::X86ReciprocalSquareRootEstimate => (f.width,1,f.width == 16 && f.environment == FloatEnvironment::X86Mxcsr),
                FloatOperation::Scale => (f.width, 2, format(f.width) && f.environment == FloatEnvironment::X86Mxcsr),
                FloatOperation::Reduce { scale, rounding, .. } | FloatOperation::RoundScale { scale, rounding, .. } => (f.width, 1,
                    format(f.width) && f.environment == FloatEnvironment::X86Mxcsr && scale < 16 && rounding != FloatRounding::NearestAway),
                FloatOperation::GetExponent => (f.width, 1, format(f.width) && f.environment == FloatEnvironment::X86Mxcsr),
                FloatOperation::GetMantissa { interval, sign_control } => (f.width, 1,
                    format(f.width) && f.environment == FloatEnvironment::X86Mxcsr && interval < 4 && sign_control < 4),
                FloatOperation::WideningFusedMultiplyAdd { source_width } => (source_width, 3,
                    source_width == 16 && f.width == 32 && f.environment == FloatEnvironment::A64),
                FloatOperation::ToBFloat16 => (32, 1, f.width == 16 && f.environment == FloatEnvironment::A64),
                FloatOperation::HalfDotProduct => (16,4,f.width==32&&f.environment==FloatEnvironment::A64),
                FloatOperation::ZaHalfDot => (16,5,f.width==32&&f.environment==FloatEnvironment::A64),
                FloatOperation::ZaFused {bfloat} => (f.width,3,matches!(f.width,16|32|64)&&(!bfloat||f.width==16)&&f.environment==FloatEnvironment::A64),
                FloatOperation::ZaBinary {bfloat,..} => (f.width,2,matches!(f.width,16|32|64)&&(!bfloat||f.width==16)&&f.environment==FloatEnvironment::A64),
                FloatOperation::Fp8Dot {ways} => (ways*8,4,matches!(f.width,16|32)&&matches!(ways,2|4|8)&&f.environment==FloatEnvironment::A64),
                FloatOperation::Fp8WideningFused => (8,4,matches!(f.width,16|32)&&f.environment==FloatEnvironment::A64),
                FloatOperation::BFloatWideningFused { .. } => (16,3,f.width == 32 && f.environment == FloatEnvironment::A64),
                FloatOperation::BFloatDotAdd => (32, 5, f.width == 32 && f.environment == FloatEnvironment::A64),
                FloatOperation::BFloatBinary { .. } => (16, 2, f.width == 16 && f.environment == FloatEnvironment::A64),
                FloatOperation::BFloatFused => (16, 3, f.width == 16 && f.environment == FloatEnvironment::A64),
                FloatOperation::Fp8Convert { source_width, bfloat, source2 } => (source_width, 2,
                    f.environment == FloatEnvironment::A64 && if source_width == 8 { f.width == 16 }
                    else { matches!(source_width,16|32) && f.width == 8 && (!bfloat || source_width==16) && !source2 }),
                FloatOperation::Compare { source_width, .. } => (source_width, 2, format(source_width) && f.width == 4),
                FloatOperation::Convert { source_width, round_to_odd } => (source_width, 1,
                    format(source_width) && format(f.width) && (!round_to_odd || (source_width, f.width) == (64, 32))),
                FloatOperation::ToInteger { source_width, fractional_bits, rounding, .. } => (source_width, 1,
                    format(source_width) && (format(f.width) || f.environment == FloatEnvironment::A64 && f.width == 8 && source_width == 16 && fractional_bits == 0 && rounding == FloatRounding::Zero) && fractional_bits <= f.width
                    && (fractional_bits == 0 || rounding == FloatRounding::Zero)),
                FloatOperation::FromInteger { source_width, fractional_bits, .. } => (source_width, 1,
                    format(source_width) && format(f.width) && fractional_bits <= source_width),
                _ => (f.width, 2, format(f.width)),
            };
            dimensions
                && (f.environment == FloatEnvironment::A64
                    || (source != 16 && f.width != 16)
                    || (f.environment == FloatEnvironment::A32Vfp
                        && matches!(f.operation, FloatOperation::Convert { .. }
                            | FloatOperation::Add | FloatOperation::Subtract | FloatOperation::Multiply
                            | FloatOperation::Divide | FloatOperation::SquareRoot
                            | FloatOperation::FusedMultiplyAdd { .. } | FloatOperation::Compare { .. }
                            | FloatOperation::FromInteger { .. } | FloatOperation::ToInteger { .. }
                            | FloatOperation::RoundToIntegral { .. } | FloatOperation::MinMax { numeric: true, .. }))
                    || (f.environment == FloatEnvironment::A32Neon
                        && matches!(f.operation, FloatOperation::Add | FloatOperation::Subtract
                            | FloatOperation::Multiply | FloatOperation::FusedMultiplyAdd { .. }
                            | FloatOperation::Compare { .. } | FloatOperation::MinMax { .. }
                            | FloatOperation::RoundToIntegral { .. } | FloatOperation::FromInteger { .. }
                            | FloatOperation::ToInteger { .. }))
                    || (f.environment == FloatEnvironment::X86Mxcsr && match f.operation {
                        FloatOperation::Add | FloatOperation::Subtract | FloatOperation::Multiply
                        | FloatOperation::Divide | FloatOperation::SquareRoot
                        | FloatOperation::FusedMultiplyAdd { .. } | FloatOperation::Compare { .. }
                        | FloatOperation::Convert { .. } | FloatOperation::RoundToIntegral { .. }
                        | FloatOperation::MinMax { numeric: false, .. } => true,
                        FloatOperation::GetExponent | FloatOperation::GetMantissa { .. } | FloatOperation::Scale
                        | FloatOperation::X86ReciprocalEstimate | FloatOperation::X86ReciprocalSquareRootEstimate
                        | FloatOperation::Reduce { .. } | FloatOperation::RoundScale { .. } => true,
                        FloatOperation::ToInteger { .. } => matches!(f.width, 16 | 32 | 64),
                        FloatOperation::FromInteger { source_width, .. } => matches!(source_width, 16 | 32 | 64),
                        _ => false,
                    }))
                && f.inputs.len() == arity
                && (match f.operation {
                    FloatOperation::Fp8Convert { source_width, .. } => f.inputs.iter().map(|input| input.ty.width).eq([source_width,64]),
                    FloatOperation::Fp8Dot {ways} => f.inputs.iter().map(|input|input.ty.width).eq([f.width,ways*8,ways*8,64]),
                    FloatOperation::Fp8WideningFused => f.inputs.iter().map(|input|input.ty.width).eq([f.width,8,8,64]),
                    FloatOperation::BFloatWideningFused { .. } => f.inputs.iter().map(|input|input.ty.width).eq([32,16,16]),
                    FloatOperation::ZaHalfDot => f.inputs.iter().map(|input|input.ty.width).eq([32,16,16,16,16]),
                    FloatOperation::BFloatDotAdd => f.inputs.iter().map(|input| input.ty.width).eq([32,16,16,16,16]),
                    FloatOperation::WideningFusedMultiplyAdd { source_width } =>
                        f.inputs.iter().map(|input| input.ty.width).eq([f.width,source_width,source_width]),
                    _ => f.inputs.iter().all(|input| input.ty.width == source),
                })
                && f.control.ty.width == 32
                && f.status.ty.width == 32
                && w == match f.projection {
                    FloatProjection::Value => f.width,
                    FloatProjection::Status => 32,
                    FloatProjection::Trapped => 1,
                }
        }
        ExprKind::ChoiceResult { step } => choices.get(*step).map(|choice| choice.width) == Some(w),
        ExprKind::WideLoadChunk { step, chunk } => wide.get(*step).and_then(|memory| memory.chunk_width(*chunk)) == Some(w),
        ExprKind::WideLoadSuccess { step } => w == 1 && wide.get(*step).is_some(),
        ExprKind::Temporary(index) => temps.get(*index).map(|ty| ty.width) == Some(w),
        ExprKind::AtomicResult { step, projection } => {
            atomics.get(*step).and_then(|s| match s {
                AtomicStep::Memory(o) => o.result_type(*projection),
                AtomicStep::Block64(o) => match (&o.kind,projection) {
                    (Block64Kind::Load,AtomicProjection::BlockChunk(i)) if *i<8 => Some(Type{width:64,signedness:Signedness::Unsigned}),
                    (Block64Kind::Store{with_status:true,..},AtomicProjection::Value) => Some(Type{width:64,signedness:Signedness::Unsigned}),
                    _=>None,
                },
                AtomicStep::ClearExclusive => None,
            }) == Some(e.ty)
        }
        ExprKind::Extract { value, offset } => {
            u16::from(*offset) + u16::from(w) <= u16::from(value.ty.width)
        }
        ExprKind::AddCarry { left, right, carry } => {
            w == 1 && left.ty.width == right.ty.width && carry.ty.width == 1
        }
        ExprKind::SubBorrow {
            left,
            right,
            borrow,
        } => w == 1 && left.ty.width == right.ty.width && borrow.ty.width == 1,
        ExprKind::Overflow {
            left,
            right,
            result,
            ..
        } => w == 1 && left.ty.width == right.ty.width && result.ty.width == left.ty.width,
        _ => true,
    };
    if !valid {
        return Err(EvalError::InvalidExpression);
    }
    let check = |value: &Expr| validate_expression_graph_inner(value, temps, atomics, wide, choices, pre_read);
    match &e.kind {
        ExprKind::Unary { value, .. }
        | ExprKind::Cast { value, .. }
        | ExprKind::Extract { value, .. } => check(value)?,
        ExprKind::Binary { left, right, .. } => {
            check(left)?;
            check(right)?;
        }
        ExprKind::Select { condition, yes, no } => {
            check(condition)?;
            check(yes)?;
            check(no)?;
        }
        ExprKind::IndexedRegister(s) => check(&s.index)?,
        ExprKind::RequireContext { condition, .. } => check(condition)?,
        ExprKind::Load(memory) => check(&memory.address)?,
        ExprKind::LoadAllocationTag {address,..} => check(address)?,
        ExprKind::PointerAuthentication(p) => {for input in &p.inputs {check(input)?;}},
        ExprKind::X87(f) => {
            for input in &f.inputs {
                for chunk in &input.chunks {
                    check(chunk)?;
                }
            }
            check(&f.control)?;
            check(&f.status)?;
            check(&f.tags)?;
        }
        ExprKind::Float(f) => {
            for input in &f.inputs {
                check(input)?;
            }
            check(&f.control)?;
            check(&f.status)?;
        }
        ExprKind::AddCarry { left, right, carry } => {
            check(left)?;
            check(right)?;
            check(carry)?;
        }
        ExprKind::SubBorrow {
            left,
            right,
            borrow,
        } => {
            check(left)?;
            check(right)?;
            check(borrow)?;
        }
        ExprKind::Overflow {
            left,
            right,
            result,
            ..
        } => {
            check(left)?;
            check(right)?;
            check(result)?;
        }
        _ => {}
    }
    Ok(())
}

fn immutable_read_progress(expression: &Expr) -> bool {
    match &expression.kind {
        ExprKind::Constant(_) | ExprKind::Undefined(_) | ExprKind::Temporary(_)
        | ExprKind::ChoiceResult { .. } | ExprKind::WideLoadChunk { .. }
        | ExprKind::WideLoadSuccess { .. } => true,
        ExprKind::Unary { value, .. } | ExprKind::Cast { value, .. }
        | ExprKind::Extract { value, .. } => immutable_read_progress(value),
        ExprKind::Binary { left, right, .. } => immutable_read_progress(left) && immutable_read_progress(right),
        ExprKind::Select { condition, yes, no } => immutable_read_progress(condition)
            && immutable_read_progress(yes) && immutable_read_progress(no),
        _ => false,
    }
}
impl Recipe {
    /// Check the complete typed graph before evaluating or lowering it.
    /// This includes inactive predicates and both arms of a selection.
    pub fn validate(&self) -> Result<(), EvalError> {
        if self.support != Support::Full {
            return Err(EvalError::Unsupported);
        }
        if self.guard.ty.width != 1
            || self.flow.condition.ty.width != 1
            || self.flow.target.ty.width != self.flow.fallthrough.ty.width
        {
            return Err(EvalError::InvalidExpression);
        }
        validate_expression(&self.guard, &[])?;
        validate_expression(&self.flow.fallthrough, &[])?;
        for update in &self.always_writes {
            validate_expression(&Expr::register(update.destination), &[])?;
            validate_expression(&update.value, &[])?;
            if update.value.ty.width != update.destination.width
                || (update.policy == WritePolicy::ZeroUpper && update.destination.offset != 0)
            {
                return Err(EvalError::InvalidExpression);
            }
        }
        for (_, condition) in &self.entry_traps {
            if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
            validate_expression_graph_inner(condition, &[], &[], &[], &[], true)?;
        }
        for (update, condition) in &self.completion_writes {
            validate_expression(&Expr::register(update.destination), &[])?;
            if condition.ty.width != 1 || update.value.ty.width != update.destination.width
                || (update.policy == WritePolicy::ZeroUpper && update.destination.offset != 0) {
                return Err(EvalError::InvalidExpression);
            }
            validate_expression_graph_inner(condition, &[], &[], &[], &[], true)?;
            validate_expression_graph_inner(&update.value, &[], &[], &[], &[], true)?;
        }
        for (_,condition)in &self.preflight_traps{if condition.ty.width!=1{return Err(EvalError::InvalidExpression);}validate_expression_graph_inner(condition,&[],&[],&[],&[],true)?;}
        for (index, choice) in self.choices.iter().enumerate() {
            if choice.width == 0 || choice.width > 64 { return Err(EvalError::InvalidExpression); }
            if let Some(condition) = &choice.condition {
                if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                validate_expression_graph(condition, &[], &[], &[], &self.choices[..index])?;
            }
        }
        for (index, step) in self.atomics.iter().enumerate() {
            if let AtomicStep::Memory(operation) = step {
                validate_atomic(operation, &self.atomics[..index])?;
            }
            if let AtomicStep::Block64(operation)=step {
                if operation.address.ty.width!=64{return Err(EvalError::InvalidExpression);}
                validate_expression_with_atomics(&operation.address,&[],&self.atomics[..index])?;
                if let Block64Kind::Store{chunks,..}=&operation.kind {
                    for chunk in chunks {if chunk.ty.width!=64{return Err(EvalError::InvalidExpression);}validate_expression_with_atomics(chunk,&[],&self.atomics[..index])?;}
                }
            }
        }
        if self.pre_read_bindings > self.temporaries.len() { return Err(EvalError::InvalidExpression); }
        let mut types = Vec::with_capacity(self.temporaries.len());
        for expression in &self.temporaries[..self.pre_read_bindings] {
            validate_expression_graph_inner(expression, &types, &[], &[], &self.choices, true)?;
            types.push(expression.ty);
        }
        // Ordered atomics cannot substitute for original-snapshot reads.
        if !self.atomics.is_empty() && !self.wide_loads.is_empty() { return Err(EvalError::InvalidExpression); }
        if self.wide_load_conditions.len() != self.wide_loads.len() { return Err(EvalError::InvalidExpression); }
        if self.wide_load_recovery.len() != self.wide_loads.len() { return Err(EvalError::InvalidExpression); }
        for (index, memory) in self.wide_loads.iter().enumerate() {
            let recovery = &self.wide_load_recovery[index];
            if !recovery.is_empty() && (memory.kind!=MemoryKind::Data || !matches!(memory.width, 8 | 16 | 32 | 64)
                || !recovery.windows(2).all(|pair| pair[0] < pair[1])) {
                return Err(EvalError::InvalidExpression);
            }
            if let Some(condition) = &self.wide_load_conditions[index] {
                if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                validate_expression_graph(condition, &types, &[], &self.wide_loads[..index], &self.choices)?;
            }
            if !memory.valid_read_width() { return Err(EvalError::InvalidExpression); }
            validate_expression_graph(&memory.address, &types, &[], &self.wide_loads[..index], &self.choices)?;
        }
        if let Some(progress) = &self.read_progress {
            if !immutable_read_progress(&progress.restart)
                || self.wide_loads.iter().any(|memory| !immutable_read_progress(&memory.address))
                || self.wide_load_conditions.iter().flatten().any(|condition| !immutable_read_progress(condition))
                || progress.restart.ty.width != self.flow.fallthrough.ty.width
                || !immutable_read_progress(&self.flow.fallthrough)
                || !immutable_read_progress(&self.flow.condition)
                || !immutable_read_progress(&self.flow.target)
                || self.temporaries[self.pre_read_bindings..].iter().any(|value| !immutable_read_progress(value))
                || !self.always_writes.is_empty() || !self.completion_writes.is_empty()
                || self.effects.iter().any(|effect| match effect {
                    Effect::WriteRegister { value, .. } => !immutable_read_progress(value),
                    Effect::WriteRegisterConditional { value, condition, .. } =>
                        !immutable_read_progress(value) || !immutable_read_progress(condition),
                    _ => true,
                })
                || !self.atomics.is_empty() {
                return Err(EvalError::InvalidExpression);
            }
            validate_expression_graph(&progress.restart, &types, &[], &[], &self.choices)?;
            let mut previous = 0;
            for step in &progress.updates {
                let update = &step.update;
                if !immutable_read_progress(&update.value)
                    || step.condition.as_ref().is_some_and(|condition| !immutable_read_progress(condition))
                    || step.after_read < previous || step.after_read > self.wide_loads.len()
                    || update.value.ty.width != update.destination.width
                    || (update.policy == WritePolicy::ZeroUpper && update.destination.offset != 0) {
                    return Err(EvalError::InvalidExpression);
                }
                previous = step.after_read;
                validate_expression(&Expr::register(update.destination), &[])?;
                let reads = &self.wide_loads[..step.after_read];
                validate_expression_graph(&update.value, &types, &[], reads, &self.choices)?;
                if let Some(condition) = &step.condition {
                    if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                    validate_expression_graph(condition, &types, &[], reads, &self.choices)?;
                }
            }
        }
        for expression in &self.temporaries[self.pre_read_bindings..] {
            validate_expression_graph(expression, &types, &self.atomics, &self.wide_loads, &self.choices)?;
            types.push(expression.ty);
        }
        for effect in &self.effects {
            match effect {
                Effect::Barrier { condition, .. } => {
                    if let Some(condition) = condition {
                        if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                        validate_expression_graph(condition, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    }
                }
                Effect::TimedWait{source,deadline,condition,..}=>{
                    if *source>=32||deadline.ty.width!=64||condition.ty.width!=1{return Err(EvalError::InvalidExpression);}
                    validate_expression_graph(deadline,&types,&self.atomics,&self.wide_loads,&self.choices)?;
                    validate_expression_graph(condition,&types,&self.atomics,&self.wide_loads,&self.choices)?;
                }
                Effect::ExclusiveMonitorClear | Effect::Wait { .. } | Effect::SendEvent { .. } => {}
                Effect::WriteRegister {
                    destination,
                    policy,
                    value,
                } | Effect::WriteRegisterConditional {
                    destination,
                    policy,
                    value,
                    ..
                } => {
                    if let Effect::WriteRegisterConditional { condition, .. } = effect {
                        if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                        validate_expression_graph(condition, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    }
                    validate_expression_graph(
                        &Expr::register(*destination),
                        &types,
                        &self.atomics, &self.wide_loads, &self.choices,
                    )?;
                    if destination.width != value.ty.width
                        || (*policy == WritePolicy::ZeroUpper && destination.offset != 0)
                    {
                        return Err(EvalError::InvalidExpression);
                    }
                    validate_expression_graph(value, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                }
                Effect::WriteIndexedRegister {
                    destination,
                    policy,
                    value,
                } => {
                    if !destination.valid_dimensions()
                        || destination.width != value.ty.width
                        || (*policy == WritePolicy::ZeroUpper && destination.offset != 0)
                    {
                        return Err(EvalError::InvalidExpression);
                    }
                    validate_expression_graph(
                        &destination.index, &types, &self.atomics, &self.wide_loads, &self.choices,
                    )?;
                    validate_expression_graph(value, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                }
                Effect::Trap { condition, .. } => {
                    if condition.ty.width != 1 {
                        return Err(EvalError::InvalidExpression);
                    }
                    validate_expression_graph(condition, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                }
                Effect::StoreAllocationTag {address,tag,condition,..} => {
                    if address.ty.width!=64 || tag.ty.width!=4 || condition.as_ref().is_some_and(|c|c.ty.width!=1){return Err(EvalError::InvalidExpression);}
                    for value in [Some(address),Some(tag),condition.as_ref()].into_iter().flatten(){validate_expression_graph(value,&types,&self.atomics,&self.wide_loads,&self.choices)?;}
                }
                Effect::StoreWide { memory, chunks } | Effect::StoreWideConditional { memory, chunks, .. } => {
                    if let Effect::StoreWideConditional { condition, .. } = effect {
                        if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                        validate_expression_graph(condition, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    }
                    if !memory.valid_width() || chunks.len() != memory.chunk_count() { return Err(EvalError::InvalidExpression); }
                    validate_expression_graph(&memory.address, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    for (chunk, value) in chunks.iter().enumerate() {
                        if Some(value.ty.width) != memory.chunk_width(chunk) { return Err(EvalError::InvalidExpression); }
                        validate_expression_graph(value, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    }
                }
                Effect::Store { memory, value } | Effect::StoreConditional { memory, value, .. } => {
                    if let Effect::StoreConditional { condition, .. } = effect {
                        if condition.ty.width != 1 { return Err(EvalError::InvalidExpression); }
                        validate_expression_graph(condition, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    }
                    if (memory.kind==MemoryKind::GuardedControlStack && memory.width!=64) || memory.width == 0
                        || memory.width > 64
                        || memory.width % 8 != 0
                        || value.ty.width != memory.width
                    {
                        return Err(EvalError::InvalidExpression);
                    }
                    validate_expression_graph(&memory.address, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                    validate_expression_graph(value, &types, &self.atomics, &self.wide_loads, &self.choices)?;
                }
            }
        }
        validate_expression_graph(&self.flow.condition, &types, &self.atomics, &self.wide_loads, &self.choices)?;
        validate_expression_graph(&self.flow.target, &types, &self.atomics, &self.wide_loads, &self.choices)?;
        if self.flow.kind == FlowKind::Next
            && (self.flow.target != self.flow.fallthrough
                || !matches!(self.flow.condition.kind, ExprKind::Constant(1)))
        {
            return Err(EvalError::InvalidExpression);
        }
        Ok(())
    }
}

pub fn evaluate_expression<M: Machine>(
    e: &Expr,
    state: &M,
    temps: &[Value],
) -> Result<Value, EvalError> {
    let types: Vec<_> = temps
        .iter()
        .map(|value| Type {
            width: value.width,
            // Values are bit patterns; signed operations are explicit in ExprKind.
            signedness: Signedness::Unsigned,
        })
        .collect();
    validate_expression(e, &types)?;
    evaluate_validated_expression(e, state, temps, &[], &[], &[])
}

struct MemoryReadResult {
    chunks: Vec<Value>,
    success: Value,
}

fn evaluate_validated_expression<M: Machine>(
    e: &Expr,
    state: &M,
    temps: &[Value],
    atomics: &[AtomicTransition],
    wide: &[MemoryReadResult],
    choices: &[Value],
) -> Result<Value, EvalError> {
    let w = e.ty.width;
    let eval = |x: &Expr| evaluate_validated_expression(x, state, temps, atomics, wide, choices);
    let known = |bits| Ok(Value::known(w, bits));
    match &e.kind {
        ExprKind::ChoiceResult { step } => {
            let value = choices.get(*step).copied().filter(|v| v.width == w).ok_or(EvalError::InvalidExpression)?;
            if value.is_known() { Ok(value) } else { Err(EvalError::UnavailableChoiceResult) }
        },
        ExprKind::WideLoadChunk { step, chunk } => wide.get(*step).and_then(|read| read.chunks.get(*chunk)).copied()
            .filter(|v| v.width == w).ok_or(EvalError::InvalidExpression),
        ExprKind::WideLoadSuccess { step } => {
            let success = wide.get(*step).ok_or(EvalError::InvalidExpression)?.success;
            if success.is_known() { Ok(success) } else { Err(EvalError::UnavailableMemoryResult) }
        },
        ExprKind::RequireContext { condition, .. } => {
            let condition = eval(condition)?;
            if !condition.is_known() {
                return Err(EvalError::UnknownCondition);
            }
            if condition.bits == 0 {
                return Err(EvalError::UnsupportedContext);
            }
            known(1)
        }
        ExprKind::AtomicResult { step, projection } => {
            let result = atomics.get(*step).ok_or(EvalError::InvalidExpression)?;
            match projection {
                AtomicProjection::BlockChunk(i) => match &result.block64 {
                    Some(Block64Transition{observation:Block64Observation::Load{chunks,..},..}) => chunks.get(usize::from(*i)).copied().filter(|v|v.width==w).ok_or(EvalError::InvalidExpression),
                    _=>Err(EvalError::InvalidExpression),
                },
                AtomicProjection::ValueHigh => result
                    .value_high
                    .filter(|v| v.width == w)
                    .ok_or(EvalError::InvalidExpression),
                AtomicProjection::Value => result
                    .value
                    .filter(|v| v.width == w)
                    .ok_or(EvalError::InvalidExpression),
                AtomicProjection::Success => result
                    .success
                    .filter(|_| w == 1)
                    .map(|b| Value::known(1, b as u64))
                    .ok_or(EvalError::InvalidExpression),
            }
        }
        ExprKind::Constant(bits) => known(*bits),
        ExprKind::Undefined(_) => Ok(Value::unknown(w)),
        ExprKind::Temporary(i) => temps
            .get(*i)
            .copied()
            .filter(|v| v.width == w)
            .ok_or(EvalError::InvalidExpression),
        ExprKind::Register(s) => {
            if s.width != w || s.offset as u16 + w as u16 > s.parent_width as u16 {
                return Err(EvalError::InvalidExpression);
            }
            let v = state.read_register(s.register);
            if v.width < s.parent_width || v.width > 64 {
                return Err(EvalError::InvalidExpression);
            }
            Ok(Value {
                width: w,
                bits: (v.bits >> s.offset) & mask(w),
                defined: (v.defined >> s.offset) & mask(w),
            })
        }
        ExprKind::IndexedRegister(s) => {
            let selected = resolve_indexed_register(s, eval(&s.index)?)?;
            // Reuse the scalar slice semantics, including the parent-state
            // width check, while reading only the selected concrete register.
            evaluate_validated_expression(&Expr::register(selected), state, temps, atomics, wide, choices)
        }
        ExprKind::LoadAllocationTag {address,privilege} => {
            let address=eval(address)?;if !address.is_known(){return Err(EvalError::UnknownAddress);}
            let value=state.read_allocation_tag(address.bits,*privilege)?;
            if value.width!=4 || value.bits&!15!=0 || value.defined&!15!=0{return Err(EvalError::InvalidExpression);}
            Ok(value)
        }
        ExprKind::Load(m) => {
            let a = eval(&m.address)?;
            if !a.is_known() {
                return Err(EvalError::UnknownAddress);
            }
            let value = if m.kind==MemoryKind::GuardedControlStack {state.read_guarded_control_stack(a.bits,m.endian,m.privilege)} else {state.read_memory_for_access(a.bits, m.width, m.endian, m.privilege)}?;
            if value.width != w {
                return Err(EvalError::InvalidExpression);
            }
            Ok(Value {
                bits: value.bits & mask(w),
                defined: value.defined & mask(w),
                width: w,
            })
        }
        ExprKind::PointerAuthentication(p) => {
            let inputs=p.inputs.iter().map(eval).collect::<Result<Vec<_>,_>>()?;
            if inputs.iter().any(|v|!v.is_known()){return Ok(Value::unknown(64));}
            let result=state.evaluate_pointer_authentication(p,&inputs)?;
            if result.width != 64 || !result.is_known(){return Err(EvalError::InvalidExpression);}
            Ok(result)
        }
        ExprKind::X87(f) => {
            let inputs = f.inputs.iter().flat_map(|input| input.chunks.iter())
                .map(eval).collect::<Result<Vec<_>, _>>()?;
            let control = eval(&f.control)?;
            let status = eval(&f.status)?;
            let tags = eval(&f.tags)?;
            // Unknown data stays typed and symbolic. It never enters a known-
            // operand engine as a fabricated zero or an ambient host value.
            if inputs.iter().chain([&control, &status, &tags]).any(|v| !v.is_known()) {
                return Ok(Value::unknown(w));
            }
            let result = state.evaluate_x87(f, &inputs, control, status, tags)?;
            if result.width != w || !result.is_known()
                || result.bits & !mask(w) != 0 || result.defined & !mask(w) != 0
            {
                return Err(EvalError::InvalidX87Outcome);
            }
            Ok(result)
        }
        ExprKind::Float(f) => {
            let inputs = f.inputs.iter().map(eval).collect::<Result<Vec<_>, _>>()?;
            let control = eval(&f.control)?;
            let status = eval(&f.status)?;
            let result = state.evaluate_float(f, &inputs, control, status)?;
            if result.width != w {
                return Err(EvalError::InvalidExpression);
            }
            Ok(Value {
                bits: result.bits & mask(w),
                defined: result.defined & mask(w),
                width: w,
            })
        }
        ExprKind::Cast {
            value,
            signed: sign,
        } => {
            let v = eval(value)?;
            let high = mask(w) & !mask(v.width);
            let s = 1u64 << (v.width - 1);
            let extend = *sign && v.bits & s != 0;
            Ok(Value {
                width: w,
                bits: (v.bits | if extend { high } else { 0 }) & mask(w),
                defined: (v.defined
                    | if !*sign || v.defined & s != 0 {
                        high
                    } else {
                        0
                    })
                    & mask(w),
            })
        }
        ExprKind::Extract { value, offset } => {
            let v = eval(value)?;
            if *offset as u16 + w as u16 > v.width as u16 {
                return Err(EvalError::InvalidExpression);
            }
            Ok(Value {
                width: w,
                bits: (v.bits >> offset) & mask(w),
                defined: (v.defined >> offset) & mask(w),
            })
        }
        ExprKind::Select { condition, yes, no } => {
            let c = eval(condition)?;
            if !c.is_known() {
                return Ok(Value::unknown(w));
            }
            eval(if c.bits != 0 { yes } else { no })
        }
        ExprKind::Unary { op, value } => {
            let v = eval(value)?;
            if !v.is_known() {
                return Ok(Value::unknown(w));
            }
            known(match op {
                UnaryOp::Not => !v.bits,
                UnaryOp::Neg => v.bits.wrapping_neg(),
                UnaryOp::Parity => ((v.bits as u8).count_ones() % 2 == 0) as u64,
                UnaryOp::CountLeadingZeros => {
                    u64::from(v.bits.leading_zeros()) - u64::from(64 - v.width)
                }
                UnaryOp::PopulationCount => u64::from(v.bits.count_ones()),
                UnaryOp::ReverseBits => v.bits.reverse_bits() >> (64 - v.width),
                UnaryOp::ReverseBytes => v.bits.swap_bytes() >> (64 - v.width),
            })
        }
        ExprKind::Binary { op, left, right } => {
            let a = eval(left)?;
            let b = eval(right)?;
            if !a.is_known() || !b.is_known() {
                return Ok(Value::unknown(w));
            }
            let n = b.bits;
            known(match op {
                BinaryOp::Add => a.bits.wrapping_add(b.bits),
                BinaryOp::Sub => a.bits.wrapping_sub(b.bits),
                BinaryOp::Mul => a.bits.wrapping_mul(b.bits),
                BinaryOp::Udiv => {
                    if b.bits == 0 {
                        0
                    } else {
                        a.bits / b.bits
                    }
                }
                BinaryOp::Sdiv => {
                    if b.bits == 0 {
                        0
                    } else {
                        (signed(a.bits, a.width) / signed(b.bits, b.width)) as u64
                    }
                }
                BinaryOp::Urem => {
                    if b.bits == 0 {
                        0
                    } else {
                        a.bits % b.bits
                    }
                }
                BinaryOp::Srem => {
                    if b.bits == 0 {
                        0
                    } else {
                        (signed(a.bits, a.width) % signed(b.bits, b.width)) as u64
                    }
                }
                BinaryOp::UnsignedMultiplyHigh => {
                    ((u128::from(a.bits) * u128::from(b.bits)) >> a.width) as u64
                }
                BinaryOp::SignedMultiplyHigh => {
                    ((signed(a.bits, a.width) * signed(b.bits, b.width)) >> a.width) as u64
                }
                BinaryOp::And => a.bits & b.bits,
                BinaryOp::Or => a.bits | b.bits,
                BinaryOp::Xor => a.bits ^ b.bits,
                BinaryOp::Shl => {
                    if n >= a.width as u64 {
                        0
                    } else {
                        a.bits << n
                    }
                }
                BinaryOp::Lsr => {
                    if n >= a.width as u64 {
                        0
                    } else {
                        a.bits >> n
                    }
                }
                BinaryOp::Asr => (signed(a.bits, a.width) >> n.min(127)) as u64,
                BinaryOp::Ror => {
                    let n = n % a.width as u64;
                    if n == 0 {
                        a.bits
                    } else {
                        (a.bits >> n) | (a.bits << (a.width as u64 - n))
                    }
                }
                BinaryOp::Eq => (a.bits == b.bits) as u64,
                BinaryOp::Ult => (a.bits < b.bits) as u64,
                BinaryOp::Slt => (signed(a.bits, a.width) < signed(b.bits, b.width)) as u64,
            })
        }
        ExprKind::AddCarry { left, right, carry } => {
            let a = eval(left)?;
            let b = eval(right)?;
            let c = eval(carry)?;
            if !a.is_known() || !b.is_known() || !c.is_known() {
                return Ok(Value::unknown(w));
            }
            known((((a.bits as u128) + (b.bits as u128) + (c.bits as u128)) >> a.width) as u64)
        }
        ExprKind::SubBorrow {
            left,
            right,
            borrow,
        } => {
            let a = eval(left)?;
            let b = eval(right)?;
            let c = eval(borrow)?;
            if !a.is_known() || !b.is_known() || !c.is_known() {
                return Ok(Value::unknown(w));
            }
            known(((a.bits as u128) < (b.bits as u128) + (c.bits as u128)) as u64)
        }
        ExprKind::Overflow {
            subtract,
            left,
            right,
            result,
        } => {
            let a = eval(left)?;
            let b = eval(right)?;
            let r = eval(result)?;
            if !a.is_known() || !b.is_known() || !r.is_known() {
                return Ok(Value::unknown(w));
            }
            let s = 1u64 << (a.width - 1);
            known(
                (((if *subtract {
                    a.bits ^ b.bits
                } else {
                    !(a.bits ^ b.bits)
                }) & (a.bits ^ r.bits)
                    & s)
                    != 0) as u64,
            )
        }
    }
}
fn atomic_load_order(order: MemoryOrdering) -> bool {
    matches!(
        order,
        MemoryOrdering::Monotonic
            | MemoryOrdering::Acquire
            | MemoryOrdering::AcquireRcpc
            | MemoryOrdering::AcquireLimited
            | MemoryOrdering::SequentiallyConsistent
    )
}
fn atomic_store_order(order: MemoryOrdering) -> bool {
    matches!(
        order,
        MemoryOrdering::Monotonic
            | MemoryOrdering::Release
            | MemoryOrdering::ReleaseLimited
            | MemoryOrdering::SequentiallyConsistent
    )
}
fn atomic_failure_order(success: MemoryOrdering, failure: MemoryOrdering) -> bool {
    match failure {
        MemoryOrdering::Monotonic => true,
        MemoryOrdering::Acquire => matches!(
            success,
            MemoryOrdering::Acquire
                | MemoryOrdering::AcquireRelease
                | MemoryOrdering::SequentiallyConsistent
        ),
        MemoryOrdering::SequentiallyConsistent => success == MemoryOrdering::SequentiallyConsistent,
        _ => false,
    }
}
/// Pure RCWCheck over effective masks. Failure selects the permitted no-write
/// outcome, including a failed CAS. Numeric bit order is independent of endian.
fn evaluate_rcw_update(
    op: AtomicRcwOp,
    soft: bool,
    width: u8,
    old: u128,
    expected: u128,
    operand: u128,
    mask: u128,
    soft_mask: u128,
    protection: bool,
) -> (u8, Option<u128>) {
    let keep = if width == 128 {
        u128::MAX
    } else {
        u128::from(u64::MAX)
    };
    let new = match op {
        AtomicRcwOp::Clear => old & !operand,
        AtomicRcwOp::Set => old | operand,
        _ => operand,
    } & keep;
    if op == AtomicRcwOp::CompareExchange && old != expected {
        return (10, None);
    }
    let pbit = if width == 128 { 114 } else { 52 };
    let protected = old & (1 << pbit) != 0;
    let valid = old & 1 != 0;
    let hard = protection
        && ((old ^ new) & (1 << pbit) != 0
            || protected && (old ^ new) & 1 != 0
            || protected && valid && (old ^ new) & !mask & keep != 0);
    let soft_fail = soft
        && ((valid || !protection || !protected) && (old ^ new) & 1 != 0
            || valid && (old ^ new) & !soft_mask & keep != 0);
    let nzcv = (u8::from(hard) << 2) | (u8::from(!soft_fail) << 1);
    (nzcv, (nzcv == 2).then_some(new))
}
fn validate_atomic(operation: &AtomicOperation, earlier: &[AtomicStep]) -> Result<(), EvalError> {
    let width = operation.memory.width;
    if operation.memory.kind==MemoryKind::GuardedControlStack &&
        (width!=64 || !matches!(operation.kind,AtomicOperationKind::CompareExchange{..}) || operation.ordering!=MemoryOrdering::Monotonic) {
        return Err(EvalError::InvalidExpression);
    }
    let pair = matches!(operation.kind,
        AtomicOperationKind::LoadPair | AtomicOperationKind::ReadModifyWritePair { .. } | AtomicOperationKind::StorePair { .. }
        | AtomicOperationKind::CompareExchangePair { .. } | AtomicOperationKind::LoadLinkedPair | AtomicOperationKind::LoadLinkedPairSplit
        | AtomicOperationKind::StoreConditionalPair { .. });
    let rcw = matches!(operation.kind, AtomicOperationKind::RestrictedReadModifyWrite { .. });
    if (pair && width != 128) || (rcw && !matches!(width,64|128))
        || (!pair && !rcw && !matches!(width, 8 | 16 | 32 | 64))
        || matches!(operation.scope, MemoryScope::Named(name) if name.trim().is_empty())
    {
        return Err(EvalError::InvalidExpression);
    }
    validate_expression_with_atomics(&operation.memory.address, &[], earlier)?;
    let check = |value: &Expr| {
        if value.ty.width != if pair { 64 } else { width } {
            return Err(EvalError::InvalidExpression);
        }
        validate_expression_with_atomics(value, &[], earlier)
    };
    if operation.ordering == MemoryOrdering::AcquireRcpc
        && !matches!(operation.kind, AtomicOperationKind::Load | AtomicOperationKind::LoadPair) {
        return Err(EvalError::InvalidExpression);
    }
    if matches!(operation.ordering, MemoryOrdering::AcquireLimited | MemoryOrdering::ReleaseLimited)
        && !matches!(operation.kind, AtomicOperationKind::Load | AtomicOperationKind::Store { .. }) {
        return Err(EvalError::InvalidExpression);
    }
    match &operation.kind {
        AtomicOperationKind::Load | AtomicOperationKind::LoadLinked
        | AtomicOperationKind::LoadPair | AtomicOperationKind::LoadLinkedPair | AtomicOperationKind::LoadLinkedPairSplit => {
            if !atomic_load_order(operation.ordering) {
                return Err(EvalError::InvalidExpression);
            }
        }
        AtomicOperationKind::Store { value } | AtomicOperationKind::StoreConditional { value } => {
            if !atomic_store_order(operation.ordering)
                && !(matches!(operation.kind, AtomicOperationKind::StoreConditional { .. })
                    && operation.ordering == MemoryOrdering::AcquireRelease)
            {
                return Err(EvalError::InvalidExpression);
            }
            check(value)?;
        }
        AtomicOperationKind::StorePair { low, high }
        | AtomicOperationKind::StoreConditionalPair { low, high } => {
            if !atomic_store_order(operation.ordering)
                && !(matches!(operation.kind, AtomicOperationKind::StoreConditionalPair { .. })
                    && operation.ordering == MemoryOrdering::AcquireRelease) {
                return Err(EvalError::InvalidExpression);
            }
            check(low)?;
            check(high)?;
        }
        AtomicOperationKind::CompareExchangePair { expected_low, expected_high,
            replacement_low, replacement_high, failure_ordering } => {
            if !atomic_failure_order(operation.ordering, *failure_ordering) {
                return Err(EvalError::InvalidExpression);
            }
            for value in [expected_low, expected_high, replacement_low, replacement_high] {
                check(value)?;
            }
        }
        AtomicOperationKind::ReadModifyWritePair { low, high, .. } => { check(low)?; check(high)?; }
        AtomicOperationKind::ReadModifyWrite { value, .. } => check(value)?,
        AtomicOperationKind::RestrictedReadModifyWrite {expected,operand,mask,soft_mask,protection,..} => {
            if !matches!(operation.ordering,MemoryOrdering::Monotonic|MemoryOrdering::Acquire|MemoryOrdering::Release|MemoryOrdering::AcquireRelease|MemoryOrdering::SequentiallyConsistent) || protection.ty.width!=1 {return Err(EvalError::InvalidExpression);}
            for chunks in [expected,operand,mask,soft_mask] {for (i,value) in chunks.iter().enumerate() {
                if value.ty.width!=64 || (width==64 && i==1 && !matches!(value.kind,ExprKind::Constant(0))) {return Err(EvalError::InvalidExpression);}
                validate_expression_with_atomics(value,&[],earlier)?;
            }}
            validate_expression_with_atomics(protection,&[],earlier)?;
        },
        AtomicOperationKind::FloatingPointReadModifyWrite { value, control, bfloat, .. }=>{
            if !matches!(width,16|32|64)||*bfloat&&width!=16||control.ty.width!=32{return Err(EvalError::InvalidExpression);}
            check(value)?;validate_expression_with_atomics(control,&[],earlier)?;
        },
        AtomicOperationKind::CompareExchange {
            expected,
            replacement,
            failure_ordering,
        } => {
            if !atomic_failure_order(operation.ordering, *failure_ordering) {
                return Err(EvalError::InvalidExpression);
            }
            check(expected)?;
            check(replacement)?;
        }
    }
    Ok(())
}
fn evaluate_atomics<M: Machine>(
    recipe: &Recipe,
    state: &M,
    pending: &mut Vec<AtomicTransition>,
) -> Result<(), EvalError> {
    // None means unread; Some(None) is a known cleared local monitor.
    let mut monitor: Option<Option<ExclusiveReservation>> = None;
    for step in &recipe.atomics {
        if let AtomicStep::Block64(operation)=step {
            let eval=|e:&Expr| {let v=evaluate_validated_expression(e,state,&[],pending,&[],&[])?;if !v.is_known(){return Err(EvalError::UnknownAtomicValue);}Ok(v)};
            let address=evaluate_validated_expression(&operation.address,state,&[],pending,&[],&[])?;
            if !address.is_known(){return Err(EvalError::UnknownAddress);}
            let address=address.bits;
            let kind=match &operation.kind {
                Block64Kind::Load=>Block64RequestKind::Load,
                Block64Kind::Store{chunks,with_status}=>{let mut values=[Value::known(64,0);8];for(i,e)in chunks.iter().enumerate(){values[i]=eval(e)?;}Block64RequestKind::Store{chunks:values,with_status:*with_status}},
            };
            let request=Block64Request{address,tagchecked:operation.tagchecked,kind};
            let observation=state.evaluate_block64(&request)?;
            let (value,clear)=match (&request.kind,&observation) {
                (Block64RequestKind::Load,Block64Observation::Load{chunks,clear_reservation,..}) if chunks.iter().all(|v|v.width==64&&v.is_known())=>(None,*clear_reservation),
                (Block64RequestKind::Store{with_status,..},Block64Observation::Store{status,committed,clear_reservation,..})
                    if status.is_some()==*with_status && (*with_status||*committed) && status.is_none_or(|v|v.width==64&&v.is_known())=>(*status,*clear_reservation),
                _=>return Err(EvalError::InvalidAtomicOutcome),
            };
            if clear {monitor=Some(None);}
            pending.push(AtomicTransition{split_pair_witnesses:None,block64:Some(Block64Transition{request,observation}),request:None,observation:None,value,value_high:None,success:None,stored:None,stored_high:None,monitor:if clear{ExclusiveMonitorEffect::Cleared}else{ExclusiveMonitorEffect::Preserved}});
            continue;
        }
        let AtomicStep::Memory(operation) = step else {
            monitor = Some(None);
            pending.push(AtomicTransition {
                split_pair_witnesses:None,
                block64:None,
                request: None,
                observation: None,
                value: None,
                value_high: None,
                success: None,
                stored: None,
                stored_high: None,
                monitor: ExclusiveMonitorEffect::Cleared,
            });
            continue;
        };
        let eval = |e: &Expr| {
            let value = evaluate_validated_expression(e, state, &[], pending, &[], &[])?;
            if !value.is_known() {
                return Err(EvalError::UnknownAtomicValue);
            }
            Ok(value)
        };
        let address =
            evaluate_validated_expression(&operation.memory.address, state, &[], pending, &[], &[])?;
        if !address.is_known() {
            return Err(EvalError::UnknownAddress);
        }
        let kind = match &operation.kind {
            AtomicOperationKind::LoadPair => AtomicRequestKind::LoadPair,
            AtomicOperationKind::ReadModifyWritePair { operation, low, high } => AtomicRequestKind::ReadModifyWritePair { operation: *operation, low: eval(low)?, high: eval(high)? },
            AtomicOperationKind::StorePair { low, high } => AtomicRequestKind::StorePair { low: eval(low)?, high: eval(high)? },
            AtomicOperationKind::CompareExchangePair { expected_low, expected_high,
                replacement_low, replacement_high, failure_ordering } => AtomicRequestKind::CompareExchangePair {
                expected_low: eval(expected_low)?, expected_high: eval(expected_high)?,
                replacement_low: eval(replacement_low)?, replacement_high: eval(replacement_high)?,
                failure_ordering: *failure_ordering,
            },
            AtomicOperationKind::LoadLinkedPair => AtomicRequestKind::LoadLinkedPair,
            AtomicOperationKind::LoadLinkedPairSplit => AtomicRequestKind::LoadLinkedPairSplit,
            AtomicOperationKind::StoreConditionalPair { low, high } => AtomicRequestKind::StoreConditionalPair { low: eval(low)?, high: eval(high)? },
            AtomicOperationKind::Load => AtomicRequestKind::Load,
            AtomicOperationKind::Store { value } => AtomicRequestKind::Store {
                value: eval(value)?,
            },
            AtomicOperationKind::ReadModifyWrite { operation, value } => {
                AtomicRequestKind::ReadModifyWrite {
                    operation: *operation,
                    value: eval(value)?,
                }
            }
            AtomicOperationKind::FloatingPointReadModifyWrite {operation,bfloat,value,control}=>AtomicRequestKind::FloatingPointReadModifyWrite {operation:*operation,bfloat:*bfloat,value:eval(value)?,control:eval(control)?},
            AtomicOperationKind::RestrictedReadModifyWrite {operation,soft,expected,operand,mask,soft_mask,protection} => {
                let pair=|v:&[Expr;2]| -> Result<[Value;2],EvalError> {Ok([eval(&v[0])?,eval(&v[1])?])};
                AtomicRequestKind::RestrictedReadModifyWrite {operation:*operation,soft:*soft,expected:pair(expected)?,operand:pair(operand)?,mask:pair(mask)?,soft_mask:pair(soft_mask)?,protection:eval(protection)?}
            },
            AtomicOperationKind::CompareExchange {
                expected,
                replacement,
                failure_ordering,
            } => AtomicRequestKind::CompareExchange {
                expected: eval(expected)?,
                replacement: eval(replacement)?,
                failure_ordering: *failure_ordering,
            },
            AtomicOperationKind::LoadLinked => AtomicRequestKind::LoadLinked,
            AtomicOperationKind::StoreConditional { value } => {
                AtomicRequestKind::StoreConditional {
                    value: eval(value)?,
                }
            }
        };
        let reservation = if matches!(kind, AtomicRequestKind::StoreConditional { .. } | AtomicRequestKind::StoreConditionalPair { .. }) {
            if monitor.is_none() {
                monitor = Some(state.read_exclusive_monitor()?);
            }
            monitor.flatten()
        } else {
            None
        };
        let request = AtomicRequest {memory_kind: operation.memory.kind, privilege: operation.memory.privilege,
            address: address.bits,
            width: operation.memory.width,
            endian: operation.memory.endian,
            ordering: operation.ordering,
            scope: operation.scope,
            kind,
            reservation,
        };
        let pair = request.width == 128;
        let (observation, old_high, split_pair_witnesses) = if matches!(request.kind, AtomicRequestKind::LoadLinkedPairSplit) {
            let response=state.evaluate_exclusive_pair(&request,pending)?;
            (AtomicObservation{old:Some(response.low),store_succeeded:None,reservation_token:Some(response.reservation_token),witness:response.witnesses[0]},Some(response.high),Some(response.witnesses))
        } else if pair {
            let response = state.evaluate_atomic_pair(&request, pending)?;
            (response.observation, response.old_high,None)
        } else {
            (state.evaluate_atomic(&request, pending)?, None,None)
        };
        let reads = matches!(
            request.kind,
            AtomicRequestKind::Load
                | AtomicRequestKind::ReadModifyWrite { .. }
                | AtomicRequestKind::FloatingPointReadModifyWrite { .. }
                | AtomicRequestKind::RestrictedReadModifyWrite { .. }
                | AtomicRequestKind::CompareExchange { .. }
                | AtomicRequestKind::LoadLinked
                | AtomicRequestKind::LoadPair
                | AtomicRequestKind::ReadModifyWritePair { .. }
                | AtomicRequestKind::CompareExchangePair { .. }
                | AtomicRequestKind::LoadLinkedPair | AtomicRequestKind::LoadLinkedPairSplit
        );
        if reads != observation.old.is_some()
            || (pair && reads) != old_high.is_some()
            || matches!(request.kind, AtomicRequestKind::StoreConditional { .. } | AtomicRequestKind::StoreConditionalPair { .. })
                != observation.store_succeeded.is_some()
            || matches!(request.kind, AtomicRequestKind::LoadLinked | AtomicRequestKind::LoadLinkedPair | AtomicRequestKind::LoadLinkedPairSplit)
                != observation.reservation_token.is_some()
            || observation.old.is_some_and(|v| {
                v.width != if pair { 64 } else { request.width } || !v.is_known() || v.bits & !mask(v.width) != 0
            })
            || old_high.is_some_and(|v| v.width != 64 || !v.is_known())
        {
            return Err(EvalError::InvalidAtomicOutcome);
        }
        let mut result = AtomicTransition {
            split_pair_witnesses,
            block64:None,
            request: Some(request.clone()),
            observation: Some(observation.clone()),
            value: observation.old,
            value_high: old_high,
            success: None,
            stored: None,
            stored_high: None,
            monitor: ExclusiveMonitorEffect::Preserved,
        };
        match &request.kind {
            AtomicRequestKind::Load | AtomicRequestKind::LoadPair => {}
            AtomicRequestKind::RestrictedReadModifyWrite {operation,soft,expected,operand,mask,soft_mask,protection} => {
                let pack=|v:&[Value;2]|u128::from(v[0].bits)|(u128::from(v[1].bits)<<64);
                let old=u128::from(observation.old.ok_or(EvalError::InvalidAtomicOutcome)?.bits)|(u128::from(old_high.map_or(0,|v|v.bits))<<64);
                let (_,stored)=evaluate_rcw_update(*operation,*soft,request.width,old,pack(expected),pack(operand),pack(mask),pack(soft_mask),protection.bits!=0);
                if let Some(value)=stored {result.stored=Some(Value::known(64,value as u64));if pair {result.stored_high=Some(Value::known(64,(value>>64)as u64));}}
            }
            AtomicRequestKind::ReadModifyWritePair { operation, low, high } => {
                let old_low = observation.old.ok_or(EvalError::InvalidAtomicOutcome)?;
                let old_high = old_high.ok_or(EvalError::InvalidAtomicOutcome)?;
                let apply = |old: Value, value: &Value| Value::known(64, match operation {
                    AtomicPairRmwOp::Exchange => value.bits,
                    AtomicPairRmwOp::And => old.bits & value.bits,
                    AtomicPairRmwOp::Or => old.bits | value.bits,
                });
                result.stored = Some(apply(old_low, low));
                result.stored_high = Some(apply(old_high, high));
            }
            AtomicRequestKind::StorePair { low, high } => {
                result.stored = Some(*low);
                result.stored_high = Some(*high);
            }
            AtomicRequestKind::CompareExchangePair { expected_low, expected_high, replacement_low, replacement_high, .. } => {
                let success = observation.old.ok_or(EvalError::InvalidAtomicOutcome)?.bits == expected_low.bits
                    && old_high.ok_or(EvalError::InvalidAtomicOutcome)?.bits == expected_high.bits;
                result.success = Some(success);
                if success { result.stored = Some(*replacement_low); result.stored_high = Some(*replacement_high); }
            }
            AtomicRequestKind::Store { value } => result.stored = Some(*value),
            AtomicRequestKind::FloatingPointReadModifyWrite {operation,bfloat,value,control}=>{
                let old=observation.old.ok_or(EvalError::InvalidAtomicOutcome)?;
                let raw=control.bits as u32;let mut ctrl=raw&!((1<<26)|(1<<25)|(1<<24)|3|(0x1f<<8)|(1<<15));ctrl|=1<<25;if raw&((1<<24)|1)!=0{ctrl|=1<<24;}
                let operation=if *bfloat{FloatOperation::BFloatBinary{operation:match operation{AtomicFloatRmwOp::Add=>BFloatOperation::Add,AtomicFloatRmwOp::Maximum=>BFloatOperation::Maximum,AtomicFloatRmwOp::Minimum=>BFloatOperation::Minimum,AtomicFloatRmwOp::MaximumNumber=>BFloatOperation::MaximumNumber,AtomicFloatRmwOp::MinimumNumber=>BFloatOperation::MinimumNumber}}}else{match operation{AtomicFloatRmwOp::Add=>FloatOperation::Add,AtomicFloatRmwOp::Maximum=>FloatOperation::MinMax{minimum:false,numeric:false},AtomicFloatRmwOp::Minimum=>FloatOperation::MinMax{minimum:true,numeric:false},AtomicFloatRmwOp::MaximumNumber=>FloatOperation::MinMax{minimum:false,numeric:true},AtomicFloatRmwOp::MinimumNumber=>FloatOperation::MinMax{minimum:true,numeric:true}}};
                let expression=FloatExpression{operation,environment:FloatEnvironment::A64,width:request.width,control:Box::new(Expr::constant(32,u64::from(ctrl))),status:Box::new(Expr::constant(32,0)),inputs:vec![Expr::constant(request.width,old.bits),Expr::constant(request.width,value.bits)],projection:FloatProjection::Value};
                let stored=state.evaluate_float(&expression,&[old,*value],Value::known(32,u64::from(ctrl)),Value::known(32,0))?;
                if stored.width!=request.width||!stored.is_known(){return Err(EvalError::InvalidAtomicOutcome);}result.stored=Some(stored);
            }
            AtomicRequestKind::ReadModifyWrite { operation, value } => {
                let old = observation.old.ok_or(EvalError::InvalidAtomicOutcome)?;
                let bits = match operation {
                    AtomicRmwOp::Exchange => value.bits,
                    AtomicRmwOp::Add => old.bits.wrapping_add(value.bits),
                    AtomicRmwOp::Subtract => old.bits.wrapping_sub(value.bits),
                    AtomicRmwOp::And => old.bits & value.bits,
                    AtomicRmwOp::Or => old.bits | value.bits,
                    AtomicRmwOp::Xor => old.bits ^ value.bits,
                    AtomicRmwOp::SignedMax => {
                        if signed(old.bits, old.width) >= signed(value.bits, value.width) {
                            old.bits
                        } else {
                            value.bits
                        }
                    }
                    AtomicRmwOp::SignedMin => {
                        if signed(old.bits, old.width) <= signed(value.bits, value.width) {
                            old.bits
                        } else {
                            value.bits
                        }
                    }
                    AtomicRmwOp::UnsignedMax => old.bits.max(value.bits),
                    AtomicRmwOp::UnsignedMin => old.bits.min(value.bits),
                };
                result.stored = Some(Value::known(request.width, bits));
            }
            AtomicRequestKind::CompareExchange {
                expected,
                replacement,
                ..
            } => {
                let success =
                    observation.old.ok_or(EvalError::InvalidAtomicOutcome)?.bits == expected.bits;
                result.success = Some(success);
                if success {
                    result.stored = Some(*replacement);
                }
            }
            AtomicRequestKind::LoadLinked | AtomicRequestKind::LoadLinkedPair | AtomicRequestKind::LoadLinkedPairSplit => {
                let reservation = ExclusiveReservation {
                    address: request.address,
                    width: request.width,
                    scope: request.scope,
                    token: observation
                        .reservation_token
                        .ok_or(EvalError::InvalidAtomicOutcome)?,
                };
                monitor = Some(Some(reservation));
                result.monitor = ExclusiveMonitorEffect::Set(reservation);
            }
            AtomicRequestKind::StoreConditional { value }
            | AtomicRequestKind::StoreConditionalPair { low: value, .. } => {
                let success = observation
                    .store_succeeded
                    .ok_or(EvalError::InvalidAtomicOutcome)?;
                if success
                    && !request.reservation.is_some_and(|r| {
                        r.address == request.address
                            && r.width == request.width
                            && r.scope == request.scope
                    })
                {
                    return Err(EvalError::InvalidAtomicOutcome);
                }
                result.success = Some(success);
                if success {
                    result.stored = Some(*value);
                    if let AtomicRequestKind::StoreConditionalPair { high, .. } = &request.kind {
                        result.stored_high = Some(*high);
                    }
                }
                monitor = Some(None);
                result.monitor = ExclusiveMonitorEffect::Cleared;
            }
        }
        pending.push(result);
    }
    Ok(())
}

fn resolve_indexed_register(s: &IndexedRegister, index: Value) -> Result<RegisterSlice, EvalError> {
    if !s.valid_dimensions() || index.width != s.index.ty.width {
        return Err(EvalError::InvalidExpression);
    }
    if !index.is_known() {
        return Err(EvalError::UnknownRegisterIndex);
    }
    if index.bits >= u64::from(s.count) {
        return Err(EvalError::RegisterIndexOutOfRange);
    }
    Ok(RegisterSlice {
        register: Register {
            bank: s.bank,
            index: (u64::from(s.base) + index.bits * u64::from(s.stride)) as u16,
        },
        offset: s.offset as u8,
        width: s.width,
        parent_width: s.parent_width as u8,
    })
}
fn append_register_write<M: Machine>(
    t: &mut Transition,
    state: &M,
    s: &RegisterSlice,
    policy: &WritePolicy,
    v: Value,
) -> Result<(), EvalError> {
    if v.width != s.width
        || s.parent_width == 0
        || s.parent_width > 64
        || s.offset as u16 + s.width as u16 > s.parent_width as u16
    {
        return Err(EvalError::InvalidExpression);
    }
    let range = mask(s.width) << s.offset;
    let keep = if *policy == WritePolicy::Preserve {
        mask(s.parent_width) & !range
    } else {
        0
    };
    let old = if keep == 0 {
        Value::known(s.parent_width, 0)
    } else {
        t.registers
            .iter()
            .rev()
            .find(|write| write.register == s.register)
            .map(|write| write.value)
            .unwrap_or_else(|| state.read_register(s.register))
    };
    if old.width < s.parent_width || old.width > 64 {
        return Err(EvalError::InvalidExpression);
    }
    let known_zero = if *policy == WritePolicy::ZeroUpper {
        mask(s.parent_width) & !range
    } else {
        0
    };
    t.registers.push(RegisterWrite {
        register: s.register,
        value: Value {
            width: s.parent_width,
            bits: (old.bits & keep) | ((v.bits & mask(s.width)) << s.offset),
            defined: (old.defined & keep)
                | ((v.defined & mask(s.width)) << s.offset)
                | known_zero,
        },
    });
    Ok(())
}

/// Failure with the explicitly published restart state, if this instruction
/// supports partial read progress. No ordinary effects are included in it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluationFailure {
    pub error: EvalError,
    pub published: Option<Transition>,
}
/// Evaluate an instruction and retain architecturally committed read progress
/// on failure. The caller applies `published` before delivering a memory fault.
pub fn evaluate_with_progress<M: Machine>(recipe: &Recipe, state: &M) -> Result<Transition, EvaluationFailure> {
    let mut published = None;
    evaluate_inner(recipe, state, &mut published)
        .map_err(|error| EvaluationFailure { error, published })
}
/// Produce a pending parallel transition. Use evaluate_with_progress for
/// restartable instructions when fault publication is required.
pub fn evaluate<M: Machine>(recipe: &Recipe, state: &M) -> Result<Transition, EvalError> {
    evaluate_with_progress(recipe, state).map_err(|failure| failure.error)
}
fn publish_read_progress<M: Machine>(recipe: &Recipe, state: &M, stage: usize,
    temps: &[Value], wide: &[MemoryReadResult], choices: &[Value],
    transition: &mut Transition, published: &mut Option<Transition>) -> Result<(), EvalError> {
    let Some(progress) = &recipe.read_progress else { return Ok(()); };
    for step in progress.updates.iter().filter(|step| step.after_read == stage) {
        if let Some(condition) = &step.condition {
            let condition = evaluate_validated_expression(condition, state, temps, &[], wide, choices)?;
            if !condition.is_known() { return Err(EvalError::UnknownCondition); }
            if condition.bits == 0 { continue; }
        }
        let update = &step.update;
        let value = evaluate_validated_expression(&update.value, state, temps, &[], wide, choices)?;
        append_register_write(transition, state, &update.destination, &update.policy, value)?;
    }
    let mut snapshot = transition.clone();
    snapshot.next_pc = evaluate_validated_expression(&progress.restart, state, temps, &[], &[], choices)?;
    *published = Some(snapshot);
    Ok(())
}
fn evaluate_inner<M: Machine>(recipe: &Recipe, state: &M, published: &mut Option<Transition>) -> Result<Transition, EvalError> {
    recipe.validate()?;
    let mut t = Transition {
        registers: vec![],
        memory: vec![],
        allocation_tags: vec![],
        wide_memory: vec![],
        atomics: vec![],
        events: vec![],
        next_pc: evaluate_validated_expression(&recipe.flow.fallthrough, state, &[], &[], &[], &[])?,
        trap: None,
    };
    for (kind, condition) in &recipe.entry_traps {
        let condition = evaluate_validated_expression(condition, state, &[], &[], &[], &[])?;
        if !condition.is_known() { return Err(EvalError::UnknownCondition); }
        if condition.bits != 0 { t.trap = Some(*kind); return Ok(t); }
    }
    let guard = evaluate_validated_expression(&recipe.guard, state, &[], &[], &[], &[])?;
    if !guard.is_known() {
        return Err(EvalError::UnknownCondition);
    }
    if guard.bits == 0 {
        apply_always_writes(recipe, state, &mut t)?;
        return Ok(t);
    }
    for(kind,condition)in &recipe.preflight_traps{let condition=evaluate_validated_expression(condition,state,&[],&[],&[],&[])?;if !condition.is_known(){return Err(EvalError::UnknownCondition);}if condition.bits!=0{t.trap=Some(*kind);return Ok(t);}}
    let mut choices = Vec::with_capacity(recipe.choices.len());
    for (index, choice) in recipe.choices.iter().enumerate() {
        if let Some(condition) = &choice.condition {
            let condition = evaluate_validated_expression(condition, state, &[], &[], &[], &choices)?;
            if !condition.is_known() { return Err(EvalError::UnknownCondition); }
            if condition.bits == 0 { choices.push(Value::unknown(choice.width)); continue; }
        }
        let value = state.choose(index, choice.width)?;
        if value.width != choice.width || !value.is_known()
            || value.bits & !mask(choice.width) != 0 || value.defined & !mask(choice.width) != 0 {
            return Err(EvalError::InvalidChoiceOutcome);
        }
        choices.push(value);
    }
    evaluate_atomics(recipe, state, &mut t.atomics)?;
    t.events
        .extend((0..t.atomics.len()).map(OrderedEvent::Atomic));
    let mut temps = Vec::with_capacity(recipe.temporaries.len());
    for expression in &recipe.temporaries[..recipe.pre_read_bindings] {
        temps.push(evaluate_validated_expression(expression, state, &temps, &[], &[], &choices)?);
    }
    let mut wide = Vec::with_capacity(recipe.wide_loads.len());
    publish_read_progress(recipe, state, 0, &temps, &wide, &choices, &mut t, published)?;
    for (index, memory) in recipe.wide_loads.iter().enumerate() {
        if let Some(condition) = &recipe.wide_load_conditions[index] {
            let condition = evaluate_validated_expression(condition, state, &temps, &[], &wide, &choices)?;
            if !condition.is_known() { return Err(EvalError::UnknownCondition); }
            if condition.bits == 0 {
                wide.push(MemoryReadResult {
                    chunks: (0..memory.chunk_count()).map(|chunk| Value::unknown(memory.chunk_width(chunk).unwrap())).collect(),
                    success: Value::unknown(1),
                });
                publish_read_progress(recipe, state, index + 1, &temps, &wide, &choices, &mut t, published)?;
                continue;
            }
        }
        let address = evaluate_validated_expression(&memory.address, state, &temps, &[], &wide, &choices)?;
        if !address.is_known() { return Err(EvalError::UnknownAddress); }
        let values = if memory.width <= 64 {
            let value = if recipe.wide_load_recovery[index].is_empty() {
                if memory.kind==MemoryKind::GuardedControlStack {state.read_guarded_control_stack(address.bits,memory.endian,memory.privilege)} else {state.read_memory_for_access(address.bits, memory.width as u8, memory.endian, memory.privilege)}
            } else {
                state.try_read_memory_for_access(address.bits, memory.width as u8, memory.endian, memory.privilege)
            };
            value.map(|value| vec![value])
        } else {
            state.read_wide_memory_for_access(address.bits, memory.width, memory.endian, memory.privilege)
        };
        let (values, success) = match values {
            Ok(values) => (values, true),
            Err(EvalError::MemoryFault(kind)) if recipe.wide_load_recovery[index].contains(&kind) => {
                (vec![Value::known(memory.width as u8, 0)], false)
            },
            Err(error) => return Err(error),
        };
        if values.len() != memory.chunk_count() || values.iter().enumerate().any(|(chunk,value)| Some(value.width) != memory.chunk_width(chunk)) {
            return Err(EvalError::InvalidExpression);
        }
        wide.push(MemoryReadResult { chunks: values, success: Value::known(1, u64::from(success)) });
        publish_read_progress(recipe, state, index + 1, &temps, &wide, &choices, &mut t, published)?;
    }
    for expression in &recipe.temporaries[recipe.pre_read_bindings..] {
        temps.push(evaluate_validated_expression(
            expression, state, &temps, &t.atomics, &wide, &choices,
        )?)
    }
    for effect in &recipe.effects {
        match effect {
            Effect::TimedWait{interrupt,source,deadline,condition}=>{
                let selected=evaluate_validated_expression(condition,state,&temps,&t.atomics,&wide,&choices)?;
                if !selected.is_known(){return Err(EvalError::UnknownCondition);}
                if selected.bits==0{continue;}
                let deadline=evaluate_validated_expression(deadline,state,&temps,&t.atomics,&wide,&choices)?;
                if !deadline.is_known(){return Err(EvalError::UnknownAtomicValue);}
                let request=TimedWaitRequest{interrupt:*interrupt,source:*source,deadline:deadline.bits};
                let outcome=state.timed_wait(&request)?;
                if outcome==TimedWaitOutcome::ClearEvent&&*interrupt{return Err(EvalError::InvalidEnvironmentOutcome);}
                t.events.push(OrderedEvent::TimedWait{request,outcome});
                match outcome{
                    TimedWaitOutcome::ClearEvent=>append_register_write(&mut t,state,&register("a64.event_register",0,1,1),&WritePolicy::ZeroUpper,Value::known(1,0))?,
                    TimedWaitOutcome::ProtectionTrap=>{t.trap=Some(TrapKind::Protection);return Ok(t);},
                    TimedWaitOutcome::InvalidInstruction=>{t.trap=Some(TrapKind::InvalidInstruction);return Ok(t);},
                    TimedWaitOutcome::FallThrough=>{},
                }
            }
            Effect::Wait { allow_protection_trap } => {
                let outcome = state.wait(*allow_protection_trap)?;
                if outcome == WaitOutcome::ProtectionTrap && !allow_protection_trap {
                    return Err(EvalError::InvalidEnvironmentOutcome);
                }
                t.events.push(OrderedEvent::Wait { allow_protection_trap: *allow_protection_trap, outcome });
                if outcome == WaitOutcome::ProtectionTrap {
                    t.trap = Some(TrapKind::Protection);
                    return Ok(t);
                }
            }
            Effect::SendEvent { local } => {
                state.send_event(*local)?;
                t.events.push(OrderedEvent::SendEvent { local: *local });
            }
            Effect::Barrier {
                kind,
                scope,
                access,
                condition,
            } => {
                if let Some(condition) = condition {
                    let value = evaluate_validated_expression(condition, state, &temps, &t.atomics, &wide, &choices)?;
                    if !value.is_known() { return Err(EvalError::UnknownCondition); }
                    if value.bits == 0 { continue; }
                }
                t.events.push(OrderedEvent::Barrier(Barrier { kind: *kind, scope: *scope, access: *access }));
            },
            Effect::ExclusiveMonitorClear => t.events.push(OrderedEvent::ExclusiveMonitorClear),
            Effect::StoreAllocationTag {address,tag,privilege,condition} => {
                if let Some(condition)=condition {let value=evaluate_validated_expression(condition,state,&temps,&t.atomics,&wide,&choices)?;if !value.is_known(){return Err(EvalError::UnknownCondition);}if value.bits==0{continue;}}
                let address=evaluate_validated_expression(address,state,&temps,&t.atomics,&wide,&choices)?;
                if !address.is_known(){return Err(EvalError::UnknownAddress);}
                let tag=evaluate_validated_expression(tag,state,&temps,&t.atomics,&wide,&choices)?;
                t.events.push(OrderedEvent::AllocationTagStore(t.allocation_tags.len()));
                t.allocation_tags.push(AllocationTagWrite {address:address.bits,tag,privilege:*privilege});
            }
            Effect::WriteRegister {
                destination: s,
                policy,
                value,
            } | Effect::WriteRegisterConditional {
                destination: s,
                policy,
                value,
                ..
            } => {
                if let Effect::WriteRegisterConditional { condition, .. } = effect {
                    let condition = evaluate_validated_expression(condition, state, &temps, &t.atomics, &wide, &choices)?;
                    if !condition.is_known() { return Err(EvalError::UnknownCondition); }
                    if condition.bits == 0 { continue; }
                }
                let v = evaluate_validated_expression(value, state, &temps, &t.atomics, &wide, &choices)?;
                append_register_write(&mut t, state, s, policy, v)?;
            }
            Effect::WriteIndexedRegister { destination, policy, value } => {
                let index = evaluate_validated_expression(&destination.index, state, &temps, &t.atomics, &wide, &choices)?;
                let selected = resolve_indexed_register(destination, index)?;
                let value = evaluate_validated_expression(value, state, &temps, &t.atomics, &wide, &choices)?;
                append_register_write(&mut t, state, &selected, policy, value)?;
            }
            Effect::StoreWide { memory, chunks } | Effect::StoreWideConditional { memory, chunks, .. } => {
                if let Effect::StoreWideConditional { condition, .. } = effect {
                    let condition = evaluate_validated_expression(condition, state, &temps, &t.atomics, &wide, &choices)?;
                    if !condition.is_known() { return Err(EvalError::UnknownCondition); }
                    if condition.bits == 0 { continue; }
                }
                let address = evaluate_validated_expression(&memory.address, state, &temps, &t.atomics, &wide, &choices)?;
                if !address.is_known() { return Err(EvalError::UnknownAddress); }
                let chunks = chunks.iter().map(|e| evaluate_validated_expression(e, state, &temps, &t.atomics, &wide, &choices)).collect::<Result<Vec<_>,_>>()?;
                t.events.push(OrderedEvent::WideStore(t.wide_memory.len()));
                t.wide_memory.push(WideMemoryWrite {privilege: memory.privilege, address: address.bits, width: memory.width, chunks, endian: memory.endian });
            }
            Effect::Store { memory: m, value } | Effect::StoreConditional { memory: m, value, .. } => {
                if let Effect::StoreConditional { condition, .. } = effect {
                    let condition = evaluate_validated_expression(condition, state, &temps, &t.atomics, &wide, &choices)?;
                    if !condition.is_known() { return Err(EvalError::UnknownCondition); }
                    if condition.bits == 0 { continue; }
                }
                let a = evaluate_validated_expression(&m.address, state, &temps, &t.atomics, &wide, &choices)?;
                if !a.is_known() {
                    return Err(EvalError::UnknownAddress);
                }
                let value = evaluate_validated_expression(value, state, &temps, &t.atomics, &wide, &choices)?;
                if value.width != m.width {
                    return Err(EvalError::InvalidExpression);
                }
                t.events.push(OrderedEvent::Store(t.memory.len()));
                t.memory.push(MemoryWrite {guarded_control_stack:m.kind==MemoryKind::GuardedControlStack,privilege: m.privilege,
                    address: a.bits,
                    value,
                    endian: m.endian,
                });
            }
            Effect::Trap { kind, condition } => {
                let condition =
                    evaluate_validated_expression(condition, state, &temps, &t.atomics, &wide, &choices)?;
                if !condition.is_known() {
                    return Err(EvalError::UnknownCondition);
                }
                if condition.bits != 0 {
                    t.trap = Some(*kind);
                    return Ok(t);
                }
            }
        }
    }
    let condition =
        evaluate_validated_expression(&recipe.flow.condition, state, &temps, &t.atomics, &wide, &choices)?;
    if !condition.is_known() {
        return Err(EvalError::UnknownCondition);
    }
    if condition.bits != 0 {
        t.next_pc = evaluate_validated_expression(&recipe.flow.target, state, &temps, &t.atomics, &wide, &choices)?
    }
    apply_always_writes(recipe, state, &mut t)?;
    Ok(t)
}

fn apply_always_writes<M: Machine>(
    recipe: &Recipe,
    state: &M,
    transition: &mut Transition,
) -> Result<(), EvalError> {
    for (update, condition) in recipe.always_writes.iter().map(|u| (u, None))
        .chain(recipe.completion_writes.iter().map(|(u,c)| (u, Some(c)))) {
        if let Some(condition) = condition {
            let condition = evaluate_validated_expression(condition, state, &[], &[], &[], &[])?;
            if !condition.is_known() { return Err(EvalError::UnknownCondition); }
            if condition.bits == 0 { continue; }
        }
        let slice = update.destination;
        let value = evaluate_validated_expression(&update.value, state, &[], &[], &[], &[])?;
        let range = mask(slice.width) << slice.offset;
        let keep = if update.policy == WritePolicy::Preserve {
            mask(slice.parent_width) & !range
        } else {
            0
        };
        let old = if keep == 0 {
            Value::known(slice.parent_width, 0)
        } else {
            transition
                .registers
                .iter()
                .rev()
                .find(|write| write.register == slice.register)
                .map(|write| write.value)
                .unwrap_or_else(|| state.read_register(slice.register))
        };
        if old.width < slice.parent_width || old.width > 64 {
            return Err(EvalError::InvalidExpression);
        }
        transition.registers.push(RegisterWrite {
            register: slice.register,
            value: Value {
                width: slice.parent_width,
                bits: (old.bits & keep) | ((value.bits & mask(slice.width)) << slice.offset),
                defined: (old.defined & keep)
                    | ((value.defined & mask(slice.width)) << slice.offset)
                    | if update.policy == WritePolicy::ZeroUpper {
                        mask(slice.parent_width) & !range
                    } else {
                        0
                    },
            },
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct State;
    impl Machine for State {
        fn read_register(&self, r: Register) -> Value {
            Value::known(64, if r.index == 0 { 0xaabbccddeeff0011 } else { 0 })
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            Err(EvalError::Memory)
        }
    }
    fn ev(e: Expr) -> Value {
        evaluate_expression(&e, &State, &[]).unwrap()
    }
    #[test]
    fn exhaustive_eight_bit_carry_borrow_overflow() {
        for a in 0..=255u64 {
            for b in 0..=255u64 {
                for ci in 0..=1u64 {
                    let x = Expr::constant(8, a);
                    let y = Expr::constant(8, b);
                    let carry = Expr::constant(1, ci);
                    let sum = a + b + ci;
                    let difference = a as i64 - b as i64 - ci as i64;
                    assert_eq!(
                        ev(Expr::add_carry(x.clone(), y.clone(), carry.clone())).bits,
                        (sum > 255) as u64
                    );
                    assert_eq!(
                        ev(Expr::sub_borrow(x.clone(), y.clone(), carry)).bits,
                        (difference < 0) as u64
                    );
                    let sa = a as u8 as i8 as i64;
                    let sb = b as u8 as i8 as i64;
                    let overflow = !(-128..=127).contains(&(sa + sb + ci as i64));
                    assert_eq!(
                        ev(Expr::overflow(
                            false,
                            x.clone(),
                            y.clone(),
                            Expr::constant(8, sum)
                        ))
                        .bits,
                        overflow as u64
                    );
                    let overflow = !(-128..=127).contains(&(sa - sb - ci as i64));
                    assert_eq!(
                        ev(Expr::overflow(
                            true,
                            x,
                            y,
                            Expr::constant(8, difference as u64)
                        ))
                        .bits,
                        overflow as u64
                    );
                }
            }
        }
    }
    #[test]
    fn sixty_four_bit_carry_and_signed_extension() {
        assert_eq!(
            ev(Expr::add_carry(
                Expr::constant(64, u64::MAX),
                Expr::constant(64, 0),
                Expr::constant(1, 1)
            ))
            .bits,
            1
        );
        assert_eq!(
            ev(Expr::cast(Expr::constant(8, 0x80), 64, true)).bits,
            0xffffffffffffff80
        );
        assert_eq!(
            ev(Expr::binary(
                BinaryOp::Asr,
                Expr::constant(64, 0x8000000000000000),
                Expr::constant(64, 255)
            ))
            .bits,
            u64::MAX
        );
    }
    #[test]
    fn subregisters_and_unknown_flags_are_preserved() {
        let mut r = Recipe::new(4, 64);
        let mut s = register("test", 0, 8, 64);
        s.offset = 8;
        r.write(
            s,
            WritePolicy::Preserve,
            Expr::undefined(8, "undefined test"),
        );
        let t = evaluate(&r, &State).unwrap();
        assert_eq!(t.registers[0].value.bits, 0xaabbccddeeff0011);
        assert_eq!(t.registers[0].value.defined, 0xffffffffffff00ff);
        let mut r = Recipe::new(4, 64);
        r.write(
            register("test", 0, 32, 64),
            WritePolicy::ZeroUpper,
            Expr::constant(32, 0x1234),
        );
        let t = evaluate(&r, &State).unwrap();
        assert_eq!(t.registers[0].value, Value::known(64, 0x1234));
    }
    #[test]
    fn temporaries_and_all_reads_use_original_input() {
        let mut r = Recipe::new(4, 64);
        let reg = register("test", 0, 64, 64);
        let target = r.bind(Expr::register(reg));
        r.write(reg, WritePolicy::ZeroUpper, Expr::constant(64, 7));
        r.branch(FlowKind::Branch, Expr::constant(1, 1), target);
        let t = evaluate(&r, &State).unwrap();
        assert_eq!(t.next_pc.bits, 0xaabbccddeeff0011);
        assert_eq!(t.registers[0].value.bits, 7);
    }
    #[test]
    fn pipeline_updates_advance_when_predication_fails_and_read_incoming_state() {
        let reg = register("test", 0, 64, 64);
        for active in [0, 1] {
            let mut r = Recipe::new(4, 64);
            r.guard = Expr::constant(1, active);
            r.write(reg, WritePolicy::ZeroUpper, Expr::constant(64, 7));
            r.write_always(
                reg,
                WritePolicy::ZeroUpper,
                Expr::binary(BinaryOp::Add, Expr::register(reg), Expr::constant(64, 1)),
            );
            let t = evaluate(&r, &State).unwrap();
            assert_eq!(t.registers.last().unwrap().value.bits, 0xaabbccddeeff0012);
        }
        let mut invalid = Recipe::new(4, 64);
        let temporary = invalid.bind(Expr::constant(64, 1));
        invalid.write_always(reg, WritePolicy::ZeroUpper, temporary);
        assert_eq!(invalid.validate(), Err(EvalError::InvalidExpression));
    }
    #[test]
    fn unsupported_and_faulting_recipes_never_produce_a_transition() {
        assert_eq!(
            evaluate(&Recipe::unsupported("system", 4, 64), &State),
            Err(EvalError::Unsupported)
        );
        let mut r = Recipe::new(4, 64);
        r.bind(Expr::load(Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(Expr::constant(64, 0)),
            width: 64,
            endian: Endian::Little,
        }));
        assert_eq!(evaluate(&r, &State), Err(EvalError::Memory));
        r.guard = Expr::constant(1, 0);
        assert_eq!(evaluate(&r, &State).unwrap().next_pc.bits, 4);
    }
    #[test]
    fn malformed_expression_widths_report_errors() {
        for w in [0, 65, 255] {
            let invalid = Expr::constant(w, 0);
            assert_eq!(
                evaluate_expression(&invalid, &State, &[]),
                Err(EvalError::InvalidExpression)
            );
        }
        let mut invalid = Expr::binary(BinaryOp::Add, Expr::constant(8, 1), Expr::constant(16, 2));
        assert_eq!(
            evaluate_expression(&invalid, &State, &[]),
            Err(EvalError::InvalidExpression)
        );
        invalid = Expr::register(RegisterSlice {
            register: Register {
                bank: "test",
                index: 0,
            },
            offset: 64,
            width: 1,
            parent_width: 64,
        });
        assert_eq!(
            evaluate_expression(&invalid, &State, &[]),
            Err(EvalError::InvalidExpression)
        );
        invalid = Expr::extract(Expr::constant(64, 0), 64, 1);
        assert_eq!(
            evaluate_expression(&invalid, &State, &[]),
            Err(EvalError::InvalidExpression)
        );
    }

    struct NoReads;
    impl Machine for NoReads {
        fn read_register(&self, _: Register) -> Value {
            panic!("this transition must not read incoming registers")
        }
        fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
            panic!("validation must precede memory access")
        }
    }

    #[test]
    fn validation_checks_inactive_branches_and_forward_temporaries() {
        let invalid = Expr::extract(Expr::constant(8, 1), 8, 1);
        let select = Expr::select(Expr::constant(1, 0), invalid, Expr::constant(1, 0));
        assert_eq!(
            evaluate_expression(&select, &NoReads, &[]),
            Err(EvalError::InvalidExpression)
        );
        let mut recipe = Recipe::new(4, 64);
        recipe.guard = Expr::constant(1, 0);
        recipe.temporaries.push(Expr {
            ty: Expr::constant(8, 0).ty,
            kind: ExprKind::Temporary(0),
        });
        assert_eq!(
            evaluate(&recipe, &NoReads),
            Err(EvalError::InvalidExpression)
        );
    }

    #[test]
    fn validation_precedes_state_access_and_rejects_nonbyte_stores() {
        let mut recipe = Recipe::new(4, 64);
        recipe.bind(Expr::load(Memory {kind: Default::default(), privilege: Default::default(),
            address: Box::new(Expr::constant(64, 0)),
            width: 8,
            endian: Endian::Little,
        }));
        recipe.effects.push(Effect::Store {
            memory: Memory {kind: Default::default(), privilege: Default::default(),
                address: Box::new(Expr::constant(64, 1)),
                width: 1,
                endian: Endian::Little,
            },
            value: Expr::constant(1, 1),
        });
        assert_eq!(
            evaluate(&recipe, &NoReads),
            Err(EvalError::InvalidExpression)
        );
        let mut recipe = Recipe::new(4, 64);
        let mut slice = register("test", 0, 8, 64);
        slice.offset = 8;
        recipe.write(slice, WritePolicy::ZeroUpper, Expr::constant(8, 0));
        assert_eq!(recipe.validate(), Err(EvalError::InvalidExpression));
    }

    #[test]
    fn complete_parent_writes_have_no_incoming_dependency() {
        let mut recipe = Recipe::new(4, 64);
        recipe.write(
            register("test", 0, 32, 64),
            WritePolicy::ZeroUpper,
            Expr::constant(32, 7),
        );
        assert_eq!(
            evaluate(&recipe, &NoReads).unwrap().registers[0].value,
            Value::known(64, 7)
        );
        recipe.effects.clear();
        recipe.write(
            register("test", 0, 64, 64),
            WritePolicy::Preserve,
            Expr::constant(64, 9),
        );
        assert_eq!(
            evaluate(&recipe, &NoReads).unwrap().registers[0].value,
            Value::known(64, 9)
        );
    }

    #[test]
    fn insufficient_parent_state_is_an_error() {
        struct Short;
        impl Machine for Short {
            fn read_register(&self, _: Register) -> Value {
                Value::known(32, 0)
            }
            fn read_memory(&self, _: u64, _: u8, _: Endian) -> Result<Value, EvalError> {
                Err(EvalError::Memory)
            }
        }
        assert_eq!(
            evaluate_expression(&Expr::register(register("test", 0, 64, 64)), &Short, &[]),
            Err(EvalError::InvalidExpression)
        );
        let mut recipe = Recipe::new(4, 64);
        recipe.write(
            register("test", 0, 8, 64),
            WritePolicy::Preserve,
            Expr::constant(8, 1),
        );
        assert_eq!(evaluate(&recipe, &Short), Err(EvalError::InvalidExpression));
    }
}
