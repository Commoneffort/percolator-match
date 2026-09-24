//! Unified Matcher Context for Percolator Markets
//!
//! Single context structure supporting multiple matcher modes:
//! - Passive (kind=0): Fixed spread around oracle price
//! - vAMM (kind=1): Spread + impact pricing with configurable liquidity curve
//!
//! All matchers use the same MatcherCtx layout with a `kind` field.

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    MatcherCall, MatcherReturn, CTX_VAMM_LEN, CTX_VAMM_OFFSET, FLAG_PARTIAL_OK, FLAG_VALID,
    MATCHER_ABI_VERSION, MATCHER_BATCH_HEADER_LEN, MATCHER_BATCH_LEG_LEN, MATCHER_BATCH_MAX_LEGS,
    MATCHER_CONTEXT_LEN, MATCHER_RETURN_LEN,
};

// =============================================================================
// Matcher Kind
// =============================================================================

/// Matcher kind selector
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatcherKind {
    /// Passive: Fixed spread around oracle price
    Passive = 0,
    /// vAMM: Spread + impact pricing with configurable liquidity curve
    Vamm = 1,
}

impl TryFrom<u8> for MatcherKind {
    type Error = ProgramError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MatcherKind::Passive),
            1 => Ok(MatcherKind::Vamm),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

// =============================================================================
// Unified Matcher Context Structure
// =============================================================================

/// Magic number for initialized context ("CTAMCREP" stored, reads as "PERCMATC")
pub const MATCHER_MAGIC: u64 = 0x5045_5243_4d41_5443;
/// Magic used by contexts initialized before commit 44d4cfa. Such contexts are never treated as
/// fresh: tag 2 refuses any context region that is not entirely zero.
pub const LEGACY_MATCHER_MAGIC: u64 = 0x4354_414d_4352_4550;
/// Current context version. Version 4 moved inventory into a per-asset table.
pub const MATCHER_VERSION: u32 = 4;
/// Version 3 contexts kept one context-wide inventory scalar; it is migrated to asset 0 on read.
pub const MATCHER_VERSION_V3: u32 = 3;

/// Number of distinct assets a context can hold nonzero inventory in at the same time.
pub const MATCHER_MAX_ASSETS: usize = 6;

/// Unified matcher context stored at offset 64 in matcher context account
///
/// Layout (256 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("PERCMATC")
/// 8       4     version
/// 12      1     kind (0=Passive, 1=vAMM)
/// 13      3     _pad0
/// 16      32    lp_pda (LP PDA for signature verification)
/// 48      4     trading_fee_bps
/// 52      4     base_spread_bps
/// 56      4     max_total_bps
/// 60      4     impact_k_bps (vAMM only, 0 for passive)
/// 64      16    liquidity_notional_e6 (vAMM only, 0 for passive)
/// 80      16    max_fill_abs
/// 96      16    inventory_base (net sum over assets; informational only)
/// 112     8     last_oracle_price_e6
/// 120     8     last_exec_price_e6
/// 128     16    max_inventory_abs (per asset)
/// 144     1     asset_slots_used (bitmap over the 6 inventory slots)
/// 145     3     _pad1
/// 148     12    asset_ids ([u16; 6])
/// 160     96    asset_inventory ([i128; 6])
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MatcherCtx {
    // ---- Header (16 bytes) ----
    /// Magic number for initialization check
    pub magic: u64, // 8 bytes, offset 0
    /// Version number
    pub version: u32, // 4 bytes, offset 8
    /// Matcher kind: 0 = Passive, 1 = vAMM
    pub kind: u8, // 1 byte, offset 12
    pub _pad0: [u8; 3], // 3 bytes, offset 13

    // ---- LP PDA (32 bytes) ----
    /// LP PDA that must sign matcher calls
    pub lp_pda: [u8; 32], // 32 bytes, offset 16

    // ---- Fee/Spread Parameters (16 bytes) ----
    /// Trading fee in basis points (e.g., 5 = 0.05%)
    pub trading_fee_bps: u32, // 4 bytes, offset 48
    /// Base spread in basis points (e.g., 10 = 0.10%)
    pub base_spread_bps: u32, // 4 bytes, offset 52
    /// Maximum total bps cap (e.g., 200 = 2.00%)
    pub max_total_bps: u32, // 4 bytes, offset 56
    /// Impact multiplier (vAMM only, 0 for passive)
    pub impact_k_bps: u32, // 4 bytes, offset 60

    // ---- Liquidity/Fill Parameters (32 bytes) ----
    /// Quoting depth in notional-e6 (vAMM only, 0 for passive)
    pub liquidity_notional_e6: u128, // 16 bytes, offset 64
    /// Maximum |exec_size| per call (0 = zero fill only)
    pub max_fill_abs: u128, // 16 bytes, offset 80

    // ---- State (32 bytes) ----
    /// Net LP inventory summed over all assets. Informational only: limits and pricing use the
    /// per-asset table, because raw base units of different assets are not nettable.
    pub inventory_base: i128, // 16 bytes, offset 96
    /// Last oracle price seen
    pub last_oracle_price_e6: u64, // 8 bytes, offset 112
    /// Last execution price
    pub last_exec_price_e6: u64, // 8 bytes, offset 120

    // ---- Limits (16 bytes) ----
    /// Maximum absolute inventory per asset (0 = no limit)
    pub max_inventory_abs: u128, // 16 bytes, offset 128

    // ---- Per-asset inventory (112 bytes) ----
    /// Bit i set when slot i holds an asset
    pub asset_slots_used: u8, // 1 byte, offset 144
    pub _pad1: [u8; 3], // 3 bytes, offset 145
    /// Asset index held by each slot
    pub asset_ids: [u16; MATCHER_MAX_ASSETS], // 12 bytes, offset 148
    /// LP inventory in base units for each slot
    pub asset_inventory: [i128; MATCHER_MAX_ASSETS], // 96 bytes, offset 160
}

// Compile-time size check
const _: () = assert!(core::mem::size_of::<MatcherCtx>() == CTX_VAMM_LEN);

impl Default for MatcherCtx {
    fn default() -> Self {
        Self {
            magic: 0,
            version: 0,
            kind: 0,
            _pad0: [0; 3],
            lp_pda: [0; 32],
            trading_fee_bps: 0,
            base_spread_bps: 0,
            max_total_bps: 0,
            impact_k_bps: 0,
            liquidity_notional_e6: 0,
            max_fill_abs: 0,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: 0,
            asset_slots_used: 0,
            _pad1: [0; 3],
            asset_ids: [0; MATCHER_MAX_ASSETS],
            asset_inventory: [0; MATCHER_MAX_ASSETS],
        }
    }
}

impl MatcherCtx {
    /// Check if context is initialized with valid magic
    pub fn is_initialized(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
        magic == MATCHER_MAGIC
    }

    /// True only for a context region that has never been written. Any nonzero byte, including
    /// a legacy or unknown magic, means the region holds state that tag 2 must not overwrite.
    pub fn is_pristine(data: &[u8]) -> bool {
        data.len() >= CTX_VAMM_LEN && data[..CTX_VAMM_LEN].iter().all(|&b| b == 0)
    }

    /// Read context from data slice (at offset 64 in full context account)
    pub fn read_from(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < CTX_VAMM_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
        if magic != MATCHER_MAGIC {
            return Err(ProgramError::UninitializedAccount);
        }

        let version = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let kind = data[12];

        let mut lp_pda = [0u8; 32];
        lp_pda.copy_from_slice(&data[16..48]);

        let trading_fee_bps = u32::from_le_bytes(data[48..52].try_into().unwrap());
        let base_spread_bps = u32::from_le_bytes(data[52..56].try_into().unwrap());
        let max_total_bps = u32::from_le_bytes(data[56..60].try_into().unwrap());
        let impact_k_bps = u32::from_le_bytes(data[60..64].try_into().unwrap());
        let liquidity_notional_e6 = u128::from_le_bytes(data[64..80].try_into().unwrap());
        let max_fill_abs = u128::from_le_bytes(data[80..96].try_into().unwrap());
        let inventory_base = i128::from_le_bytes(data[96..112].try_into().unwrap());
        let last_oracle_price_e6 = u64::from_le_bytes(data[112..120].try_into().unwrap());
        let last_exec_price_e6 = u64::from_le_bytes(data[120..128].try_into().unwrap());
        let max_inventory_abs = u128::from_le_bytes(data[128..144].try_into().unwrap());

        let mut ctx = Self {
            magic,
            version,
            kind,
            _pad0: [0; 3],
            lp_pda,
            trading_fee_bps,
            base_spread_bps,
            max_total_bps,
            impact_k_bps,
            liquidity_notional_e6,
            max_fill_abs,
            inventory_base,
            last_oracle_price_e6,
            last_exec_price_e6,
            max_inventory_abs,
            ..Self::default()
        };

        match version {
            MATCHER_VERSION => {
                ctx.asset_slots_used = data[144];
                for i in 0..MATCHER_MAX_ASSETS {
                    let id = 148 + i * 2;
                    ctx.asset_ids[i] = u16::from_le_bytes(data[id..id + 2].try_into().unwrap());
                    let inv = 160 + i * 16;
                    ctx.asset_inventory[i] =
                        i128::from_le_bytes(data[inv..inv + 16].try_into().unwrap());
                }
            }
            MATCHER_VERSION_V3 => {
                // v3 kept one scalar and v3 markets traded asset 0 through a context. The
                // v3 reserved region was always zero, so nothing else needs carrying over.
                ctx.version = MATCHER_VERSION;
                if inventory_base != 0 {
                    ctx.asset_slots_used = 1;
                    ctx.asset_ids[0] = 0;
                    ctx.asset_inventory[0] = inventory_base;
                }
            }
            _ => return Err(ProgramError::InvalidAccountData),
        }

        Ok(ctx)
    }

    /// Write context to data slice (at offset 64 in full context account)
    pub fn write_to(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < CTX_VAMM_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }

        data[0..8].copy_from_slice(&self.magic.to_le_bytes());
        data[8..12].copy_from_slice(&self.version.to_le_bytes());
        data[12] = self.kind;
        data[13..16].copy_from_slice(&self._pad0);
        data[16..48].copy_from_slice(&self.lp_pda);
        data[48..52].copy_from_slice(&self.trading_fee_bps.to_le_bytes());
        data[52..56].copy_from_slice(&self.base_spread_bps.to_le_bytes());
        data[56..60].copy_from_slice(&self.max_total_bps.to_le_bytes());
        data[60..64].copy_from_slice(&self.impact_k_bps.to_le_bytes());
        data[64..80].copy_from_slice(&self.liquidity_notional_e6.to_le_bytes());
        data[80..96].copy_from_slice(&self.max_fill_abs.to_le_bytes());
        data[96..112].copy_from_slice(&self.inventory_base.to_le_bytes());
        data[112..120].copy_from_slice(&self.last_oracle_price_e6.to_le_bytes());
        data[120..128].copy_from_slice(&self.last_exec_price_e6.to_le_bytes());
        data[128..144].copy_from_slice(&self.max_inventory_abs.to_le_bytes());
        data[144] = self.asset_slots_used;
        data[145..148].copy_from_slice(&self._pad1);
        for i in 0..MATCHER_MAX_ASSETS {
            let id = 148 + i * 2;
            data[id..id + 2].copy_from_slice(&self.asset_ids[i].to_le_bytes());
            let inv = 160 + i * 16;
            data[inv..inv + 16].copy_from_slice(&self.asset_inventory[i].to_le_bytes());
        }

        Ok(())
    }

    /// Get the matcher kind
    pub fn get_kind(&self) -> Result<MatcherKind, ProgramError> {
        MatcherKind::try_from(self.kind)
    }

    /// Get LP PDA as Pubkey
    pub fn get_lp_pda(&self) -> Pubkey {
        Pubkey::new_from_array(self.lp_pda)
    }

    /// Inventory currently held in `asset_index` (zero if the asset has no slot).
    pub fn asset_inventory(&self, asset_index: u16) -> i128 {
        match self.find_asset_slot(asset_index) {
            Some(i) => self.asset_inventory[i],
            None => 0,
        }
    }

    fn find_asset_slot(&self, asset_index: u16) -> Option<usize> {
        (0..MATCHER_MAX_ASSETS)
            .find(|&i| self.asset_slots_used & (1 << i) != 0 && self.asset_ids[i] == asset_index)
    }

    /// True when a fill in `asset_index` can be recorded: the asset already has a slot or a
    /// free slot exists.
    fn can_hold_asset(&self, asset_index: u16) -> bool {
        self.find_asset_slot(asset_index).is_some()
            || self.asset_slots_used.count_ones() < MATCHER_MAX_ASSETS as u32
    }

    /// Apply the LP side of a fill (`exec_size` is the taker's signed size) with checked
    /// arithmetic. A slot whose inventory returns to zero is released.
    fn apply_fill(&mut self, asset_index: u16, exec_size: i128) -> Result<(), ProgramError> {
        let slot = match self.find_asset_slot(asset_index) {
            Some(i) => i,
            None => {
                let i = (0..MATCHER_MAX_ASSETS)
                    .find(|&i| self.asset_slots_used & (1 << i) == 0)
                    .ok_or(ProgramError::InvalidArgument)?;
                self.asset_slots_used |= 1 << i;
                self.asset_ids[i] = asset_index;
                self.asset_inventory[i] = 0;
                i
            }
        };
        let new_inv = self.asset_inventory[slot]
            .checked_sub(exec_size)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if self.max_inventory_abs != 0 && new_inv.unsigned_abs() > self.max_inventory_abs {
            return Err(ProgramError::InvalidArgument);
        }
        self.asset_inventory[slot] = new_inv;
        if new_inv == 0 {
            self.asset_slots_used &= !(1 << slot);
            self.asset_ids[slot] = 0;
        }
        self.inventory_base = self
            .inventory_base
            .checked_sub(exec_size)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Validate context parameters
    pub fn validate(&self) -> Result<(), ProgramError> {
        let kind = self.get_kind()?;

        // For vAMM, liquidity_notional_e6 MUST be non-zero
        if kind == MatcherKind::Vamm && self.liquidity_notional_e6 == 0 {
            return Err(ProgramError::InvalidAccountData);
        }

        // Bounded so the impact integral cannot overflow without also exceeding the cap.
        if self.liquidity_notional_e6 > u64::MAX as u128 {
            return Err(ProgramError::InvalidAccountData);
        }

        // max_total_bps MUST be <= 9000
        if self.max_total_bps > 9000 {
            return Err(ProgramError::InvalidAccountData);
        }

        // trading_fee_bps should be reasonable (< 1000 = 10%)
        if self.trading_fee_bps > 1000 {
            return Err(ProgramError::InvalidAccountData);
        }

        // base_spread_bps + trading_fee_bps should not exceed max_total_bps
        let total_fixed = self.base_spread_bps.saturating_add(self.trading_fee_bps);
        if total_fixed > self.max_total_bps {
            return Err(ProgramError::InvalidAccountData);
        }

        // Every permitted inventory must be representable as i128.
        if self.max_inventory_abs > i128::MAX as u128 {
            return Err(ProgramError::InvalidAccountData);
        }

        // LP PDA must be non-zero
        if self.lp_pda == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(())
    }
}

// =============================================================================
// Init Instruction Layout (Tag 2)
// =============================================================================
// Offset  Field                   Type    Size
// 0       tag                     u8      1     Always 2
// 1       kind                    u8      1     0=Passive, 1=vAMM
// 2-6     trading_fee_bps         u32     4
// 6-10    base_spread_bps         u32     4
// 10-14   max_total_bps           u32     4
// 14-18   impact_k_bps            u32     4     (vAMM only)
// 18-34   liquidity_notional_e6   u128    16    (vAMM only, 0 for Passive)
// 34-50   max_fill_abs            u128    16
// 50-66   max_inventory_abs       u128    16    (0 = no limit)
// Total: 66 bytes

pub const INIT_CTX_LEN: usize = 66;

/// Parsed Init instruction parameters
#[derive(Clone, Copy, Debug)]
pub struct InitParams {
    pub kind: u8,
    pub trading_fee_bps: u32,
    pub base_spread_bps: u32,
    pub max_total_bps: u32,
    pub impact_k_bps: u32,
    pub liquidity_notional_e6: u128,
    pub max_fill_abs: u128,
    pub max_inventory_abs: u128,
}

impl InitParams {
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < INIT_CTX_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        if data[0] != crate::MATCHER_INIT_VAMM_TAG {
            return Err(ProgramError::InvalidInstructionData);
        }

        Ok(Self {
            kind: data[1],
            trading_fee_bps: u32::from_le_bytes(data[2..6].try_into().unwrap()),
            base_spread_bps: u32::from_le_bytes(data[6..10].try_into().unwrap()),
            max_total_bps: u32::from_le_bytes(data[10..14].try_into().unwrap()),
            impact_k_bps: u32::from_le_bytes(data[14..18].try_into().unwrap()),
            liquidity_notional_e6: u128::from_le_bytes(data[18..34].try_into().unwrap()),
            max_fill_abs: u128::from_le_bytes(data[34..50].try_into().unwrap()),
            max_inventory_abs: u128::from_le_bytes(data[50..66].try_into().unwrap()),
        })
    }

    /// Encode Init instruction data
    pub fn encode(&self) -> [u8; INIT_CTX_LEN] {
        let mut data = [0u8; INIT_CTX_LEN];
        data[0] = crate::MATCHER_INIT_VAMM_TAG;
        data[1] = self.kind;
        data[2..6].copy_from_slice(&self.trading_fee_bps.to_le_bytes());
        data[6..10].copy_from_slice(&self.base_spread_bps.to_le_bytes());
        data[10..14].copy_from_slice(&self.max_total_bps.to_le_bytes());
        data[14..18].copy_from_slice(&self.impact_k_bps.to_le_bytes());
        data[18..34].copy_from_slice(&self.liquidity_notional_e6.to_le_bytes());
        data[34..50].copy_from_slice(&self.max_fill_abs.to_le_bytes());
        data[50..66].copy_from_slice(&self.max_inventory_abs.to_le_bytes());
        data
    }
}

// =============================================================================
// Instruction Processing
// =============================================================================

/// Process Init instruction (Tag 2)
///
/// Initializes the matcher context with the specified parameters.
/// Can only be called once (context region must never have been written).
///
/// Accounts:
/// 0. `[]` LP PDA (stored for signature verification)
/// 1. `[signer, writable]` Matcher context account (owned by this program)
pub fn process_init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    use solana_program::account_info::next_account_info;

    let account_iter = &mut accounts.iter();
    let lp_pda = next_account_info(account_iter)?;
    let ctx_account = next_account_info(account_iter)?;

    // The context key authorizes binding this account to the supplied LP PDA. The LP PDA itself
    // is the wrapper's matcher delegate and can only sign through the wrapper's invoke_signed.
    if !ctx_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify ownership
    if ctx_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Verify size
    if ctx_account.data_len() < MATCHER_CONTEXT_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }

    // Verify writable
    if !ctx_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // Parse parameters
    let params = InitParams::parse(instruction_data)?;

    // Validate kind
    let _ = MatcherKind::try_from(params.kind)?;

    // Refuse anything but a never-written region: a legacy or unknown header is existing state.
    {
        let data = ctx_account.try_borrow_data()?;
        if !MatcherCtx::is_pristine(&data[CTX_VAMM_OFFSET..]) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    }

    // Create and validate context
    let ctx = MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind: params.kind,
        lp_pda: lp_pda.key.to_bytes(),
        trading_fee_bps: params.trading_fee_bps,
        base_spread_bps: params.base_spread_bps,
        max_total_bps: params.max_total_bps,
        impact_k_bps: params.impact_k_bps,
        liquidity_notional_e6: params.liquidity_notional_e6,
        max_fill_abs: params.max_fill_abs,
        max_inventory_abs: params.max_inventory_abs,
        ..MatcherCtx::default()
    };

    ctx.validate()?;

    // Write context
    let mut data = ctx_account.try_borrow_mut_data()?;
    ctx.write_to(&mut data[CTX_VAMM_OFFSET..])?;

    Ok(())
}

/// Process matcher call
///
/// Computes execution price using the configured kind (Passive or vAMM),
/// validates LP PDA signature, updates inventory, and writes result.
///
/// Accounts:
/// 0. `[signer]` LP PDA (must match stored PDA)
/// 1. `[writable]` Matcher context account
pub fn process_call(
    lp_pda: &AccountInfo,
    ctx_account: &AccountInfo,
    instruction_data: &[u8],
) -> ProgramResult {
    // Parse call
    let call = MatcherCall::parse(instruction_data)?;

    // Validate inputs
    if call.oracle_price_e6 == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if call.req_size == i128::MIN {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Read context
    let mut ctx = {
        let data = ctx_account.try_borrow_data()?;
        MatcherCtx::read_from(&data[CTX_VAMM_OFFSET..])?
    };
    ctx.validate()?;

    // Validate LP PDA matches stored PDA
    if lp_pda.key.to_bytes() != ctx.lp_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // Compute execution based on kind
    let (exec_price, exec_size, flags) = compute_execution(&ctx, &call)?;

    // Update context state if fill occurred
    if exec_size != 0 {
        ctx.apply_fill(call.asset_index, exec_size)?;
        ctx.last_oracle_price_e6 = call.oracle_price_e6;
        ctx.last_exec_price_e6 = exec_price;
    }

    // Write updated context
    {
        let mut data = ctx_account.try_borrow_mut_data()?;
        ctx.write_to(&mut data[CTX_VAMM_OFFSET..])?;
    }

    // Write return
    let ret = MatcherReturn {
        abi_version: crate::MATCHER_ABI_VERSION,
        flags,
        exec_price_e6: exec_price,
        exec_size,
        req_id: call.req_id,
        lp_account_id: call.lp_account_id,
        oracle_price_e6: call.oracle_price_e6,
        asset_index: call.asset_index as u64,
    };

    let mut data = ctx_account.try_borrow_mut_data()?;
    ret.write_to(&mut data)?;

    Ok(())
}

/// Process a batched matcher call (tag 3): fill N legs against this LP in one CPI. The LP PDA is
/// validated once; each leg runs the same `compute_execution` as the single-fill path against
/// that leg's asset inventory, state carries across legs in order, and the N 64-byte returns
/// are emitted via `set_return_data` (the context account's 64-byte return slot can't hold
/// more than one).
pub fn process_batch_call(
    lp_pda: &AccountInfo,
    ctx_account: &AccountInfo,
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() < MATCHER_BATCH_HEADER_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let n = instruction_data[1] as usize;
    if n == 0
        || n > MATCHER_BATCH_MAX_LEGS
        || instruction_data.len() != MATCHER_BATCH_HEADER_LEN + n * MATCHER_BATCH_LEG_LEN
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    let req_id = u64::from_le_bytes(instruction_data[2..10].try_into().unwrap());
    let lp_account_id = u64::from_le_bytes(instruction_data[10..18].try_into().unwrap());

    let mut ctx = {
        let data = ctx_account.try_borrow_data()?;
        MatcherCtx::read_from(&data[CTX_VAMM_OFFSET..])?
    };
    ctx.validate()?;
    if lp_pda.key.to_bytes() != ctx.lp_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut returns = [0u8; MATCHER_BATCH_MAX_LEGS * MATCHER_RETURN_LEN];
    for i in 0..n {
        let base = MATCHER_BATCH_HEADER_LEN + i * MATCHER_BATCH_LEG_LEN;
        let asset_index = u16::from_le_bytes(instruction_data[base..base + 2].try_into().unwrap());
        let oracle_price_e6 =
            u64::from_le_bytes(instruction_data[base + 2..base + 10].try_into().unwrap());
        let req_size = i128::from_le_bytes(instruction_data[base + 10..base + 26].try_into().unwrap());
        if oracle_price_e6 == 0 || req_size == i128::MIN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let call = MatcherCall {
            req_id,
            asset_index,
            lp_account_id,
            oracle_price_e6,
            req_size,
        };
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call)?;
        if exec_size != 0 {
            ctx.apply_fill(asset_index, exec_size)?;
            ctx.last_oracle_price_e6 = oracle_price_e6;
            ctx.last_exec_price_e6 = exec_price;
        }
        let ret = MatcherReturn {
            abi_version: MATCHER_ABI_VERSION,
            flags,
            exec_price_e6: exec_price,
            exec_size,
            req_id,
            lp_account_id,
            oracle_price_e6,
            asset_index: asset_index as u64,
        };
        ret.write_to(&mut returns[i * MATCHER_RETURN_LEN..])?;
    }

    {
        let mut data = ctx_account.try_borrow_mut_data()?;
        ctx.write_to(&mut data[CTX_VAMM_OFFSET..])?;
    }
    solana_program::program::set_return_data(&returns[..n * MATCHER_RETURN_LEN]);
    Ok(())
}

/// Basis points expressed in micro-bps so impact averages keep sub-bp precision.
const MICRO_BPS_PER_BP: u128 = 1_000_000;
const PRICE_DENOM: u128 = 10_000 * MICRO_BPS_PER_BP;

/// Compute execution price and size based on matcher kind.
///
/// Both kinds share sizing (fill cap, then the per-asset inventory cap) and rounding: asks round
/// up and bids round down, so rounding never favors the taker. Only the vAMM adds impact.
fn compute_execution(
    ctx: &MatcherCtx,
    call: &MatcherCall,
) -> Result<(u64, i128, u32), ProgramError> {
    let kind = ctx.get_kind()?;

    let req_abs = call.req_size.unsigned_abs();
    let is_buy = call.req_size > 0;
    let inventory = ctx.asset_inventory(call.asset_index);

    // Determine fill size (cap by max_fill_abs); req_size != i128::MIN so this fits i128.
    let fill_abs = if ctx.max_fill_abs == 0 || !ctx.can_hold_asset(call.asset_index) {
        0u128
    } else {
        core::cmp::min(req_abs, ctx.max_fill_abs)
    };

    // Check inventory limit
    let fill_abs = check_inventory_limit(ctx, inventory, fill_abs, is_buy)?;

    // Zero fill case
    if fill_abs == 0 {
        return Ok((call.oracle_price_e6, 0, FLAG_VALID | FLAG_PARTIAL_OK));
    }

    let exec_size = if is_buy {
        fill_abs as i128
    } else {
        -(fill_abs as i128)
    };

    let oracle = call.oracle_price_e6 as u128;
    let fixed_u = (ctx.base_spread_bps as u128 + ctx.trading_fee_bps as u128) * MICRO_BPS_PER_BP;
    let max_total_u = ctx.max_total_bps as u128 * MICRO_BPS_PER_BP;
    let impact_u = match kind {
        MatcherKind::Passive => 0,
        MatcherKind::Vamm => {
            let max_impact_u = max_total_u.saturating_sub(fixed_u);
            vamm_impact_micro_bps(ctx, oracle, inventory, fill_abs, is_buy, max_impact_u)?
        }
    };
    let total_u = core::cmp::min(max_total_u, fixed_u + impact_u);

    let exec_price_u128 = if is_buy {
        let num = oracle
            .checked_mul(PRICE_DENOM + total_u)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        num.div_ceil(PRICE_DENOM)
    } else {
        oracle
            .checked_mul(PRICE_DENOM - total_u)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / PRICE_DENOM
    };

    if exec_price_u128 == 0 || exec_price_u128 > u64::MAX as u128 {
        return Err(ProgramError::ArithmeticOverflow);
    }

    Ok((exec_price_u128 as u64, exec_size, FLAG_VALID))
}

/// Average impact, in micro-bps, charged on a fill of `fill_abs` against the asset's persisted
/// inventory.
///
/// Impact is priced along the LP's exposure in the direction the taker pushes it. Marginal
/// impact at exposure `e` is `m(e) = min(max_impact, 2 * k * notional(e) / L)`, so a fill from a
/// flat book is charged `k * notional(fill) / L` exactly as before, but the charge now depends
/// on inventory already accumulated: splitting an order into pieces walks the same curve and
/// pays the same integral (up to rounding, which always rounds against the taker). The part of
/// a fill that reduces existing LP exposure is charged no impact.
fn vamm_impact_micro_bps(
    ctx: &MatcherCtx,
    oracle: u128,
    inventory: i128,
    fill_abs: u128,
    is_buy: bool,
    max_impact_u: u128,
) -> Result<u128, ProgramError> {
    if ctx.impact_k_bps == 0 || max_impact_u == 0 {
        return Ok(0);
    }
    // Taker buys push the LP short, taker sells push it long. Exposure is measured on that side.
    // check_inventory_limit already made the post-fill inventory representable.
    let fill = fill_abs as i128;
    let (e0, e1) = if is_buy {
        let after = inventory.checked_sub(fill).ok_or(ProgramError::ArithmeticOverflow)?;
        (short_exposure(inventory), short_exposure(after))
    } else {
        let after = inventory.checked_add(fill).ok_or(ProgramError::ArithmeticOverflow)?;
        (long_exposure(inventory), long_exposure(after))
    };
    if e1 <= e0 {
        return Ok(0);
    }

    // m_u(e) = a * e / d in micro-bps.
    let a = 2 * ctx.impact_k_bps as u128 * oracle * MICRO_BPS_PER_BP; // < 2^118
    let d = ctx.liquidity_notional_e6 * 1_000_000; // < 2^84 by validate()
    let cap_d = max_impact_u * d; // < 2^118

    // Integral of m over [lo, hi] when m stays below the cap: a * (lo + hi) * (hi - lo) / (2d).
    // Returned as the segment average (ceil) times its length, in micro-bps * units, divided by
    // the whole fill below so the result is the fill's average impact.
    let below_avg = |lo: u128, hi: u128| -> Result<u128, ProgramError> {
        let sum = lo.checked_add(hi).ok_or(ProgramError::ArithmeticOverflow)?;
        let num = a.checked_mul(sum).ok_or(ProgramError::ArithmeticOverflow)?;
        Ok(num.div_ceil(2 * d))
    };

    let knee_reached = match a.checked_mul(e1) {
        Some(m1) => m1 > cap_d,
        None => true, // a * e1 >= 2^128 > cap_d
    };
    let impact_u = if !knee_reached {
        let avg = core::cmp::min(below_avg(e0, e1)?, max_impact_u);
        mul_div_ceil(avg, e1 - e0, fill_abs)?
    } else {
        let knee = cap_d / a; // m(knee) <= cap
        if knee <= e0 {
            mul_div_ceil(max_impact_u, e1 - e0, fill_abs)?
        } else {
            let avg = core::cmp::min(below_avg(e0, knee)?, max_impact_u);
            let lower = mul_div_ceil(avg, knee - e0, fill_abs)?;
            let upper = mul_div_ceil(max_impact_u, e1 - knee, fill_abs)?;
            lower.checked_add(upper).ok_or(ProgramError::ArithmeticOverflow)?
        }
    };
    Ok(core::cmp::min(impact_u, max_impact_u))
}

fn short_exposure(inventory: i128) -> u128 {
    if inventory < 0 {
        inventory.unsigned_abs()
    } else {
        0
    }
}

fn long_exposure(inventory: i128) -> u128 {
    if inventory > 0 {
        inventory as u128
    } else {
        0
    }
}

/// ceil(a * b / d) for d > 0, exact over the 256-bit product.
fn mul_div_ceil(a: u128, b: u128, d: u128) -> Result<u128, ProgramError> {
    if d == 0 {
        return Err(ProgramError::ArithmeticOverflow);
    }
    if let Some(p) = a.checked_mul(b) {
        return Ok(p.div_ceil(d));
    }
    let (hi, lo) = widening_mul(a, b);
    if hi >= d {
        return Err(ProgramError::ArithmeticOverflow);
    }
    // Restoring long division of (hi, lo) by d, one bit at a time; hi < d throughout.
    let mut rem = hi;
    let mut q: u128 = 0;
    for i in (0..128).rev() {
        let carry = rem >> 127;
        rem = (rem << 1) | ((lo >> i) & 1);
        q <<= 1;
        if carry == 1 || rem >= d {
            rem = rem.wrapping_sub(d);
            q |= 1;
        }
    }
    if rem != 0 {
        q = q.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;
    }
    Ok(q)
}

fn widening_mul(a: u128, b: u128) -> (u128, u128) {
    const MASK: u128 = u64::MAX as u128;
    let (a0, a1) = (a & MASK, a >> 64);
    let (b0, b1) = (b & MASK, b >> 64);
    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;
    let mid = (p00 >> 64) + (p01 & MASK) + (p10 & MASK);
    let lo = (p00 & MASK) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}

/// Cap `fill_abs` so the asset's inventory stays within `max_inventory_abs`. All arithmetic is
/// checked: a transition that is not representable is capped, never saturated.
fn check_inventory_limit(
    ctx: &MatcherCtx,
    current_inv: i128,
    fill_abs: u128,
    is_buy: bool,
) -> Result<u128, ProgramError> {
    if ctx.max_inventory_abs == 0 {
        // Unlimited: only representability bounds the fill.
        let room = if is_buy {
            // new = current - fill >= i128::MIN
            current_inv.abs_diff(i128::MIN)
        } else {
            (i128::MAX).abs_diff(current_inv)
        };
        return Ok(core::cmp::min(fill_abs, room));
    }

    // validate() bounds max_inventory_abs to i128::MAX.
    let max_inv = ctx.max_inventory_abs as i128;
    let room = if is_buy {
        // new = current - fill >= -max_inv
        if current_inv <= -max_inv {
            0
        } else {
            current_inv.abs_diff(-max_inv)
        }
    } else if current_inv >= max_inv {
        0
    } else {
        max_inv.abs_diff(current_inv)
    };
    Ok(core::cmp::min(fill_abs, room))
}

// =============================================================================
// Legacy exports for backward compatibility
// =============================================================================

// Re-export old names for lib.rs compatibility
pub use process_call as process_vamm_call;
pub use process_init as process_init_vamm;
pub use MatcherCtx as VammCtx;
pub use MatcherKind as MatcherMode;
pub use MATCHER_MAGIC as VAMM_MAGIC;

// Legacy type aliases
pub type InitVammParams = InitParams;
pub const INIT_VAMM_LEN: usize = INIT_CTX_LEN;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_vamm_ctx() -> MatcherCtx {
        MatcherCtx {
            magic: MATCHER_MAGIC,
            version: MATCHER_VERSION,
            kind: MatcherKind::Vamm as u8,
            _pad0: [0; 3],
            lp_pda: [1; 32],
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: 1_000_000_000,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: 0,
            ..MatcherCtx::default()
        }
    }

    fn default_passive_ctx() -> MatcherCtx {
        MatcherCtx {
            magic: MATCHER_MAGIC,
            version: MATCHER_VERSION,
            kind: MatcherKind::Passive as u8,
            _pad0: [0; 3],
            lp_pda: [1; 32],
            trading_fee_bps: 5,
            base_spread_bps: 50,
            max_total_bps: 200,
            impact_k_bps: 0,
            liquidity_notional_e6: 0,
            max_fill_abs: 1_000_000_000,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: 0,
            ..MatcherCtx::default()
        }
    }

    fn make_call(oracle_price: u64, req_size: i128) -> MatcherCall {
        MatcherCall {
            req_id: 1,
            asset_index: 0,
            lp_account_id: 100,
            oracle_price_e6: oracle_price,
            req_size,
        }
    }

    #[test]
    fn test_vamm_buy_adds_spread_and_fee() {
        let ctx = default_vamm_ctx();
        let call = make_call(100_000_000, 1000);

        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();

        assert!(exec_price >= call.oracle_price_e6);
        assert_eq!(exec_size, 1000);
        assert_eq!(flags, FLAG_VALID);
        assert!(exec_price >= 100_015_000);
    }

    #[test]
    fn test_passive_buy_adds_spread_and_fee() {
        let ctx = default_passive_ctx();
        let call = make_call(100_000_000, 1000);

        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();

        assert!(exec_price >= call.oracle_price_e6);
        assert_eq!(exec_size, 1000);
        assert_eq!(flags, FLAG_VALID);
        assert_eq!(exec_price, 100_550_000);
    }

    #[test]
    fn test_vamm_sell_subtracts_spread() {
        let ctx = default_vamm_ctx();
        let call = make_call(100_000_000, -1000);

        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();

        assert!(exec_price <= call.oracle_price_e6);
        assert_eq!(exec_size, -1000);
        assert_eq!(flags, FLAG_VALID);
    }

    #[test]
    fn test_vamm_bigger_size_more_impact() {
        let ctx = default_vamm_ctx();

        let call_small = make_call(100_000_000, 1_000);
        let (price_small, _, _) = compute_execution(&ctx, &call_small).unwrap();

        let call_large = make_call(100_000_000, 100_000_000);
        let (price_large, _, _) = compute_execution(&ctx, &call_large).unwrap();

        assert!(price_large > price_small);
    }

    #[test]
    fn test_total_capped_at_max() {
        let ctx = default_vamm_ctx();

        let call = make_call(100_000_000, 1_000_000_000);
        let (exec_price, _, _) = compute_execution(&ctx, &call).unwrap();

        let max_price = 100_000_000u64 * 10_200 / 10_000;
        assert!(exec_price <= max_price);
    }

    #[test]
    fn test_zero_fill_when_max_fill_zero() {
        let mut ctx = default_vamm_ctx();
        ctx.max_fill_abs = 0;

        let call = make_call(100_000_000, 1000);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();

        assert_eq!(exec_size, 0);
        assert_eq!(flags, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(exec_price, call.oracle_price_e6);
    }

    #[test]
    fn test_partial_fill_capped() {
        let mut ctx = default_vamm_ctx();
        ctx.max_fill_abs = 500;

        let call = make_call(100_000_000, 1000);
        let (_, exec_size, _) = compute_execution(&ctx, &call).unwrap();

        assert_eq!(exec_size, 500);
    }

    #[test]
    fn test_inventory_limit_caps_fill() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = 100;

        let call = make_call(100_000_000, 1000);
        let (_, exec_size, _) = compute_execution(&ctx, &call).unwrap();

        assert_eq!(exec_size, 100);
    }

    #[test]
    fn test_inventory_limit_at_boundary() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = 100;
        ctx.apply_fill(0, 100).unwrap();

        let call = make_call(100_000_000, 1000);
        let (_, exec_size, flags) = compute_execution(&ctx, &call).unwrap();

        assert_eq!(exec_size, 0);
        assert_eq!(flags, FLAG_VALID | FLAG_PARTIAL_OK);
    }

    #[test]
    fn test_vamm_validation_rejects_zero_liquidity() {
        let mut ctx = default_vamm_ctx();
        ctx.liquidity_notional_e6 = 0;

        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_passive_allows_zero_liquidity() {
        let ctx = default_passive_ctx();
        assert!(ctx.validate().is_ok());
    }

    #[test]
    fn test_validation_rejects_high_max_bps() {
        let mut ctx = default_vamm_ctx();
        ctx.max_total_bps = 9500;

        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_fee_exceeds_max() {
        let mut ctx = default_vamm_ctx();
        ctx.trading_fee_bps = 100;
        ctx.base_spread_bps = 150;
        ctx.max_total_bps = 200;

        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_zero_lp_pda() {
        let mut ctx = default_vamm_ctx();
        ctx.lp_pda = [0; 32];

        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_ctx_serialization_roundtrip() {
        let ctx = default_vamm_ctx();
        let mut buf = [0u8; CTX_VAMM_LEN];

        ctx.write_to(&mut buf).unwrap();
        let ctx2 = MatcherCtx::read_from(&buf).unwrap();

        assert_eq!(ctx.magic, ctx2.magic);
        assert_eq!(ctx.version, ctx2.version);
        assert_eq!(ctx.kind, ctx2.kind);
        assert_eq!(ctx.lp_pda, ctx2.lp_pda);
        assert_eq!(ctx.trading_fee_bps, ctx2.trading_fee_bps);
        assert_eq!(ctx.base_spread_bps, ctx2.base_spread_bps);
        assert_eq!(ctx.max_total_bps, ctx2.max_total_bps);
        assert_eq!(ctx.impact_k_bps, ctx2.impact_k_bps);
        assert_eq!(ctx.liquidity_notional_e6, ctx2.liquidity_notional_e6);
        assert_eq!(ctx.max_fill_abs, ctx2.max_fill_abs);
        assert_eq!(ctx.max_inventory_abs, ctx2.max_inventory_abs);
    }

    #[test]
    fn test_init_params_encode_decode() {
        let params = InitParams {
            kind: MatcherKind::Vamm as u8,
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: 1_000_000_000,
            max_inventory_abs: 500_000,
        };

        let encoded = params.encode();
        let decoded = InitParams::parse(&encoded).unwrap();

        assert_eq!(params.kind, decoded.kind);
        assert_eq!(params.trading_fee_bps, decoded.trading_fee_bps);
        assert_eq!(params.base_spread_bps, decoded.base_spread_bps);
        assert_eq!(params.max_total_bps, decoded.max_total_bps);
        assert_eq!(params.impact_k_bps, decoded.impact_k_bps);
        assert_eq!(params.liquidity_notional_e6, decoded.liquidity_notional_e6);
        assert_eq!(params.max_fill_abs, decoded.max_fill_abs);
        assert_eq!(params.max_inventory_abs, decoded.max_inventory_abs);
    }

    fn run_init(lp_is_signer: bool, ctx_is_signer: bool, ctx_data: &mut [u8]) -> ProgramResult {
        let program_id = Pubkey::new_unique();
        let lp_pda_key = Pubkey::new_unique();
        let ctx_key = Pubkey::new_unique();
        let mut ctx_lamports = 1_000_000_000;
        let mut lp_lamports = 0;
        let mut lp_data = alloc::vec::Vec::new();
        let lp_pda_info = AccountInfo::new(
            &lp_pda_key,
            lp_is_signer,
            false,
            &mut lp_lamports,
            &mut lp_data,
            &program_id,
            false,
            0,
        );
        let ctx_info = AccountInfo::new(
            &ctx_key,
            ctx_is_signer,
            true,
            &mut ctx_lamports,
            ctx_data,
            &program_id,
            false,
            0,
        );
        let params = InitParams {
            kind: MatcherKind::Vamm as u8,
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: 1_000_000_000,
            max_inventory_abs: 500_000,
        };
        process_init(&program_id, &[lp_pda_info, ctx_info], &params.encode())
    }

    /// Issue #4: an unsigned third party cannot bind a fresh context.
    #[test]
    fn test_init_requires_context_signer() {
        let mut data = alloc::vec![0u8; MATCHER_CONTEXT_LEN];
        assert_eq!(
            run_init(false, false, &mut data),
            Err(ProgramError::MissingRequiredSignature)
        );
        assert!(data.iter().all(|&b| b == 0));
        // The LP PDA need not sign: it is a wrapper PDA.
        assert_eq!(run_init(false, true, &mut data), Ok(()));
        assert_eq!(
            run_init(false, true, &mut data),
            Err(ProgramError::AccountAlreadyInitialized)
        );
    }

    /// Issue #10: a context written under the legacy magic is not reinitializable.
    #[test]
    fn test_legacy_magic_context_is_not_reinitializable() {
        let mut data = alloc::vec![0u8; MATCHER_CONTEXT_LEN];
        let region = &mut data[CTX_VAMM_OFFSET..];
        region[0..8].copy_from_slice(&LEGACY_MATCHER_MAGIC.to_le_bytes());
        region[96..112].copy_from_slice(&(-100i128).to_le_bytes());
        let before = data.clone();
        assert_eq!(
            run_init(false, true, &mut data),
            Err(ProgramError::AccountAlreadyInitialized)
        );
        assert_eq!(data, before);
        // Legacy state is also not tradable as if it were current.
        assert!(MatcherCtx::read_from(&data[CTX_VAMM_OFFSET..]).is_err());
    }

    /// Version-3 contexts carry their scalar inventory into asset 0.
    #[test]
    fn test_v3_context_migrates_inventory_to_asset_zero() {
        let mut ctx = default_vamm_ctx();
        let mut buf = [0u8; CTX_VAMM_LEN];
        ctx.write_to(&mut buf).unwrap();
        buf[8..12].copy_from_slice(&MATCHER_VERSION_V3.to_le_bytes());
        buf[96..112].copy_from_slice(&(-250i128).to_le_bytes());
        buf[144..256].fill(0);
        ctx = MatcherCtx::read_from(&buf).unwrap();
        assert_eq!(ctx.version, MATCHER_VERSION);
        assert_eq!(ctx.asset_inventory(0), -250);
        assert_eq!(ctx.asset_inventory(1), 0);
    }

    /// Issue #9: the cap is enforced with checked arithmetic at the i128 boundary.
    #[test]
    fn test_inventory_cap_at_i128_boundary() {
        let mut ctx = default_passive_ctx();
        ctx.max_fill_abs = u128::MAX;
        ctx.max_inventory_abs = i128::MAX as u128;
        let (_, size, _) = compute_execution(&ctx, &make_call(1_000_000, -i128::MAX)).unwrap();
        assert_eq!(size, -i128::MAX);
        ctx.apply_fill(0, size).unwrap();
        assert_eq!(ctx.asset_inventory(0), i128::MAX);
        // One more unit in the same direction is not admitted.
        let (_, size, flags) = compute_execution(&ctx, &make_call(1_000_000, -1)).unwrap();
        assert_eq!(size, 0);
        assert_eq!(flags, FLAG_VALID | FLAG_PARTIAL_OK);
        assert!(ctx.apply_fill(0, -1).is_err());
        // Unlimited contexts still refuse an unrepresentable transition.
        ctx.max_inventory_abs = 0;
        let (_, size, _) = compute_execution(&ctx, &make_call(1_000_000, -1)).unwrap();
        assert_eq!(size, 0);
        // Symmetric negative side.
        let mut ctx = default_passive_ctx();
        ctx.max_fill_abs = u128::MAX;
        ctx.max_inventory_abs = i128::MAX as u128;
        ctx.apply_fill(0, i128::MAX).unwrap();
        let (_, size, _) = compute_execution(&ctx, &make_call(1_000_000, 1)).unwrap();
        assert_eq!(size, 0);
        // A cap above the representable range is rejected at validation.
        ctx.max_inventory_abs = i128::MAX as u128 + 1;
        assert!(ctx.validate().is_err());
    }

    /// Issue #8: opposite fills in different assets do not net against one another.
    #[test]
    fn test_inventory_is_tracked_per_asset() {
        let mut ctx = default_passive_ctx();
        ctx.max_fill_abs = 100;
        ctx.max_inventory_abs = 100;
        let mut buy_a = make_call(1_000_000, 100);
        buy_a.asset_index = 1;
        let (_, size, _) = compute_execution(&ctx, &buy_a).unwrap();
        ctx.apply_fill(1, size).unwrap();
        let mut sell_b = make_call(1_000_000, -100);
        sell_b.asset_index = 2;
        let (_, size, _) = compute_execution(&ctx, &sell_b).unwrap();
        ctx.apply_fill(2, size).unwrap();
        assert_eq!(ctx.asset_inventory(1), -100);
        assert_eq!(ctx.asset_inventory(2), 100);
        // Asset 1 is at its cap regardless of asset 2.
        let (_, size, _) = compute_execution(&ctx, &buy_a).unwrap();
        assert_eq!(size, 0);
        // Returning an asset to flat frees its slot.
        let mut sell_a = buy_a;
        sell_a.req_size = -100;
        let (_, size, _) = compute_execution(&ctx, &sell_a).unwrap();
        ctx.apply_fill(1, size).unwrap();
        assert_eq!(ctx.asset_slots_used.count_ones(), 1);
    }

    /// Once every slot holds inventory a new asset gets a zero fill rather than netting.
    #[test]
    fn test_full_asset_table_zero_fills_new_asset() {
        let mut ctx = default_passive_ctx();
        for asset in 0..MATCHER_MAX_ASSETS as u16 {
            ctx.apply_fill(asset, 10).unwrap();
        }
        let mut call = make_call(1_000_000, 10);
        call.asset_index = 99;
        let (_, size, flags) = compute_execution(&ctx, &call).unwrap();
        assert_eq!(size, 0);
        assert_eq!(flags, FLAG_VALID | FLAG_PARTIAL_OK);
        // Existing assets still trade.
        call.asset_index = 3;
        let (_, size, _) = compute_execution(&ctx, &call).unwrap();
        assert_eq!(size, 10);
    }

    fn fill_cost(ctx: &mut MatcherCtx, pieces: &[i128]) -> u128 {
        let mut cost = 0u128;
        for &p in pieces {
            let (price, size, _) = compute_execution(ctx, &make_call(1_000_000, p)).unwrap();
            assert_eq!(size, p);
            cost += price as u128 * size.unsigned_abs();
            ctx.apply_fill(0, size).unwrap();
        }
        cost
    }

    /// Issue #11: splitting an order walks the same impact curve and cannot be cheaper.
    #[test]
    fn test_split_order_pays_at_least_aggregate_impact() {
        let base = MatcherCtx {
            kind: MatcherKind::Vamm as u8,
            trading_fee_bps: 0,
            base_spread_bps: 0,
            max_total_bps: 9000,
            impact_k_bps: 100,
            liquidity_notional_e6: 10_000,
            max_fill_abs: 10_000,
            max_inventory_abs: 10_000,
            ..default_vamm_ctx()
        };
        // The issue's reproduction: one 10,000 buy vs ten 1,000 buys.
        let aggregate = fill_cost(&mut base.clone(), &[10_000]);
        let split = fill_cost(&mut base.clone(), &[1_000; 10]);
        assert_eq!(aggregate, 10_000 * 1_010_000);
        assert!(split >= aggregate, "split {} < aggregate {}", split, aggregate);
        // Rounding tolerance: each piece rounds up by at most one price unit per base unit.
        assert!(split - aggregate <= 10 * 1_000);

        // Integer-truncation case from the issue: many small pieces at e6 prices.
        let big = MatcherCtx {
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: u128::MAX,
            max_inventory_abs: 0,
            ..base
        };
        let aggregate = fill_cost(&mut big.clone(), &[16 * 99_999_999]);
        let split = fill_cost(&mut big.clone(), &[99_999_999; 16]);
        assert!(split >= aggregate);
    }

    /// Reducing existing LP exposure pays no impact; a round trip never pays the taker.
    #[test]
    fn test_reducing_fill_pays_no_impact_and_round_trip_costs_taker() {
        let mut ctx = default_vamm_ctx();
        ctx.trading_fee_bps = 0;
        ctx.base_spread_bps = 0;
        ctx.liquidity_notional_e6 = 10_000;
        let (buy_price, size, _) = compute_execution(&ctx, &make_call(1_000_000, 5_000)).unwrap();
        ctx.apply_fill(0, size).unwrap();
        assert!(buy_price > 1_000_000);
        let (sell_price, size, _) = compute_execution(&ctx, &make_call(1_000_000, -5_000)).unwrap();
        ctx.apply_fill(0, size).unwrap();
        assert_eq!(sell_price, 1_000_000);
        assert_eq!(ctx.asset_inventory(0), 0);
        assert!(buy_price >= sell_price);
    }

    /// When the cap binds inside a fill, the clamped portion is priced at the cap.
    #[test]
    fn test_impact_integral_respects_cap() {
        let mut ctx = default_vamm_ctx();
        ctx.trading_fee_bps = 0;
        ctx.base_spread_bps = 0;
        ctx.max_total_bps = 100;
        ctx.liquidity_notional_e6 = 10_000;
        ctx.max_fill_abs = u128::MAX;
        // Marginal hits 100 bps at e = 5,000 (2 * 100 * e / 10,000); a 10,000 fill averages
        // 50 bps on the first half and 100 bps on the second: 75 bps.
        let (price, _, _) = compute_execution(&ctx, &make_call(1_000_000, 10_000)).unwrap();
        assert_eq!(price, 1_007_500);
        let split = fill_cost(&mut ctx.clone(), &[2_500; 4]);
        assert!(split >= 10_000 * 1_007_500);
    }

    #[test]
    fn test_mul_div_ceil_wide() {
        assert_eq!(mul_div_ceil(7, 3, 2).unwrap(), 11);
        let a = 1u128 << 100;
        let b = 1u128 << 100;
        assert_eq!(mul_div_ceil(a, b, 1u128 << 80).unwrap(), 1u128 << 120);
        assert_eq!(mul_div_ceil(a, b + 1, 1u128 << 80).unwrap(), (1u128 << 120) + (1 << 20));
        // Inexact wide division: q is the least value with q * d >= a * b.
        for d in [(1u128 << 73) + 3, (1u128 << 80) + 1, u128::MAX / 7] {
            let q = mul_div_ceil(a, b, d).unwrap();
            let prod = widening_mul(a, b);
            assert!(widening_mul(q, d) >= prod);
            assert!(widening_mul(q - 1, d) < prod);
        }
        assert!(mul_div_ceil(u128::MAX, u128::MAX, 1).is_err());
    }
}
