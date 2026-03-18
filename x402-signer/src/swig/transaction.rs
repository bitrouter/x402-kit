use std::str::FromStr;

use base64::{Engine, prelude::BASE64_STANDARD};
use bitrouter_swig_sdk::auth::ClientRole;
use bitrouter_swig_sdk::auth::ed25519::Ed25519ClientRole;
use serde::Deserialize;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use x402_core::transport::{PaymentPayload, PaymentRequirements, PaymentResource};
use x402_core::types::{Extension, Record, X402V2};
use x402_networks::svm::SvmAddress;
use x402_networks::svm::exact::ExplicitSvmPayload;

use crate::svm::constants::*;
use crate::svm::rpc::SvmRpc;
use crate::svm::transaction::{
    build_memo_instruction, build_set_compute_unit_limit, build_set_compute_unit_price,
    build_transfer_checked, derive_ata,
};
use crate::svm::wallet::SvmWalletSigner;

/// SWIG-specific signing errors.
#[derive(Debug, thiserror::Error)]
pub enum SwigSigningError {
    #[error("wallet error: {0}")]
    Wallet(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("cannot parse address '{0}': {1}")]
    AddressParse(String, String),

    #[error("feePayer missing from requirements extra")]
    MissingFeePayer,

    #[error("payload serialization: {0}")]
    Serialization(String),

    #[error("swig SDK error: {0}")]
    Swig(String),
}

#[derive(Deserialize)]
pub(super) struct SvmExtra {
    #[serde(rename = "feePayer")]
    pub fee_payer: Option<String>,
}

pub(super) fn parse_pubkey(s: &str) -> Result<Pubkey, SwigSigningError> {
    Pubkey::from_str(s).map_err(|e| SwigSigningError::AddressParse(s.to_string(), e.to_string()))
}

/// Build a SWIG-wrapped x402 payment transaction.
///
/// Shared by both [`SwigEmbeddedSigner`](super::SwigEmbeddedSigner) and
/// [`SwigDelegationSigner`](super::SwigDelegationSigner).
///
/// Transaction layout:
/// 0. SetComputeUnitLimit
/// 1. SetComputeUnitPrice
/// 2. SWIG sign_v2(TransferChecked)
/// 3. Memo (random nonce)
///
/// The facilitator (`feePayer`) pays gas. Its signature slot is left empty.
pub(super) async fn sign_swig_payment<W, R>(
    swig_account: Pubkey,
    swig_wallet_address: Pubkey,
    authority_pubkey: Pubkey,
    role_id: u32,
    wallet: &W,
    rpc: &R,
    requirements: &PaymentRequirements,
    resource: &PaymentResource,
    extensions: &Record<Extension>,
) -> Result<PaymentPayload, SwigSigningError>
where
    W: SvmWalletSigner + Sync,
    R: SvmRpc + Sync,
{
    // 1. Parse requirements.
    let extra: SvmExtra = requirements
        .extra
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or(SvmExtra { fee_payer: None });

    let fee_payer = parse_pubkey(&extra.fee_payer.ok_or(SwigSigningError::MissingFeePayer)?)?;
    let mint = parse_pubkey(&requirements.asset)?;
    let destination_owner = parse_pubkey(&requirements.pay_to)?;
    let amount = requirements.amount.0 as u64;

    // 2. Fetch mint info and blockhash from RPC.
    let mint_info = rpc
        .fetch_mint_info(SvmAddress(mint))
        .await
        .map_err(|e| SwigSigningError::Rpc(e.to_string()))?;

    let recent_blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| SwigSigningError::Rpc(e.to_string()))?;

    // 3. Build inner TransferChecked instruction.
    //    Source is the ATA of swig_wallet_address (the embedded wallet PDA).
    let source_ata = derive_ata(&swig_wallet_address, &mint, &mint_info.program_address.0);
    let destination_ata = derive_ata(&destination_owner, &mint, &mint_info.program_address.0);

    let transfer_ix = build_transfer_checked(
        &source_ata,
        &mint,
        &destination_ata,
        &swig_wallet_address,
        amount,
        mint_info.decimals,
        &mint_info.program_address.0,
    );

    // 4. Wrap transfer in SWIG sign_v2 delegation.
    let client_role = Ed25519ClientRole::new(authority_pubkey);
    let swig_instructions = client_role
        .sign_v2(
            swig_account,
            swig_wallet_address,
            role_id,
            vec![transfer_ix],
            None, // Ed25519 doesn't use current_slot
            &[fee_payer],
        )
        .map_err(|e| SwigSigningError::Swig(e.to_string()))?;

    // 5. Assemble full instruction list: compute budget + swig + memo.
    let mut instructions: Vec<Instruction> = Vec::with_capacity(swig_instructions.len() + 3);
    instructions.push(build_set_compute_unit_limit(DEFAULT_COMPUTE_UNIT_LIMIT));
    instructions.push(build_set_compute_unit_price(DEFAULT_COMPUTE_UNIT_PRICE));
    instructions.extend(swig_instructions);
    instructions.push(build_memo_instruction());

    // 6. Build and partially sign the transaction.
    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer), &recent_blockhash);
    let mut tx = Transaction::new_unsigned(message);

    let message_bytes = tx.message_data();
    let signature = wallet
        .sign_message(&message_bytes)
        .await
        .map_err(|e| SwigSigningError::Wallet(e.to_string()))?;

    // Place signature at the authority's index; fee_payer slot stays empty.
    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == &authority_pubkey)
        .ok_or_else(|| {
            SwigSigningError::Serialization("authority not found in account keys".into())
        })?;
    tx.signatures[signer_index] = signature.0;

    // 7. Serialize to base64.
    let tx_bytes = bincode::serde::encode_to_vec(&tx, bincode::config::legacy())
        .map_err(|e| SwigSigningError::Serialization(e.to_string()))?;

    let payload_json = serde_json::to_value(ExplicitSvmPayload {
        transaction: BASE64_STANDARD.encode(&tx_bytes),
    })
    .map_err(|e| SwigSigningError::Serialization(e.to_string()))?;

    Ok(PaymentPayload {
        x402_version: X402V2,
        resource: resource.clone(),
        accepted: requirements.clone(),
        payload: payload_json,
        extensions: extensions.clone(),
    })
}
