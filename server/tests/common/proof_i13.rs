#[allow(dead_code)]
pub fn proof_i13_signer() -> catbird_server::federation::receipt::I13ReceiptSigner {
    let sequencer_did = catbird_server::identity::service_did_base_opt()
        .unwrap_or_else(|| "did:web:chat.catbird.blue".to_owned());
    proof_i13_signer_for(&sequencer_did)
}

#[allow(dead_code)]
pub fn proof_i13_signer_for(
    sequencer_did: &str,
) -> catbird_server::federation::receipt::I13ReceiptSigner {
    catbird_server::federation::receipt::I13ReceiptSigner::new(
        p256::ecdsa::SigningKey::from_slice(&[0x13; 32])
            .expect("proof receipt key is a valid P-256 scalar"),
        sequencer_did.to_owned(),
    )
}
