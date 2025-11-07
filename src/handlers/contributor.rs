use anyhow::Result;
use bytes::Bytes;
use commonware_codec::{EncodeSize, ReadExt, Write};
use commonware_cryptography::Signer;
use commonware_p2p::{Receiver, Sender};
use commonware_utils::hex;
use dotenv::dotenv;
use jito_bls_ncn_core::bls::solana_bls_interface::{SolanaBN254G2, SolanaBN254Keypair, SolanaBN254Signature};
use std::collections::{HashMap, HashSet};
use tracing::info;

use commonware_avs_router::{validator::Validator, wire::{self, aggregation::Payload}};

pub struct Contributor {
    orchestrator: SolanaBN254G2,
    signer: SolanaBN254Keypair,
    me: usize,
}

impl Contributor {
    pub fn new(orchestrator: SolanaBN254G2, signer: SolanaBN254Keypair, mut contributors: Vec<SolanaBN254G2>) -> Self {
        dotenv().ok();
        contributors.sort();
        let mut ordered_contributors = HashMap::new();
        for (idx, contributor) in contributors.iter().enumerate() {
            ordered_contributors.insert(contributor.clone(), idx);
        }
        let me = *ordered_contributors.get(&signer.public_key()).unwrap();
        Self {
            orchestrator,
            signer,
            me,
        }
    }

    pub async fn run(
        self,
        mut sender: impl Sender,
        mut receiver: impl Receiver<PublicKey = SolanaBN254G2>,
    ) -> Result<()> {
        let mut signed = HashSet::new();
        let mut signatures: HashMap<u64, HashMap<usize, SolanaBN254Signature>> = HashMap::new();
        let validator = Validator::new().await?;

        while let Ok((s, message)) = receiver.recv().await {
            // Parse message
            let Ok(message) = wire::Aggregation::read(&mut std::io::Cursor::new(message)) else {
                continue;
            };
            let round = message.round;

            // Handle message from orchestrator
            match message.payload {
                Some(Payload::Start) => (),
                _ => continue,
            };
            if s != self.orchestrator {
                info!("not from orchestrator: {:?}", s);
                continue;
            }

            // Check if already signed at round
            if !signed.insert(round) {
                info!("already signed at round: {:?}", round);
                continue;
            }
            let mut buf = Vec::with_capacity(message.encode_size());
            message.write(&mut buf);
            let payload = validator.validate_and_return_expected_hash(&buf).await?;
            info!(
                "Generating signature for round: {}, payload hash: {}",
                round,
                hex(&payload)
            );

            // Sign the raw message directly
            let signature = self.signer.solana_sign(&payload, round);

            // Store signature
            signatures
                .entry(round)
                .or_default()
                .insert(self.me, signature.clone());

            // Return signature to orchestrator
            let message = wire::Aggregation {
                round,
                var1: message.var1.clone(),
                var2: message.var2.clone(),
                var3: message.var3.clone(),
                payload: Some(Payload::Signature(signature.to_vec())),
            };
            let mut buf = Vec::with_capacity(message.encode_size());
            message.write(&mut buf);
            info!("Sending signature for round: {}", round);

            // Broadcast to all (including orchestrator)
            sender
                .send(commonware_p2p::Recipients::All, Bytes::from(buf), true)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to broadcast signature: {}", e))?;
            info!(round, "broadcast signature");
        }

        Ok(())
    }
}
