use commonware_avs_router::validator::Validator;
use alloy::sol;
use bn254::{
    self, aggregate_signatures, aggregate_verify, Bn254, G1PublicKey, PublicKey, Signature as Bn254Signature
};
use commonware_cryptography::{Signer, Verifier};
use commonware_p2p::{Receiver, Sender};
use commonware_utils::hex;
use dotenv::dotenv;
use bytes::Bytes;
use commonware_codec::{EncodeSize, ReadExt, Write};
use std::collections::{HashMap, HashSet};
use tracing::info;
use anyhow::Result;

use commonware_avs_router::wire::{self, aggregation::Payload};

sol! {
    contract NumberEncoder {
        #[derive(Debug)]
        function yourNumbFunc(uint256 number) public returns (bytes memory);
    }
}


pub struct AggregatingContributor {
    orchestrator: PublicKey,
    signer: Bn254,
    me: usize,
    g1_map: HashMap<PublicKey, G1PublicKey>, // g2 (PublicKey) -> g1 (PublicKey)
    contributors: Vec<PublicKey>,
    ordered_contributors: HashMap<PublicKey, usize>,
    threshold: usize,
}

impl AggregatingContributor {
    pub fn new(
        orchestrator: PublicKey,
        signer: Bn254,
        mut contributors: Vec<PublicKey>,
        threshold: usize,
        g1_map: HashMap<PublicKey, G1PublicKey>,
    ) -> Self {
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
            contributors,
            ordered_contributors,
            threshold,
            g1_map,
        }
    }


    pub async fn run(
        self,
        mut sender: impl Sender,
        mut receiver: impl Receiver<PublicKey = PublicKey>,
    ) -> Result<()> {
        let mut signed = HashSet::new();
        let mut signatures: HashMap<u64, HashMap<usize, Bn254Signature>> = HashMap::new();
        let validator = Validator::new().await?;

        while let Ok((s, message)) = receiver.recv().await {
            // Parse message
            let Ok(message) = wire::Aggregation::read(&mut std::io::Cursor::new(message)) else {
                continue;
            };
            let round = message.round;

            // Check if from orchestrator
            if s != self.orchestrator {
                // Get contributor
                let Some(contributor) = self.ordered_contributors.get(&s) else {
                    info!("contributor not found: {:?}", s);
                    continue;
                };

                // Check if contributor already signed
                let Some(signatures) = signatures.get_mut(&round) else {
                    info!("signatures not found: {:?}", round);
                    continue;
                };
                if signatures.contains_key(contributor) {
                    info!("contributor already signed: {:?}", contributor);
                    continue;
                }

                // Extract signature
                let signature = match message.clone().payload {
                    Some(Payload::Signature(signature)) => signature,
                    _ => {
                        info!("signature not found: {:?}", message.clone().payload);
                        continue;
                    },
                };
                let Ok(signature) = Bn254Signature::try_from(signature.clone()) else {
                    info!("not a valid signature: {:?}", signature);
                    continue;
                };
                let mut buf = Vec::with_capacity(message.encode_size());
                message.write(&mut buf);
                let payload = validator.validate_and_return_expected_hash(&buf).await.unwrap();
                if !Bn254::verify(&self.signer, None, &payload, &signature) {
                    continue;
                }

                // Insert signature
                signatures.insert(*contributor, signature);

                // Check if should aggregate
                if signatures.len() < self.threshold {
                    info!("current signatures aggregated: {:?}, needed: {:?}, continuing aggregation", signatures.len(), self.threshold);
                    continue;
                }

                // Enough signatures, aggregate
                let mut participating = Vec::new();
                let mut participating_g1 = Vec::new();
                let mut sigs = Vec::new();
                for i in 0..self.contributors.len() {
                    let Some(signature) = signatures.get(&i) else {
                        continue;
                    };
                    let contributor = &self.contributors[i];
                    participating.push(contributor.clone());
                    participating_g1.push(self.g1_map[contributor].clone());
                    sigs.push(signature.clone());
                }
                let agg_signature = aggregate_signatures(&sigs).unwrap();

                // Verify aggregated signature (already verified individual signatures so should never fail)
                if !aggregate_verify(&participating, None, &payload, &agg_signature) {
                    panic!("failed to verify aggregated signature");
                }
                info!(
                    round,
                    msg = hex(&payload),
                    ?participating,
                    signature = hex(&agg_signature),
                    "aggregated signatures",
                );
                continue;
            }


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
            let signature = self.signer.sign(None, &payload);

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
