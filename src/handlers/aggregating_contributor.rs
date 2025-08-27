use anyhow::Result;
use bn254::{
    self, Bn254, G1PublicKey, PublicKey, Signature as Bn254Signature, aggregate_signatures,
    aggregate_verify,
};
use bytes::Bytes;
use commonware_avs_router::validator::Validator;
use commonware_codec::{EncodeSize, ReadExt, Write};
use commonware_cryptography::Signer;
use commonware_p2p::{Receiver, Sender};
use commonware_utils::hex;
use dotenv::dotenv;
use std::collections::{HashMap, HashSet};
use tracing::info;

use commonware_avs_router::wire::{self, aggregation::Payload};
use crate::handlers::traits::Contribute;
use crate::handlers::traits::Contribute;

use super::traits::AggregationInput;

pub struct AggregatingContributor {
    orchestrator: PublicKey,
    signer: Bn254,
    me: usize,
    g1_map: HashMap<PublicKey, G1PublicKey>, // g2 (PublicKey) -> g1 (PublicKey)
    contributors: Vec<PublicKey>,
    ordered_contributors: HashMap<PublicKey, usize>,
    threshold: usize,
}
 
impl Contribute for AggregatingContributor {
    type PublicKey = PublicKey;
    type Signer = Bn254;

    fn new(
        orchestrator: PublicKey,
        signer: Bn254,
        mut contributors: Vec<PublicKey>,
        aggregation_data: Option<AggregationInput>
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

    async fn run<S, R>(
        self,
        mut sender: S,
        mut receiver: R,
    ) -> Result<()>
    where
        S: Sender,
        R: Receiver<PublicKey = PublicKey>
        {
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
                    }
                };
                let Ok(signature) = Bn254Signature::try_from(signature.clone()) else {
                    info!("not a valid signature: {:?}", signature);
                    continue;
                };
                let mut buf = Vec::with_capacity(message.encode_size());
                message.write(&mut buf);
                let Ok(payload) = validator.validate_and_return_expected_hash(&buf).await else {
                    info!(
                        "failed to validate payload for contributor: {:?}",
                        contributor
                    );
                    continue;
                };
                // Verify signature from contributor using aggregate_verify with single public key
                if !aggregate_verify(&[s.clone()], None, &payload, &signature) {
                    info!("invalid signature from contributor: {:?}", contributor);
                    continue;
                }

                // Insert signature
                signatures.insert(*contributor, signature);

                // Check if should aggregate
                if signatures.len() < self.threshold {
                    info!(
                        "current signatures aggregated: {:?}, needed: {:?}, continuing aggregation",
                        signatures.len(),
                        self.threshold
                    );
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
                let Some(agg_signature) = aggregate_signatures(&sigs) else {
                    info!("failed to aggregate signatures");
                    continue;
                };

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

impl Contribute for AggregatingContributor {
    type PublicKey = PublicKey;
    type Signer = Bn254;

    fn new(
        orchestrator: Self::PublicKey,
        signer: Self::Signer,
        mut contributors: Vec<Self::PublicKey>,
    ) -> Self {
        // Default aggregation settings when constructed via Contribute::new
        let threshold = contributors.len();
        let g1_map: HashMap<PublicKey, G1PublicKey> = HashMap::new();

        // Reuse the existing constructor
        Self::new(orchestrator, signer, contributors, threshold, g1_map)
    }

    async fn run<S, R>(self, sender: S, receiver: R) -> Result<()>
    where
        S: Sender,
        R: Receiver<PublicKey = Self::PublicKey>,
    {
        // Forward to the inherent method implementation
        self.run(sender, receiver).await
    }
}
