use std::hash::Hash;

use anyhow::Result;
use commonware_cryptography::{PublicKey, Signer};
use commonware_p2p::{Receiver, Sender};

pub trait Contribute {
    type PublicKey: PublicKey + Ord + Eq + Hash + Clone;
    type Signer: Signer<PublicKey = Self::PublicKey>;

    fn new(
        orchestrator: Self::PublicKey,
        signer: Self::Signer,
        contributors: Vec<Self::PublicKey>,
    ) -> Self;

    async fn run<S, R>(self, sender: S, receiver: R) -> Result<()>
    where
        S: Sender,
        R: Receiver<PublicKey = Self::PublicKey>;
}
