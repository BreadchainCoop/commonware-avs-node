//! Aggregate signatures from multiple contributors over the BN254 curve.
//!
//! # Usage (3 of 4 Threshold)
mod handlers;

use clap::{Arg, Command};
use commonware_avs_router::solana_helpers::{get_client_and_test_bls_ncn, get_operator_states};
use commonware_p2p::authenticated::lookup::{self, Network};
use commonware_runtime::{
    Metrics, Runner, Spawner,
    tokio::{self},
};
use commonware_utils::NZU32;
use governor::Quota;
use jito_bls_ncn_core::bls::solana_bls_interface::SolanaBN254G2;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// Unique namespace to avoid message replay attacks.
const APPLICATION_NAMESPACE: &[u8] = b"_COMMONWARE_AGGREGATION_";

fn main() {
    dotenv::dotenv().ok();

    // Initialize runtime
    let runtime_cfg = tokio::Config::default();
    let runner = tokio::Runner::new(runtime_cfg.clone());

    // Parse arguments
    let matches = Command::new("commonware-aggregation")
        .about("generate and verify BN254 Multi-Signatures")
        .arg(
            Arg::new("port")
                .long("port")
                .required(true)
                .help("Port to run the service on"),
        )
        .arg(
            Arg::new("operator_index")
                .long("operator_index")
                .required(true)
                .help("Operator index"),
        )
        .get_matches();

    let port_str = matches
        .get_one::<String>("port")
        .expect("Please provide port");
    let port = port_str.parse::<u16>().expect("Invalid port");
    let index_str = matches
        .get_one::<String>("operator_index")
        .expect("Please provide operator index");
    let index = index_str.parse::<u16>().expect("Invalid operator index");

    println!("Starting contributor on port {} with operator index {}", port, index);

    let (client, test_bls_ncn) = get_client_and_test_bls_ncn().expect("Could not load Test BLS NCN");
    let signer = test_bls_ncn.test_operators[index as usize].bls_keypair;

    println!("Loaded signer for operator index {}", index);

    // Start runtime
    runner.start(|context: tokio::Context| async move {
        println!("Runtime started");

        let mut recipients: Vec<(SolanaBN254G2, SocketAddr)> = Vec::new();
        let orchestrator_pub_key;
        {
            println!("Fetching operator states...");
            let operators = get_operator_states(&client, &test_bls_ncn)
                .await
                .expect("Failed to get operator states");
            println!("Found {} operators", operators.len());

            let participants = operators.clone();
            if participants.is_empty() {
                panic!("Please provide at least one participant");
            }
            for participant in &participants {
                let verifier = participant.bls_operator.g2;
                println!("Registered authorized key: {:?}", verifier);
                if let Some(socket) = participant.socket_address {
                    recipients.push((verifier, socket));
                }
            }

            orchestrator_pub_key = test_bls_ncn.bls_orchestrator.bls_public_key.g2;
            println!("Orchestrator pub key: {:?}", orchestrator_pub_key);

            let orchestrator_addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                3000,
            );
            recipients.push((orchestrator_pub_key.clone(), orchestrator_addr));
            println!("Added orchestrator at {}", orchestrator_addr);
        }

        // Initialize logger BEFORE using tracing macros
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::stdout)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);

        tracing::info!("Logger initialized");

        // Configure network
        const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
        let my_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let my_local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        tracing::info!("Configuring P2P network on {}...", my_local_addr);

        let p2p_cfg = lookup::Config::aggressive(
            signer.clone(),
            APPLICATION_NAMESPACE,
            my_addr,
            my_local_addr,
            MAX_MESSAGE_SIZE,
        );
        let (mut network, mut oracle) = Network::new(context.with_label("network"), p2p_cfg);

        tracing::info!("Registering {} authorized peers", recipients.len());
        oracle.register(0, recipients).await;

        // Parse contributors from operator states
        let mut contributors = Vec::new();
        let mut contributors_map = HashMap::new();
        let quorum_infos = get_operator_states(&client, &test_bls_ncn)
            .await
            .expect("Failed to get operator states");
        let operators = &quorum_infos;
        if operators.is_empty() {
            panic!("Please provide at least one contributor");
        }
        for operator in operators {
            let verifier = operator.bls_operator.g2;
            let verifier_g1 = operator.bls_operator.g1;
            tracing::info!(key = ?verifier, "registered contributor");
            contributors.push(verifier.clone());
            contributors_map.insert(verifier, verifier_g1);
        }

        const DEFAULT_MESSAGE_BACKLOG: usize = 256;

        let (sender, receiver) =
            network.register(0, Quota::per_second(NZU32!(1)), DEFAULT_MESSAGE_BACKLOG);

        tracing::info!("Creating contributor handler...");
        let contributor = handlers::Contributor::new(orchestrator_pub_key, signer, contributors);

        tracing::info!("Spawning contributor task...");
        context.spawn(|_| async move {
            tracing::info!("Contributor task started, entering run loop...");
            let result = contributor.run(sender, receiver).await;
            tracing::error!("Contributor run exited with: {:?}", result);
        });

        tracing::info!("Starting network...");
        let _ = network.start().await;
        tracing::info!("Network started");
    });
}
