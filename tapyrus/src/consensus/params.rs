// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus parameters.
//!
//! This module provides a predefined set of parameters for different Bitcoin
//! chains (such as mainnet, testnet).
//!

use crate::network::Network;

/// Parameters that influence chain consensus.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: u32,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: u32,
}

impl Params {
    /// Creates parameters set for the given network.
    pub fn new(network: Network) -> Self {
        match network {
            Network::Bitcoin => Params {
                network: Network::Bitcoin,
                rule_change_activation_threshold: 1916, // 95%
                miner_confirmation_window: 2016,
            },
            Network::Testnet => Params {
                network: Network::Testnet,
                rule_change_activation_threshold: 1512, // 75%
                miner_confirmation_window: 2016,
            },
            Network::Signet => Params {
                network: Network::Signet,
                rule_change_activation_threshold: 1916, // 95%
                miner_confirmation_window: 2016,
            },
            Network::Regtest => Params {
                network: Network::Regtest,
                rule_change_activation_threshold: 108, // 75%
                miner_confirmation_window: 144,
            },
            Network::Paradium => Params {
                network: Network::Paradium,
                rule_change_activation_threshold: 108, // 75%
                miner_confirmation_window: 144,
            },
        }
    }
}
