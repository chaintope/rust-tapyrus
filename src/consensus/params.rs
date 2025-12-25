// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
// Changes for rust-tapyrus is licensed as below.
// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

//! Consensus parameters
//!
//! This module provides predefined set of parameters for different chains.
//!

use crate::network::constants::Network;

#[derive(Debug, Clone)]
/// Parameters that influence chain consensus.
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
}

impl Params {
    /// Creates parameters set for the given network.
    pub fn new(network: Network) -> Self {
        match network {
            Network::Prod => Params {
                network: Network::Prod,
            },
            Network::Dev => Params {
                network: Network::Dev,
            },
        }
    }
}
