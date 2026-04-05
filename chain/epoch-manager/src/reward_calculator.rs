use crate::validator_stats::get_validator_online_ratio;
use near_chain_configs::GenesisConfig;
use near_primitives::types::{AccountId, Balance, BlockChunkValidatorStats};
use near_primitives::version::{PROD_GENESIS_PROTOCOL_VERSION, ProtocolVersion};
use num_rational::Rational32;
use primitive_types::{U256, U512};
use std::collections::HashMap;

pub(crate) const NUM_NS_IN_SECOND: u64 = 1_000_000_000;
pub const NUM_SECONDS_IN_A_YEAR: u64 = 24 * 60 * 60 * 365;

// ── Final Layer v1002: Fixed APY staking schedule ────────────────────────────
// Replaces NEAR's total-supply inflation model.
// Each validator earns:  stake × apy_rate × epoch_duration_seconds / seconds_per_year
// The APY is fixed per calendar year (counted in epochs):
//   Year 1 (epochs   0 –  729): 20/100
//   Year 2 (epochs 730 – 1459):  5/100
//   Year 3+  (epoch 1460+):      1/100
//
// 730 epochs/year  =  365 days × (86 400 s/day ÷ 43 200 s/epoch)
//
// No re-entrancy risk: rewards are computed once per epoch boundary by the
// epoch manager and written atomically before any account mutations occur.
// No state is mutated twice within the same epoch transition.
pub const FL_EPOCHS_PER_YEAR: u64 = 730;

/// Return (numerator, denominator) of the annual APY for the given epoch height.
pub fn fl_apy_rate(epoch_height: u64) -> (u64, u64) {
    let year = epoch_height / FL_EPOCHS_PER_YEAR;
    match year {
        0 => (20, 100), // Year 1: 20% APY
        1 => (5, 100),  // Year 2:  5% APY
        _ => (1, 100),  // Year 3+: 1% APY (perpetual floor)
    }
}

/// Human-readable APY percentage for the given epoch height (for RPC/UI display).
pub fn fl_apy_pct(epoch_height: u64) -> f64 {
    let (n, d) = fl_apy_rate(epoch_height);
    n as f64 / d as f64 * 100.0
}

/// APR = ln(1 + APY).  Useful for per-second display.
pub fn fl_apr_pct(epoch_height: u64) -> f64 {
    let apy = fl_apy_pct(epoch_height) / 100.0;
    (1.0 + apy).ln() * 100.0
}

/// Which halving year (0-indexed) this epoch belongs to.
pub fn fl_current_year(epoch_height: u64) -> u64 {
    epoch_height / FL_EPOCHS_PER_YEAR
}

/// Contains online thresholds for validators.
#[derive(Clone, Debug)]
pub struct ValidatorOnlineThresholds {
    /// Online minimum threshold below which validator doesn't receive reward.
    pub online_min_threshold: Rational32,
    /// Online maximum threshold above which validator gets full reward.
    pub online_max_threshold: Rational32,
    /// If set, contains a number between 0 and 100 (percentage), and endorsement ratio
    /// below this threshold will be treated 0, and otherwise be treated 1,
    /// before calculating the average uptime ratio of the validator.
    /// If not set, endorsement ratio will be used as is.
    pub endorsement_cutoff_threshold: Option<u8>,
}

#[derive(Clone, Debug)]
pub struct RewardCalculator {
    pub num_blocks_per_year: u64,
    pub epoch_length: u64,
    pub protocol_reward_rate: Rational32,
    pub protocol_treasury_account: AccountId,
    pub num_seconds_per_year: u64,
    pub genesis_protocol_version: ProtocolVersion,
}

impl RewardCalculator {
    pub fn new(config: &GenesisConfig, epoch_length: u64) -> Self {
        RewardCalculator {
            num_blocks_per_year: config.num_blocks_per_year,
            epoch_length,
            protocol_reward_rate: config.protocol_reward_rate,
            protocol_treasury_account: config.protocol_treasury_account.clone(),
            num_seconds_per_year: NUM_SECONDS_IN_A_YEAR,
            genesis_protocol_version: config.protocol_version,
        }
    }

    /// Final Layer v1002: Fixed APY validator reward calculation.
    ///
    /// Each validator earns:
    ///   reward = stake × apy_rate × epoch_duration_seconds / seconds_per_year
    ///
    /// The APY rate depends on which year the chain is in (see `fl_apy_rate`).
    /// Rewards are scaled by the validator's uptime ratio (same online threshold
    /// logic as before), ensuring validators must perform to earn their full APY.
    ///
    /// No treasury cut is taken from staking rewards in v1002.  Treasury funding
    /// should come from a dedicated allocation in genesis, not validator inflation.
    ///
    /// Security properties:
    /// - No overflow: U512 arithmetic used for intermediate products.
    /// - No double-count: each (account_id, stats) pair processed exactly once.
    /// - No re-entrancy: called once at epoch finalization; no callbacks issued.
    /// - Idempotent on zero stake: zero-stake validators receive zero reward.
    ///
    /// `epoch_height` determines the APY year.  Pass `epoch_info.epoch_height()`.
    pub fn calculate_reward(
        &self,
        validator_block_chunk_stats: HashMap<AccountId, BlockChunkValidatorStats>,
        validator_stake: &HashMap<AccountId, Balance>,
        _total_supply: Balance,
        _protocol_version: ProtocolVersion,
        epoch_duration: u64,
        online_thresholds: ValidatorOnlineThresholds,
        _max_inflation_rate: Rational32,
        epoch_height: u64,
    ) -> (HashMap<AccountId, Balance>, Balance) {
        let mut res = HashMap::new();
        let num_validators = validator_block_chunk_stats.len();

        // No treasury reward in v1002 fixed-APY model.
        res.insert(self.protocol_treasury_account.clone(), Balance::ZERO);

        if num_validators == 0 {
            return (res, Balance::ZERO);
        }

        // epoch_duration is in nanoseconds; convert to seconds for APY math.
        let epoch_seconds = epoch_duration / NUM_NS_IN_SECOND;
        let (apy_numer, apy_denom) = fl_apy_rate(epoch_height);
        let seconds_per_year = self.num_seconds_per_year;

        let mut epoch_actual_reward = Balance::ZERO;

        for (account_id, stats) in validator_block_chunk_stats {
            let production_ratio =
                get_validator_online_ratio(&stats, online_thresholds.endorsement_cutoff_threshold);
            let average_produced_numer = production_ratio.numer();
            let average_produced_denom = production_ratio.denom();

            let expected_blocks = stats.block_stats.expected;
            let expected_chunks = stats.chunk_stats.expected();
            let expected_endorsements = stats.chunk_stats.endorsement_stats().expected;

            let online_min_numer =
                U256::from(*online_thresholds.online_min_threshold.numer() as u64);
            let online_min_denom =
                U256::from(*online_thresholds.online_min_threshold.denom() as u64);

            // Validators below online_min_threshold or with no expected work earn nothing.
            let reward = if average_produced_numer * online_min_denom
                < online_min_numer * average_produced_denom
                || (expected_chunks == 0 && expected_blocks == 0 && expected_endorsements == 0)
            {
                Balance::ZERO
            } else {
                let stake = *validator_stake
                    .get(&account_id)
                    .unwrap_or_else(|| panic!("{} is not a validator", account_id));

                // uptime_ratio = min(1, (uptime - min) / (max - min))
                let online_max_numer =
                    U256::from(*online_thresholds.online_max_threshold.numer() as u64);
                let online_max_denom =
                    U256::from(*online_thresholds.online_max_threshold.denom() as u64);
                let online_numer =
                    online_max_numer * online_min_denom - online_min_numer * online_max_denom;
                let mut uptime_numer = (average_produced_numer * online_min_denom
                    - online_min_numer * average_produced_denom)
                    * online_max_denom;
                let uptime_denum = online_numer * average_produced_denom;
                uptime_numer =
                    if uptime_numer > uptime_denum { uptime_denum } else { uptime_numer };

                // Full epoch reward for this validator (before uptime scaling):
                //   full_reward = stake × apy_numer × epoch_seconds
                //                 ─────────────────────────────────────
                //                        apy_denom × seconds_per_year
                //
                // Then scale by uptime: reward = full_reward × uptime_numer / uptime_denum
                //
                // Combined (single U512 expression to avoid intermediate overflow):
                //   reward = stake × apy_numer × epoch_seconds × uptime_numer
                //            ────────────────────────────────────────────────
                //            apy_denom × seconds_per_year × uptime_denum
                Balance::from_yoctonear(
                    (U512::from(stake.as_yoctonear())
                        * U512::from(apy_numer)
                        * U512::from(epoch_seconds)
                        * U512::from(uptime_numer)
                        / (U512::from(apy_denom)
                            * U512::from(seconds_per_year)
                            * U512::from(uptime_denum)))
                    .as_u128(),
                )
            };
            res.insert(account_id, reward);
            epoch_actual_reward = epoch_actual_reward.checked_add(reward).unwrap();
        }
        (res, epoch_actual_reward)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_primitives::epoch_manager::EpochConfigStore;
    use near_primitives::types::{BlockChunkValidatorStats, ChunkStats, ValidatorStats};
    use near_primitives::version::{PROD_GENESIS_PROTOCOL_VERSION, PROTOCOL_VERSION};
    use num_rational::Ratio;
    use std::collections::HashMap;

    #[test]
    fn test_zero_produced_and_expected() {
        let epoch_length = 1;
        let max_inflation_rate = Ratio::new(0, 1);
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: 1000000,
            epoch_length,
            protocol_reward_rate: Ratio::new(0, 1),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: 1000000,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let validator_block_chunk_stats = HashMap::from([
            (
                "test1".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats::default(),
                },
            ),
            (
                "test2".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 1 },
                    chunk_stats: ChunkStats::new_with_production(0, 1),
                },
            ),
        ]);
        let validator_stake = HashMap::from([
            ("test1".parse().unwrap(), Balance::from_yoctonear(100)),
            ("test2".parse().unwrap(), Balance::from_yoctonear(100)),
        ]);
        let total_supply = Balance::from_yoctonear(1_000_000_000_000);
        let result = reward_calculator.calculate_reward(
            validator_block_chunk_stats,
            &validator_stake,
            total_supply,
            PROTOCOL_VERSION,
            epoch_length * NUM_NS_IN_SECOND,
            ValidatorOnlineThresholds {
                online_min_threshold: Ratio::new(9, 10),
                online_max_threshold: Ratio::new(1, 1),
                endorsement_cutoff_threshold: None,
            },
            max_inflation_rate,
            0, // epoch_height (test: year 1, 20% APY)
        );
        assert_eq!(
            result.0,
            HashMap::from([
                ("near".parse().unwrap(), Balance::ZERO),
                ("test1".parse().unwrap(), Balance::ZERO),
                ("test2".parse().unwrap(), Balance::ZERO)
            ])
        );
    }

    /// Test reward calculation when validators are not fully online.
    #[test]
    fn test_reward_validator_different_online() {
        let epoch_length = 1000;
        let max_inflation_rate = Ratio::new(1, 100);
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: 1000,
            epoch_length,
            protocol_reward_rate: Ratio::new(0, 10),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: 1000,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let validator_block_chunk_stats = HashMap::from([
            (
                "test1".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 945, expected: 1000 },
                    chunk_stats: ChunkStats::new_with_production(945, 1000),
                },
            ),
            (
                "test2".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 999, expected: 1000 },
                    chunk_stats: ChunkStats::new_with_production(999, 1000),
                },
            ),
            (
                "test3".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 850, expected: 1000 },
                    chunk_stats: ChunkStats::new_with_production(850, 1000),
                },
            ),
        ]);
        let validator_stake = HashMap::from([
            ("test1".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test2".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test3".parse().unwrap(), Balance::from_yoctonear(500_000)),
        ]);
        let total_supply = Balance::from_yoctonear(1_000_000_000);
        let result = reward_calculator.calculate_reward(
            validator_block_chunk_stats,
            &validator_stake,
            total_supply,
            PROTOCOL_VERSION,
            epoch_length * NUM_NS_IN_SECOND,
            ValidatorOnlineThresholds {
                online_min_threshold: Ratio::new(9, 10),
                online_max_threshold: Ratio::new(99, 100),
                endorsement_cutoff_threshold: None,
            },
            max_inflation_rate,
            0, // epoch_height (test: year 1, 20% APY)
        );
        // Total reward is 10_000_000. Divided by 3 equal stake validators - each gets 3_333_333.
        // test1 with 94.5% online gets 50% because of linear between (0.99-0.9) online.
        assert_eq!(
            result.0,
            HashMap::from([
                ("near".parse().unwrap(), Balance::ZERO),
                ("test1".parse().unwrap(), Balance::from_yoctonear(1_666_666)),
                ("test2".parse().unwrap(), Balance::from_yoctonear(3_333_333)),
                ("test3".parse().unwrap(), Balance::ZERO)
            ])
        );
        assert_eq!(result.1, Balance::from_yoctonear(4_999_999));
    }

    /// Test reward calculation for chunk only or block only producers
    #[test]
    fn test_reward_chunk_only_producer() {
        let epoch_length = 1000;
        let max_inflation_rate = Ratio::new(1, 100);
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: 1000,
            epoch_length,
            protocol_reward_rate: Ratio::new(0, 10),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: 1000,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let validator_block_chunk_stats = HashMap::from([
            (
                "test1".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 945, expected: 1000 },
                    chunk_stats: ChunkStats::new_with_production(945, 1000),
                },
            ),
            // chunk only producer
            (
                "test2".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats::new_with_production(999, 1000),
                },
            ),
            // block only producer (not implemented right now, just for testing)
            (
                "test3".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 945, expected: 1000 },
                    chunk_stats: ChunkStats::default(),
                },
            ),
            // a validator that expected blocks and chunks are both 0 (this could occur with very
            // small probability for validators with little stakes)
            (
                "test4".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats::default(),
                },
            ),
        ]);
        let validator_stake = HashMap::from([
            ("test1".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test2".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test3".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test4".parse().unwrap(), Balance::from_yoctonear(500_000)),
        ]);
        let total_supply = Balance::from_yoctonear(1_000_000_000);
        let result = reward_calculator.calculate_reward(
            validator_block_chunk_stats,
            &validator_stake,
            total_supply,
            PROTOCOL_VERSION,
            epoch_length * NUM_NS_IN_SECOND,
            ValidatorOnlineThresholds {
                online_min_threshold: Ratio::new(9, 10),
                online_max_threshold: Ratio::new(99, 100),
                endorsement_cutoff_threshold: None,
            },
            max_inflation_rate,
            0, // epoch_height (test: year 1, 20% APY)
        );
        // Total reward is 10_000_000. Divided by 4 equal stake validators - each gets 2_500_000.
        // test1 with 94.5% online gets 50% because of linear between (0.99-0.9) online.
        {
            assert_eq!(
                result.0,
                HashMap::from([
                    ("near".parse().unwrap(), Balance::ZERO),
                    ("test1".parse().unwrap(), Balance::from_yoctonear(1_250_000)),
                    ("test2".parse().unwrap(), Balance::from_yoctonear(2_500_000)),
                    ("test3".parse().unwrap(), Balance::from_yoctonear(1_250_000)),
                    ("test4".parse().unwrap(), Balance::ZERO)
                ])
            );
            assert_eq!(result.1, Balance::from_yoctonear(5_000_000));
        }
    }

    #[test]
    fn test_reward_stateless_validation() {
        let epoch_length = 1000;
        let max_inflation_rate = Ratio::new(1, 100);
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: 1000,
            epoch_length,
            protocol_reward_rate: Ratio::new(0, 10),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: 1000,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let validator_block_chunk_stats = HashMap::from([
            // Blocks, chunks, endorsements
            (
                "test1".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 945, expected: 1000 },
                    chunk_stats: ChunkStats {
                        production: ValidatorStats { produced: 944, expected: 1000 },
                        endorsement: ValidatorStats { produced: 946, expected: 1000 },
                    },
                },
            ),
            // Chunks and endorsements
            (
                "test2".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats {
                        production: ValidatorStats { produced: 998, expected: 1000 },
                        endorsement: ValidatorStats { produced: 1000, expected: 1000 },
                    },
                },
            ),
            // Blocks and endorsements
            (
                "test3".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 940, expected: 1000 },
                    chunk_stats: ChunkStats::new_with_endorsement(950, 1000),
                },
            ),
            // Endorsements only
            (
                "test4".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats::new_with_endorsement(1000, 1000),
                },
            ),
        ]);
        let validator_stake = HashMap::from([
            ("test1".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test2".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test3".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test4".parse().unwrap(), Balance::from_yoctonear(500_000)),
        ]);
        let total_supply = Balance::from_yoctonear(1_000_000_000);
        let result = reward_calculator.calculate_reward(
            validator_block_chunk_stats,
            &validator_stake,
            total_supply,
            PROTOCOL_VERSION,
            epoch_length * NUM_NS_IN_SECOND,
            ValidatorOnlineThresholds {
                online_min_threshold: Ratio::new(9, 10),
                online_max_threshold: Ratio::new(99, 100),
                endorsement_cutoff_threshold: None,
            },
            max_inflation_rate,
            0, // epoch_height (test: year 1, 20% APY)
        );
        // Total reward is 10_000_000. Divided by 4 equal stake validators - each gets 2_500_000.
        // test1 with 94.5% online gets 50% because of linear between (0.99-0.9) online.
        {
            assert_eq!(
                result.0,
                HashMap::from([
                    ("near".parse().unwrap(), Balance::ZERO),
                    ("test1".parse().unwrap(), Balance::from_yoctonear(1_250_000)),
                    ("test2".parse().unwrap(), Balance::from_yoctonear(2_500_000)),
                    ("test3".parse().unwrap(), Balance::from_yoctonear(1_250_000)),
                    ("test4".parse().unwrap(), Balance::from_yoctonear(2_500_000))
                ])
            );
            assert_eq!(result.1, Balance::from_yoctonear(7_500_000));
        }
    }

    #[test]
    fn test_reward_stateless_validation_with_endorsement_cutoff() {
        let epoch_length = 1000;
        let max_inflation_rate = Ratio::new(1, 100);
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: 1000,
            epoch_length,
            protocol_reward_rate: Ratio::new(0, 10),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: 1000,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let validator_block_chunk_stats = HashMap::from([
            // Blocks, chunks, endorsements - endorsement ratio cutoff is exceeded
            (
                "test1".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 945, expected: 1000 },
                    chunk_stats: ChunkStats {
                        production: ValidatorStats { produced: 944, expected: 1000 },
                        endorsement: ValidatorStats { produced: 946, expected: 1000 },
                    },
                },
            ),
            // Blocks, chunks, endorsements - endorsement ratio cutoff is not exceeded
            (
                "test2".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 945, expected: 1000 },
                    chunk_stats: ChunkStats {
                        production: ValidatorStats { produced: 944, expected: 1000 },
                        endorsement: ValidatorStats { produced: 446, expected: 1000 },
                    },
                },
            ),
            // Endorsements only - endorsement ratio cutoff is exceeded
            (
                "test3".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats::new_with_endorsement(946, 1000),
                },
            ),
            // Endorsements only - endorsement ratio cutoff is not exceeded
            (
                "test4".parse().unwrap(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 0, expected: 0 },
                    chunk_stats: ChunkStats::new_with_endorsement(446, 1000),
                },
            ),
        ]);
        let validator_stake = HashMap::from([
            ("test1".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test2".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test3".parse().unwrap(), Balance::from_yoctonear(500_000)),
            ("test4".parse().unwrap(), Balance::from_yoctonear(500_000)),
        ]);
        let total_supply = Balance::from_yoctonear(1_000_000_000);
        let result = reward_calculator.calculate_reward(
            validator_block_chunk_stats,
            &validator_stake,
            total_supply,
            PROTOCOL_VERSION,
            epoch_length * NUM_NS_IN_SECOND,
            ValidatorOnlineThresholds {
                online_min_threshold: Ratio::new(9, 10),
                online_max_threshold: Ratio::new(99, 100),
                endorsement_cutoff_threshold: Some(50),
            },
            max_inflation_rate,
            0, // epoch_height (test: year 1, 20% APY)
        );
        // "test2" does not get reward since its uptime ratio goes below online_min_threshold,
        // because its endorsement ratio is below the cutoff threshold.
        // "test4" does not get reward since its endorsement ratio is below the cutoff threshold.
        {
            assert_eq!(
                result.0,
                HashMap::from([
                    ("near".parse().unwrap(), Balance::ZERO),
                    ("test1".parse().unwrap(), Balance::from_yoctonear(1_750_000)),
                    ("test2".parse().unwrap(), Balance::ZERO),
                    ("test3".parse().unwrap(), Balance::from_yoctonear(2_500_000)),
                    ("test4".parse().unwrap(), Balance::ZERO)
                ])
            );
            assert_eq!(result.1, Balance::from_yoctonear(4_250_000));
        }
    }

    /// Test that under an extreme setting (total supply 100b, epoch length half a day),
    /// reward calculation will not overflow.
    #[test]
    fn test_reward_no_overflow() {
        let epoch_length = 60 * 60 * 12;
        let max_inflation_rate = Ratio::new(1, 40);
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: 60 * 60 * 24 * 365,
            // half a day
            epoch_length,
            protocol_reward_rate: Ratio::new(1, 10),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: 60 * 60 * 24 * 365,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let validator_block_chunk_stats = HashMap::from([(
            "test".parse().unwrap(),
            BlockChunkValidatorStats {
                block_stats: ValidatorStats { produced: 43200, expected: 43200 },
                chunk_stats: ChunkStats {
                    production: ValidatorStats { produced: 345600, expected: 345600 },
                    endorsement: ValidatorStats { produced: 345600, expected: 345600 },
                },
            },
        )]);
        let validator_stake =
            HashMap::from([("test".parse().unwrap(), Balance::from_near(500_000))]);
        // some hypothetical large total supply (100b)
        let total_supply = Balance::from_near(100_000_000_000);
        reward_calculator.calculate_reward(
            validator_block_chunk_stats,
            &validator_stake,
            total_supply,
            PROTOCOL_VERSION,
            epoch_length * NUM_NS_IN_SECOND,
            ValidatorOnlineThresholds {
                online_min_threshold: Ratio::new(9, 10),
                online_max_threshold: Ratio::new(1, 1),
                endorsement_cutoff_threshold: None,
            },
            max_inflation_rate,
            0, // epoch_height (test: year 1, 20% APY)
        );
    }

    /// v1002: Verify fixed APY schedule produces correct rewards.
    /// stake=100 NEAR, seconds_per_year=1_000_000, epoch_length=1 s
    /// Year 1 (epoch 0):   reward = 100 * 20/100 * 1/1_000_000 = 0.000002 NEAR = 2_000_000_000_000_000_000 yocto
    /// Year 2 (epoch 730): reward = 100 * 5/100  * 1/1_000_000 = 0.0000005 NEAR
    /// Year 3 (epoch 1460): reward = 100 * 1/100 * 1/1_000_000
    #[test]
    fn test_fl_fixed_apy_reward() {
        let epoch_length = 1u64;
        let account_id: AccountId = "test1".parse().unwrap();
        let seconds_per_year = 1_000_000u64;
        let reward_calculator = RewardCalculator {
            num_blocks_per_year: seconds_per_year,
            epoch_length,
            protocol_reward_rate: Ratio::new(0, 1),
            protocol_treasury_account: "near".parse().unwrap(),
            num_seconds_per_year: seconds_per_year,
            genesis_protocol_version: PROTOCOL_VERSION,
        };
        let stake = Balance::from_near(100);
        let validator_stake = HashMap::from([(account_id.clone(), stake)]);
        let total_supply = Balance::from_near(1_000_000_000);

        for (epoch_height, apy_numer, apy_denom) in
            [(0u64, 20u64, 100u64), (730, 5, 100), (1460, 1, 100)]
        {
            let stats = HashMap::from([(
                account_id.clone(),
                BlockChunkValidatorStats {
                    block_stats: ValidatorStats { produced: 1, expected: 1 },
                    chunk_stats: ChunkStats::default(),
                },
            )]);
            let (rewards, total) = reward_calculator.calculate_reward(
                stats,
                &validator_stake,
                total_supply,
                PROTOCOL_VERSION,
                epoch_length * NUM_NS_IN_SECOND,
                ValidatorOnlineThresholds {
                    online_min_threshold: Ratio::new(9, 10),
                    online_max_threshold: Ratio::new(99, 100),
                    endorsement_cutoff_threshold: None,
                },
                Ratio::new(0, 1),
                epoch_height,
            );
            // Treasury always zero in v1002.
            assert_eq!(rewards.get(&reward_calculator.protocol_treasury_account), Some(&Balance::ZERO));
            // Validator reward = stake * apy_numer * epoch_seconds / (apy_denom * seconds_per_year)
            // With 100% uptime (uptime_numer == uptime_denum) and only one validator.
            let expected_validator = Balance::from_yoctonear(
                (primitive_types::U512::from(stake.as_yoctonear())
                    * primitive_types::U512::from(apy_numer)
                    / primitive_types::U512::from(apy_denom)
                    / primitive_types::U512::from(seconds_per_year))
                .as_u128(),
            );
            assert_eq!(rewards.get(&account_id), Some(&expected_validator));
            assert_eq!(total, expected_validator);
        }
    }
}
