//! Vesting schedules through a hardfork: every timed account of the prefork
//! genesis ledger must have the same schedule in the fork config and on the
//! daemon, and the daemon and rosetta must lock the amount the schedule gives
//! at the slot they answer for.

mod account_report;
mod daemon_view;
mod error;
mod fork_schedule;
mod report;
mod rosetta_view;
mod schedule;
mod timed_account;

pub use account_report::AccountReport;
pub use daemon_view::DaemonView;
pub use error::VestingError;
pub use fork_schedule::ForkSchedule;
pub use report::VestingReport;
pub use rosetta_view::RosettaView;
pub use schedule::VestingSchedule;
pub use timed_account::TimedAccount;

use super::Check;

/// The checks of one timed account. `fork` is none before `hardfork
/// prepare`; `rosetta` is none on a network without rosetta.
pub fn check_account(
    account: &TimedAccount,
    fork: Option<&ForkSchedule>,
    daemon: &DaemonView,
    rosetta: Option<&RosettaView>,
) -> AccountReport {
    let want = &account.schedule;
    let mut checks = Vec::new();
    if let Some(fork) = fork {
        checks.push(Check::new(
            "fork config schedule",
            *fork == ForkSchedule::Timed(*want),
            fork.to_string(),
        ));
    }
    checks.push(Check::new(
        "daemon schedule",
        daemon.schedule == Some(*want),
        daemon
            .schedule
            .map_or("no schedule".to_string(), |s| s.to_string()),
    ));
    // the daemon may already count the slot of the next block
    let expected = [want.locked_at(daemon.slot), want.locked_at(daemon.slot + 1)];
    checks.push(Check::new(
        format!("daemon locked at slot {}", daemon.slot),
        daemon.locked.is_some_and(|l| expected.contains(&l)),
        format!(
            "{} locked of {}, the schedule gives {}",
            daemon.locked.map_or("no".to_string(), |l| l.mina()),
            daemon.total.mina(),
            expected[0].mina()
        ),
    ));
    if let Some(r) = rosetta {
        checks.push(rosetta_check(want, r));
    }
    AccountReport::new(&account.public_key, want, checks)
}

fn rosetta_check(want: &VestingSchedule, r: &RosettaView) -> Check {
    let name = format!("rosetta at block {} {}", r.block_index, r.block_hash);
    let Some(slot) = r.slot else {
        return Check::new(
            name,
            false,
            "the daemon does not know the block rosetta answered for, so its slot is unknown",
        );
    };
    let locked = want.locked_at(slot);
    let liquid = r.total.nanomina().checked_sub(locked.nanomina());
    Check::new(
        format!("{name} (slot {slot})"),
        r.locked == locked && Some(r.liquid.nanomina()) == liquid,
        format!(
            "{} locked, {} liquid of {}; the schedule locks {}",
            r.locked.mina(),
            r.liquid.mina(),
            r.total.mina(),
            locked.mina()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mina_sdk::Currency;

    fn mina(s: &str) -> Currency {
        Currency::from_mina(s).unwrap()
    }

    fn account() -> TimedAccount {
        TimedAccount {
            public_key: "B62qcliff".into(),
            schedule: VestingSchedule {
                initial_minimum_balance: mina("1000"),
                cliff_time: 20,
                cliff_amount: mina("100"),
                vesting_period: 5,
                vesting_increment: mina("50"),
            },
        }
    }

    fn daemon(locked: &str) -> DaemonView {
        DaemonView {
            slot: 68,
            schedule: Some(account().schedule),
            total: mina("2000"),
            locked: Some(mina(locked)),
        }
    }

    fn rosetta(slot: Option<u64>, locked: &str, liquid: &str) -> RosettaView {
        RosettaView {
            block_index: 23,
            block_hash: "3NKx".into(),
            slot,
            total: mina("2000"),
            locked: mina(locked),
            liquid: mina(liquid),
        }
    }

    #[test]
    fn a_schedule_kept_through_the_fork_passes() {
        let fork = ForkSchedule::Timed(account().schedule);
        let r = rosetta(Some(68), "450", "1550");
        let report = check_account(&account(), Some(&fork), &daemon("450"), Some(&r));
        assert!(report.passed, "{report:?}");
        let names: Vec<_> = report.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "fork config schedule",
                "daemon schedule",
                "daemon locked at slot 68",
                "rosetta at block 23 3NKx (slot 68)"
            ]
        );
        // the next slot's amount is also right for the daemon
        let next = check_account(&account(), None, &daemon("450"), None);
        assert!(next.passed);
    }

    #[test]
    fn every_difference_fails_its_check() {
        let fork = ForkSchedule::Untimed;
        let r = rosetta(Some(68), "450", "1500");
        let report = check_account(&account(), Some(&fork), &daemon("500"), Some(&r));
        assert!(!report.passed);
        let failed: Vec<_> = report
            .checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(
            failed,
            [
                "fork config schedule",
                "daemon locked at slot 68",
                "rosetta at block 23 3NKx (slot 68)"
            ]
        );
        let unknown = check_account(
            &account(),
            None,
            &daemon("450"),
            Some(&rosetta(None, "450", "1550")),
        );
        assert!(!unknown.passed);
        assert!(unknown.checks[2].detail.contains("its slot is unknown"));
    }
}
