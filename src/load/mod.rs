//! Payment loads: payments between the test accounts of a network, sent in
//! the background through one daemon, in rounds a [`Scenario`] sets.
//!
//! `network load start` writes the load's [`LoadSpec`] into
//! `<network>/load/<id>/` and starts `minimina network load run`, the
//! [`Worker`], as a process of its own. The worker reports in
//! `status.json` and logs every payment in `payments.jsonl`. It stops on
//! `network load stop` (SIGTERM), at the end of its scenario, when the
//! daemon refuses a payment with `After_slot_tx_end` (unless it goes on
//! across the fork), when no sender can pay, or after `max_failures` failed
//! payments in a row.

mod accounts;
mod chain_view;
mod clock;
mod control;
mod daemon_error;
mod daemon_gateway;
mod error;
mod file_journal;
mod gateway;
mod journal;
mod load_list;
mod load_process;
mod load_spec;
mod load_state;
mod load_status;
pub mod mina_amount;
mod payment_record;
mod scenario;
mod sender;
mod sender_status;
mod stop_reason;
mod store;
mod summary;
mod worker;

pub use accounts::{pick_node, pick_senders, test_accounts};
pub use chain_view::ChainView;
pub use clock::{Clock, SystemClock};
pub use control::STOP_TIMEOUT;
pub use daemon_error::DaemonError;
pub use daemon_gateway::DaemonGateway;
pub use error::LoadError;
pub use file_journal::FileJournal;
pub use gateway::Gateway;
pub use journal::Journal;
pub use load_list::LoadList;
pub use load_process::LoadProcess;
pub use load_spec::LoadSpec;
pub use load_state::LoadState;
pub use load_status::LoadStatus;
pub use payment_record::PaymentRecord;
pub use scenario::{Scenario, ScenarioKind};
pub use sender::Sender;
pub use sender_status::SenderStatus;
pub use stop_reason::StopReason;
pub use store::LoadStore;
pub use summary::LoadSummary;
pub use worker::{Worker, POLL};

#[cfg(test)]
mod worker_tests;
