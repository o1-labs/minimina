use super::{LoadError, LoadStatus, PaymentRecord};

/// Where the worker writes what it does.
pub trait Journal {
    fn payment(&mut self, record: &PaymentRecord) -> Result<(), LoadError>;
    fn status(&mut self, status: &LoadStatus) -> Result<(), LoadError>;
}
