use super::{Journal, LoadError, LoadStatus, LoadStore, PaymentRecord};

/// The worker's [`Journal`] in the load's directory.
pub struct FileJournal<'a> {
    pub store: &'a LoadStore,
    pub id: &'a str,
}

impl Journal for FileJournal<'_> {
    fn payment(&mut self, record: &PaymentRecord) -> Result<(), LoadError> {
        self.store.append_payment(self.id, record)
    }

    fn status(&mut self, status: &LoadStatus) -> Result<(), LoadError> {
        self.store.save_status(self.id, status)
    }
}
