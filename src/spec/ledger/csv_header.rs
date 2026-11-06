use crate::spec::LedgerProblem;

/// A column of a CSV ledger file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Column {
    PublicKey,
    Balance,
    PrivateKey,
    Delegate,
}

impl std::str::FromStr for Column {
    type Err = LedgerProblem;

    fn from_str(name: &str) -> Result<Self, LedgerProblem> {
        match name.trim() {
            "public_key" => Ok(Column::PublicKey),
            "balance" => Ok(Column::Balance),
            "private_key" => Ok(Column::PrivateKey),
            "delegate" => Ok(Column::Delegate),
            other => Err(LedgerProblem::UnknownColumn(other.to_string())),
        }
    }
}

/// The header line of a CSV ledger file: which column is where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsvHeader {
    pub columns: Vec<Column>,
}

impl std::str::FromStr for CsvHeader {
    type Err = LedgerProblem;

    fn from_str(line: &str) -> Result<Self, LedgerProblem> {
        let columns: Vec<Column> = line.split(',').map(str::parse).collect::<Result<_, _>>()?;
        if !columns.contains(&Column::PublicKey) || !columns.contains(&Column::Balance) {
            return Err(LedgerProblem::RequiredColumns);
        }
        Ok(CsvHeader { columns })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_in_any_order() {
        let header: CsvHeader = "balance, public_key ,delegate".parse().unwrap();
        assert_eq!(
            header.columns,
            [Column::Balance, Column::PublicKey, Column::Delegate]
        );
        assert!(matches!(
            "pk,balance".parse::<CsvHeader>(),
            Err(LedgerProblem::UnknownColumn(c)) if c == "pk"
        ));
        assert!(matches!(
            "public_key".parse::<CsvHeader>(),
            Err(LedgerProblem::RequiredColumns)
        ));
    }
}
