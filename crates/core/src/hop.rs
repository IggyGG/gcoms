//! In-band hop status (SPEC §5.2, §7.5).
//!
//! Every post-authentication response is HTTP `200` carrying exactly one
//! wire cell, so a network observer cannot separate accepted, conflicting,
//! overloaded, or empty outcomes by size or status. Pre-authentication
//! failures use the decoy surface and are the only non-uniform responses.
//!
//! A reply that carries data (a grant, for example) is the handler's own
//! cell. A reply that carries no data is an `ACK` cell whose payload is
//! `[HOP_REPLY_VERSION, code]`.

use crate::{Cell, CellType};
use alloc::{format, string::String, vec};

pub const HOP_REPLY_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopReply {
    Accepted,
    Conflict,
    Overloaded,
    Internal,
}

impl HopReply {
    pub const fn code(self) -> u8 {
        match self {
            Self::Accepted => 0,
            Self::Conflict => 1,
            Self::Overloaded => 2,
            Self::Internal => 3,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Accepted),
            1 => Some(Self::Conflict),
            2 => Some(Self::Overloaded),
            3 => Some(Self::Internal),
            _ => None,
        }
    }

    pub fn cell(self) -> Cell {
        Cell::new(CellType::Ack, 0, 0, vec![HOP_REPLY_VERSION, self.code()])
    }

    /// Interpret a reply cell: a two-byte versioned `ACK` is a status; any
    /// other cell is handler data.
    pub fn parse(cell: &Cell) -> Option<Self> {
        if cell.cell_type() != Some(CellType::Ack) || cell.payload.len() != 2 {
            return None;
        }
        if cell.payload[0] != HOP_REPLY_VERSION {
            return None;
        }
        Self::from_code(cell.payload[1])
    }
}

/// What a client learned from one finite request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HopOutcome {
    /// Authenticated and admitted. Carries the handler's data cell, if any.
    Accepted(Option<Cell>),
    Conflict,
    Overloaded,
    Internal,
    /// The server answered from its decoy surface: the request never
    /// authenticated (unknown token, malformed body, or pre-auth limit).
    Decoy(u16),
}

impl HopOutcome {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    pub fn into_accepted(self) -> Result<Option<Cell>, String> {
        match self {
            Self::Accepted(cell) => Ok(cell),
            Self::Conflict => Err("TP-1 hop rejected: conflict".into()),
            Self::Overloaded => Err("TP-1 hop rejected: overloaded".into()),
            Self::Internal => Err("TP-1 hop rejected: internal".into()),
            Self::Decoy(status) => Err(format!("TP-1 hop unauthenticated: {status}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_roundtrip_and_encode_to_one_small_cell() {
        for reply in [
            HopReply::Accepted,
            HopReply::Conflict,
            HopReply::Overloaded,
            HopReply::Internal,
        ] {
            let cell = reply.cell();
            assert_eq!(HopReply::parse(&cell), Some(reply));
            assert_eq!(cell.encode_wire().unwrap().len(), 4096);
        }
        let data = Cell::new(CellType::Ack, 0, 0, vec![0; 180]);
        assert_eq!(HopReply::parse(&data), None);
        let wrong_version = Cell::new(CellType::Ack, 0, 0, vec![9, 0]);
        assert_eq!(HopReply::parse(&wrong_version), None);
    }
}
