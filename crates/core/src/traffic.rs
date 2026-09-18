//! Traffic intent is explicit. Control and ordinary application messages use
//! Interactive; bulk must never borrow its reserved delivery credit.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TrafficClass {
    #[default]
    Interactive = 0,
    Bulk = 1,
}

impl TrafficClass {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Interactive),
            1 => Some(Self::Bulk),
            _ => None,
        }
    }
}
