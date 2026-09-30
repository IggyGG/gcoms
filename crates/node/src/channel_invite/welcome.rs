//! Durable enrollment result. Bootstrap records are MLS-authenticated at the
//! Welcome epoch and travel with that exact result, rather than depending on
//! transient directory pushes arriving after a lost Welcome.
const MAGIC: &[u8; 6] = b"GCEW01";
pub const MAX_BYTES: usize = 256 * 1024;
const MAX_RECORDS: usize = 160;

pub(crate) fn encode(welcome: &[u8], records: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if records.len() > MAX_RECORDS {
        return Err("enrollment bootstrap record limit reached".into());
    }
    let size = records.iter().try_fold(
        12usize
            .checked_add(welcome.len())
            .ok_or("enrollment result too large")?,
        |size, record| {
            size.checked_add(4)
                .and_then(|size| size.checked_add(record.len()))
                .ok_or("enrollment result too large")
        },
    )?;
    if size > MAX_BYTES {
        return Err("enrollment result too large".into());
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(welcome.len() as u32).to_be_bytes());
    bytes.extend_from_slice(welcome);
    bytes.extend_from_slice(&(records.len() as u16).to_be_bytes());
    for record in records {
        bytes.extend_from_slice(&(record.len() as u32).to_be_bytes());
        bytes.extend_from_slice(record);
    }
    Ok(bytes)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<(&[u8], Vec<&[u8]>), String> {
    if !bytes.starts_with(MAGIC) {
        return Ok((bytes, Vec::new()));
    }
    if bytes.len() > MAX_BYTES {
        return Err("enrollment result too large".into());
    }
    fn field<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
        let length_bytes = bytes
            .get(*pos..*pos + 4)
            .ok_or("truncated enrollment result")?;
        let length = u32::from_be_bytes(
            length_bytes
                .try_into()
                .map_err(|_| "invalid enrollment result")?,
        ) as usize;
        *pos += 4;
        let end = pos
            .checked_add(length)
            .ok_or("enrollment result too large")?;
        let field = bytes.get(*pos..end).ok_or("truncated enrollment result")?;
        *pos = end;
        Ok(field)
    }
    let mut pos = MAGIC.len();
    let welcome = field(bytes, &mut pos)?;
    let count = u16::from_be_bytes(
        bytes
            .get(pos..pos + 2)
            .ok_or("truncated enrollment result")?
            .try_into()
            .map_err(|_| "invalid enrollment result")?,
    ) as usize;
    pos += 2;
    if count > MAX_RECORDS {
        return Err("enrollment bootstrap record limit reached".into());
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(field(bytes, &mut pos)?);
    }
    if pos != bytes.len() || welcome.is_empty() {
        return Err("invalid enrollment result".into());
    }
    Ok((welcome, records))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn result_bounds_truncation_and_legacy() {
        let bytes = encode(b"welcome", &[b"directory".to_vec(), b"metadata".to_vec()]).unwrap();
        let (welcome, records) = decode(&bytes).unwrap();
        assert_eq!(welcome, b"welcome");
        assert_eq!(records, [b"directory".as_slice(), b"metadata".as_slice()]);
        for length in MAGIC.len()..bytes.len() {
            assert!(decode(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode(&extra).is_err());
        assert!(encode(&vec![0; MAX_BYTES], &[]).is_err());
        assert_eq!(decode(b"legacy").unwrap(), (b"legacy".as_slice(), vec![]));
    }
}
