//! On-disk `SessionExport` envelope (`LG01`).

use libgary_core::engine::{DeviceStateAnchorV1, SessionExport};

use crate::StorageError;

const BUNDLE_MAGIC: &[u8; 4] = b"LG01";
const BUNDLE_VERSION: u32 = 1;

pub fn encode_bundle(exp: &SessionExport) -> Vec<u8> {
    let anchor = exp.anchor.encode();
    let mut out =
        Vec::with_capacity(4 + 4 + 4 + anchor.len() + 4 + 64 + 16 + 4 + 4 + exp.ratchet_blob.len());
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_VERSION.to_be_bytes());
    out.extend_from_slice(&(anchor.len() as u32).to_be_bytes());
    out.extend_from_slice(&anchor);
    out.extend_from_slice(&(64u32.to_be_bytes()));
    out.extend_from_slice(&exp.okm);
    out.extend_from_slice(&exp.session_id);
    out.extend_from_slice(&exp.epoch.to_be_bytes());
    out.extend_from_slice(&(exp.ratchet_blob.len() as u32).to_be_bytes());
    out.extend_from_slice(&exp.ratchet_blob);
    out
}

pub fn decode_bundle(bytes: &[u8]) -> Result<SessionExport, StorageError> {
    if bytes.len() < 4 + 4 {
        return Err(StorageError::BundleDecode("truncated header"));
    }
    if &bytes[0..4] != BUNDLE_MAGIC {
        return Err(StorageError::BadMagic);
    }
    let ver = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
    if ver != BUNDLE_VERSION {
        return Err(StorageError::BadMagic);
    }
    let mut o = 8usize;
    let alen = read_u32(bytes, &mut o, "anchor len")? as usize;
    if alen != DeviceStateAnchorV1::LEN {
        return Err(StorageError::BundleDecode("anchor len"));
    }
    let anchor_bytes: [u8; DeviceStateAnchorV1::LEN] =
        take(bytes, &mut o, alen, "anchor")?.try_into().unwrap();
    let anchor = DeviceStateAnchorV1::decode(&anchor_bytes);

    let okml = read_u32(bytes, &mut o, "okm len")? as usize;
    if okml != 64 {
        return Err(StorageError::BundleDecode("okm len"));
    }
    let okm: [u8; 64] = take(bytes, &mut o, okml, "okm")?.try_into().unwrap();

    let sid: [u8; 16] = take(bytes, &mut o, 16, "session_id")?.try_into().unwrap();

    let epoch_bytes = take(bytes, &mut o, 4, "epoch")?;
    let epoch = u32::from_be_bytes(epoch_bytes.try_into().unwrap());

    let blob_len = read_u32(bytes, &mut o, "blob len")? as usize;
    let ratchet_blob = take(bytes, &mut o, blob_len, "blob")?.to_vec();

    if o != bytes.len() {
        return Err(StorageError::BundleDecode("trailing garbage"));
    }

    Ok(SessionExport {
        ratchet_blob,
        okm,
        anchor,
        session_id: sid,
        epoch,
    })
}

fn read_u32(bytes: &[u8], o: &mut usize, ctx: &'static str) -> Result<u32, StorageError> {
    if *o + 4 > bytes.len() {
        return Err(StorageError::BundleDecode(ctx));
    }
    let v = u32::from_be_bytes(bytes[*o..*o + 4].try_into().unwrap());
    *o += 4;
    Ok(v)
}

fn take<'a>(
    bytes: &'a [u8],
    o: &mut usize,
    len: usize,
    ctx: &'static str,
) -> Result<&'a [u8], StorageError> {
    if *o + len > bytes.len() {
        return Err(StorageError::BundleDecode(ctx));
    }
    let s = &bytes[*o..*o + len];
    *o += len;
    Ok(s)
}
