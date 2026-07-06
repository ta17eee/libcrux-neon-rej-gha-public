from pathlib import Path


path = Path("polynomials-aarch64/src/rejsample.rs")
text = path.read_text()
old = """    let idx0 = usize::try_from(pick0).unwrap();
    _vst1q_s16(&mut out[0..8], shifted0);
    _vst1q_s16(&mut out[idx0..idx0 + 8], shifted1);
"""
new = """    let idx0 = usize::try_from(pick0).unwrap();
    if pick0 > 8 || pick1 > 8 || idx0 + 8 > out.len() || used0 > 0xff || used1 > 0xff {
        panic!(
            "NEON_REJ_SCALAR_DEBUG used0=0x{:04x} used0_u8=0x{:02x} used1=0x{:04x} used1_u8=0x{:02x} pick0={} pick1={} idx0={} out_len={}",
            used0,
            used0 as u8,
            used1,
            used1 as u8,
            pick0,
            pick1,
            idx0,
            out.len()
        );
    }
    _vst1q_s16(&mut out[0..8], shifted0);
    _vst1q_s16(&mut out[idx0..idx0 + 8], shifted1);
"""
if old not in text:
    raise SystemExit("expected rej_sample store block not found")
path.write_text(text.replace(old, new))
