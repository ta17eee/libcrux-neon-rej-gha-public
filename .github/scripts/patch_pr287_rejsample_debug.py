from pathlib import Path


path = Path("polynomials-aarch64/src/rejsample.rs")
text = path.read_text()
old = """    let masked = _vandq_u16(mask0, bits);
    let used0 = _vaddvq_u16(masked);
    let masked = _vandq_u16(mask1, bits);
    let used1 = _vaddvq_u16(masked);
    let pick0 = used0.count_ones();
    let pick1 = used1.count_ones();

    // XXX: the indices used0 and used1 must be < 256.
    let index_vec0 = _vld1q_u8(&IDX_TABLE[(used0 as u8) as usize]);
    let shifted0 = _vreinterpretq_s16_u8(_vqtbl1q_u8(_vreinterpretq_u8_s16(input.low), index_vec0));
    let index_vec1 = _vld1q_u8(&IDX_TABLE[(used1 as u8) as usize]);
    let shifted1 =
        _vreinterpretq_s16_u8(_vqtbl1q_u8(_vreinterpretq_u8_s16(input.high), index_vec1));

    let idx0 = usize::try_from(pick0).unwrap();
    _vst1q_s16(&mut out[0..8], shifted0);
    _vst1q_s16(&mut out[idx0..idx0 + 8], shifted1);
"""
new = """    let masked0 = _vandq_u16(mask0, bits);
    let used0 = _vaddvq_u16(masked0);
    let masked1 = _vandq_u16(mask1, bits);
    let used1 = _vaddvq_u16(masked1);
    let pick0 = used0.count_ones();
    let pick1 = used1.count_ones();

    // XXX: the indices used0 and used1 must be < 256.
    let index_vec0 = _vld1q_u8(&IDX_TABLE[(used0 as u8) as usize]);
    let shifted0 = _vreinterpretq_s16_u8(_vqtbl1q_u8(_vreinterpretq_u8_s16(input.low), index_vec0));
    let index_vec1 = _vld1q_u8(&IDX_TABLE[(used1 as u8) as usize]);
    let shifted1 =
        _vreinterpretq_s16_u8(_vqtbl1q_u8(_vreinterpretq_u8_s16(input.high), index_vec1));

    let idx0 = usize::try_from(pick0).unwrap();
    if pick0 > 8 || pick1 > 8 || idx0 + 8 > out.len() {
        let mut input_low_lanes = [0i16; 8];
        let mut input_high_lanes = [0i16; 8];
        let mut mask0_lanes = [0u16; 8];
        let mut mask1_lanes = [0u16; 8];
        let mut masked0_lanes = [0u16; 8];
        let mut masked1_lanes = [0u16; 8];
        _vst1q_s16(&mut input_low_lanes, input.low);
        _vst1q_s16(&mut input_high_lanes, input.high);
        _vst1q_u16(&mut mask0_lanes, mask0);
        _vst1q_u16(&mut mask1_lanes, mask1);
        _vst1q_u16(&mut masked0_lanes, masked0);
        _vst1q_u16(&mut masked1_lanes, masked1);
        panic!(
            "NEON_REJ_DEBUG used0=0x{:04x} used0_u8=0x{:02x} used1=0x{:04x} used1_u8=0x{:02x} pick0={} pick1={} idx0={} out_len={} a={:?} input_low={:?} input_high={:?} mask0={:?} mask1={:?} masked0={:?} masked1={:?}",
            used0,
            used0 as u8,
            used1,
            used1 as u8,
            pick0,
            pick1,
            idx0,
            out.len(),
            a,
            input_low_lanes,
            input_high_lanes,
            mask0_lanes,
            mask1_lanes,
            masked0_lanes,
            masked1_lanes
        );
    }
    _vst1q_s16(&mut out[0..8], shifted0);
    _vst1q_s16(&mut out[idx0..idx0 + 8], shifted1);
"""
if old not in text:
    raise SystemExit("expected rej_sample block not found")
path.write_text(text.replace(old, new))
