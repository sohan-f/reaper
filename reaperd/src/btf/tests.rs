// Synthetic buffers are tiny; every length fits in the target integer.
#![allow(clippy::cast_possible_truncation)]

use super::*;
use std::collections::HashMap;

struct Builder {
    strings: Vec<u8>,
    names: HashMap<String, u32>,
    types: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        Self {
            strings: vec![0],
            names: HashMap::new(),
            types: Vec::new(),
        }
    }

    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&off) = self.names.get(s) {
            return off;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(s.as_bytes());
        self.strings.push(0);
        self.names.insert(s.to_string(), off);
        off
    }

    fn record(&mut self, name: u32, info: u32, size_or_type: u32) {
        self.types.extend_from_slice(&name.to_le_bytes());
        self.types.extend_from_slice(&info.to_le_bytes());
        self.types.extend_from_slice(&size_or_type.to_le_bytes());
    }

    fn int(&mut self, name: &str, size: u32) -> u32 {
        let name_off = self.intern(name);
        let id = self.next_id();
        // kind INT, vlen 0
        self.record(name_off, 1 << 24, size);
        self.types.extend_from_slice(&0u32.to_le_bytes());
        id
    }

    fn ptr(&mut self, target: u32) -> u32 {
        let id = self.next_id();
        self.record(0, PTR << 24, target);
        id
    }

    fn typedef_(&mut self, name: &str, target: u32) -> u32 {
        let name_off = self.intern(name);
        let id = self.next_id();
        self.record(name_off, TYPEDEF << 24, target);
        id
    }

    fn r#struct(&mut self, name: &str, members: &[(&str, u32, u32)]) -> u32 {
        let name_off = self.intern(name);
        let id = self.next_id();
        let info = (STRUCT << 24) | members.len() as u32;
        self.record(name_off, info, 0);
        for (m_name, m_type, bit_off) in members {
            let m_off = self.intern(m_name);
            self.types.extend_from_slice(&m_off.to_le_bytes());
            self.types.extend_from_slice(&m_type.to_le_bytes());
            self.types.extend_from_slice(&bit_off.to_le_bytes());
        }
        id
    }

    fn next_id(&self) -> u32 {
        let mut count = 0;
        let mut off = 0;
        while off < self.types.len() {
            let info = u32::from_le_bytes(self.types[off + 4..off + 8].try_into().unwrap());
            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let payload = payload_size(kind, vlen).unwrap();
            off += 12 + payload;
            count += 1;
        }
        count + 1
    }

    fn build(self) -> Vec<u8> {
        let type_len = self.types.len() as u32;
        let str_off = type_len;
        let str_len = self.strings.len() as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(1); // version
        out.push(0); // flags
        out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
        out.extend_from_slice(&0u32.to_le_bytes()); // type_off
        out.extend_from_slice(&type_len.to_le_bytes());
        out.extend_from_slice(&str_off.to_le_bytes());
        out.extend_from_slice(&str_len.to_le_bytes());
        out.extend_from_slice(&self.types);
        out.extend_from_slice(&self.strings);
        out
    }
}

fn synthetic() -> Vec<u8> {
    let mut b = Builder::new();
    let pid_t = b.int("pid_t", 4);
    let s16 = b.int("", 2);
    let uid_t = b.int("uid_t", 4);
    let kuid_struct = b.r#struct("kuid_t", &[("val", uid_t, 0)]);
    let kuid_t = b.typedef_("kuid_t", kuid_struct);
    let cred = b.r#struct("cred", &[("uid", kuid_t, 64)]);
    let signal_struct = b.r#struct("signal_struct", &[("oom_score_adj", s16, 32)]);
    let to_signal = b.ptr(signal_struct);
    let to_cred = b.ptr(cred);
    b.r#struct(
        "task_struct",
        &[
            ("tgid", pid_t, 32),
            ("signal", to_signal, 64),
            ("real_cred", to_cred, 128),
        ],
    );
    b.build()
}

#[test]
fn resolves_expected_offsets() {
    let data = synthetic();
    let layout = resolve_layout(&data).expect("synthetic BTF should resolve");
    assert_eq!(layout.tgid, 4);
    assert_eq!(layout.signal, 8);
    assert_eq!(layout.real_cred, 16);
    assert_eq!(layout.cred_uid, 8);
    assert_eq!(layout.sig_oom_adj, 4);
}

#[test]
fn errors_when_member_missing() {
    let mut b = Builder::new();
    let s16 = b.int("", 2);
    let uid_t = b.int("uid_t", 4);
    let kuid_struct = b.r#struct("kuid_t", &[("val", uid_t, 0)]);
    let kuid_t = b.typedef_("kuid_t", kuid_struct);
    let cred = b.r#struct("cred", &[("uid", kuid_t, 64)]);
    let signal_struct = b.r#struct("signal_struct", &[("oom_score_adj", s16, 32)]);
    let to_signal = b.ptr(signal_struct);
    let to_cred = b.ptr(cred);
    b.r#struct(
        "task_struct",
        &[("signal", to_signal, 64), ("real_cred", to_cred, 128)],
    );
    let err = resolve_layout(&b.build()).expect_err("missing tgid must fail");
    assert!(format!("{err:#}").contains("tgid"));
}

#[test]
fn errors_on_truncated_input() {
    let data = synthetic();
    assert!(resolve_layout(&data[..data.len() - 8]).is_err());
}

#[test]
fn errors_on_bad_magic() {
    let mut data = synthetic();
    data[0] = 0xff;
    assert!(resolve_layout(&data).is_err());
}
