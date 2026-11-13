//! Minimal reader for `/sys/kernel/btf/vmlinux`.
//!
//! Resolves the member offsets `reaper-ebpf` needs by injecting them into its
//! `.rodata` section before load. aya-obj keeps its member-level APIs private,
//! so the handful of structures this project cares about are parsed directly.
//! Anything unexpected is an error; offsets are never guessed.

use anyhow::{Context, bail, ensure};

/// Byte offsets into `task_struct` and `signal_struct`, resolved from BTF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// `task_struct.tgid`
    pub tgid: u32,
    /// `task_struct.signal`
    pub signal: u32,
    /// `task_struct.real_cred`
    pub real_cred: u32,
    /// Offset of `cred.uid.val`, i.e. `cred->uid.val`.
    pub cred_uid: u32,
    /// `signal_struct.oom_score_adj`
    pub sig_oom_adj: u32,
}

const BTF_MAGIC: u16 = 0xEB9F;
const UNKN: u32 = 0;
const INT: u32 = 1;
const PTR: u32 = 2;
const ARRAY: u32 = 3;
const STRUCT: u32 = 4;
const UNION: u32 = 5;
const ENUM: u32 = 6;
const FWD: u32 = 7;
const TYPEDEF: u32 = 8;
const VOLATILE: u32 = 9;
const CONST: u32 = 10;
const RESTRICT: u32 = 11;
const FUNC: u32 = 12;
const FUNC_PROTO: u32 = 13;
const VAR: u32 = 14;
const DATASEC: u32 = 15;
const FLOAT: u32 = 16;
const DECL_TAG: u32 = 17;
const TYPE_TAG: u32 = 18;
const ENUM64: u32 = 19;
const MAX_RESOLVE_DEPTH: usize = 16;

/// Resolves the kernel struct offsets the eBPF program needs from vmlinux BTF.
///
/// # Errors
///
/// Returns an error if the BTF is malformed, shorter than its declared
/// sections, or missing one of the expected structs, members, or types.
pub fn resolve_layout(data: &[u8]) -> anyhow::Result<Layout> {
    let btf = Btf::parse(data)?;

    let task = btf.find_struct("task_struct")?;
    btf.ensure_int(btf.member_type(task, "tgid")?, 4, "task_struct.tgid")?;
    btf.ensure_kind(btf.member_type(task, "signal")?, PTR, "task_struct.signal")?;
    btf.ensure_kind(
        btf.member_type(task, "real_cred")?,
        PTR,
        "task_struct.real_cred",
    )?;
    let tgid = btf.member_offset(task, "tgid")?;
    let signal = btf.member_offset(task, "signal")?;
    let real_cred = btf.member_offset(task, "real_cred")?;

    let signal_struct = btf.find_struct("signal_struct")?;
    let sig_oom_adj = btf.member_offset(signal_struct, "oom_score_adj")?;
    btf.ensure_int(
        btf.member_type(signal_struct, "oom_score_adj")?,
        2,
        "signal_struct.oom_score_adj",
    )?;

    let cred = btf.find_struct("cred")?;
    let uid_off = btf.member_offset(cred, "uid")?;
    let kuid = btf.resolve_to_aggregate(btf.member_type(cred, "uid")?, "cred.uid")?;
    let val_off = btf.member_offset(kuid, "val")?;
    btf.ensure_int(btf.member_type(kuid, "val")?, 4, "cred.uid.val")?;

    Ok(Layout {
        tgid,
        signal,
        real_cred,
        cred_uid: uid_off + val_off,
        sig_oom_adj,
    })
}

struct Btf<'a> {
    data: &'a [u8],
    strs_base: usize,
    strs_end: usize,
    types: Vec<(u32, usize)>,
}

fn scan_types(
    data: &[u8],
    types_base: usize,
    types_end: usize,
) -> anyhow::Result<Vec<(u32, usize)>> {
    let mut types = Vec::new();
    let mut off = types_base;
    while off < types_end {
        let info = le_u32(data, off + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let record = 12
            + payload_size(kind, vlen)
                .with_context(|| format!("bad BTF kind {kind} at offset {off}"))?;
        let next = off
            .checked_add(record)
            .context("type record offset overflow")?;
        ensure!(
            next <= types_end,
            "type record extends past the type section"
        );
        types.push((info, off));
        off = next;
    }
    Ok(types)
}

impl<'a> Btf<'a> {
    fn parse(data: &'a [u8]) -> anyhow::Result<Self> {
        ensure!(data.len() >= 24, "vmlinux BTF too small for header");
        let magic = le_u16(data, 0)?;
        ensure!(
            magic == BTF_MAGIC,
            "vmlinux BTF has unexpected magic {magic:#06x} (only little endian is supported)"
        );

        let hdr_len = le_u32(data, 4)? as usize;
        let type_off = le_u32(data, 8)? as usize;
        let type_len = le_u32(data, 12)? as usize;
        let str_off = le_u32(data, 16)? as usize;
        let str_len = le_u32(data, 20)? as usize;

        let types_base = hdr_len
            .checked_add(type_off)
            .context("type section offset overflow")?;
        let strs_base = hdr_len
            .checked_add(str_off)
            .context("string section offset overflow")?;
        let types_end = types_base
            .checked_add(type_len)
            .context("type section length overflow")?;
        let strs_end = strs_base
            .checked_add(str_len)
            .context("string section length overflow")?;
        ensure!(
            types_end <= data.len(),
            "vmlinux BTF type section extends past end of data"
        );
        ensure!(
            strs_end <= data.len(),
            "vmlinux BTF string section extends past end of data"
        );
        ensure!(
            hdr_len <= data.len(),
            "vmlinux BTF header extends past end of data"
        );

        let types = scan_types(data, types_base, types_end)?;

        Ok(Self {
            data,
            strs_base,
            strs_end,
            types,
        })
    }

    fn type_info(&self, id: u32) -> anyhow::Result<(usize, u32)> {
        ensure!(id >= 1, "type id 0 is invalid");
        self.types
            .get((id - 1) as usize)
            .map(|&(info, off)| (off, info))
            .with_context(|| format!("type id {id} out of range"))
    }
    fn kind_of(&self, id: u32) -> anyhow::Result<u32> {
        Ok((self.type_info(id)?.1 >> 24) & 0x1f)
    }

    fn string_at(&self, off: u32) -> anyhow::Result<&'a str> {
        let base = self.strs_base;
        let start = base
            .checked_add(off as usize)
            .context("string offset overflow")?;
        ensure!(start < self.strs_end, "string offset {off} out of range");
        let bytes = &self.data[start..self.strs_end];
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .context("unterminated string in vmlinux BTF")?;
        std::str::from_utf8(&bytes[..end]).context("invalid UTF-8 in vmlinux BTF string")
    }

    fn type_name(&self, record_off: usize) -> anyhow::Result<&'a str> {
        self.string_at(le_u32(self.data, record_off)?)
    }

    fn find_struct(&self, name: &str) -> anyhow::Result<u32> {
        for (i, &(info, off)) in self.types.iter().enumerate() {
            let kind = (info >> 24) & 0x1f;
            if kind != STRUCT && kind != UNION {
                continue;
            }
            if self.type_name(off)? == name {
                let id = u32::try_from(i + 1).context("vmlinux BTF has too many types")?;
                return Ok(id);
            }
        }
        bail!("struct {name} not found in vmlinux BTF")
    }

    fn find_member(&self, id: u32, member: &str) -> anyhow::Result<(u32, u32)> {
        let (off, info) = self.type_info(id)?;
        let kind = (info >> 24) & 0x1f;
        ensure!(
            kind == STRUCT || kind == UNION,
            "type id {id} is not a struct or union"
        );
        let vlen = (info & 0xffff) as usize;
        let kflag = info >> 31 == 1;
        for i in 0..vlen {
            let moff = off + 12 + i * 12;
            let name = self.string_at(le_u32(self.data, moff)?)?;
            if name != member {
                continue;
            }
            let raw = le_u32(self.data, moff + 8)?;
            let bit_off = if kflag { raw & 0x00ff_ffff } else { raw };
            ensure!(bit_off % 8 == 0, "member {member} is not byte aligned");
            return Ok((bit_off / 8, le_u32(self.data, moff + 4)?));
        }
        bail!("member {member} not found in struct type id {id}")
    }

    fn member_offset(&self, id: u32, member: &str) -> anyhow::Result<u32> {
        Ok(self.find_member(id, member)?.0)
    }

    fn member_type(&self, id: u32, member: &str) -> anyhow::Result<u32> {
        Ok(self.find_member(id, member)?.1)
    }

    fn resolve_to_aggregate(&self, mut id: u32, what: &str) -> anyhow::Result<u32> {
        for _ in 0..MAX_RESOLVE_DEPTH {
            match self.kind_of(id)? {
                STRUCT | UNION => return Ok(id),
                TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG => {
                    let (off, _) = self.type_info(id)?;
                    id = le_u32(self.data, off + 8)?;
                }
                kind => bail!("{what} resolves to unexpected BTF kind {kind}"),
            }
        }
        bail!("{what} exceeded the type resolution depth limit")
    }

    fn ensure_int(&self, mut id: u32, size: u32, what: &str) -> anyhow::Result<()> {
        for _ in 0..MAX_RESOLVE_DEPTH {
            match self.kind_of(id)? {
                INT => {
                    let (off, _) = self.type_info(id)?;
                    let actual = le_u32(self.data, off + 8)?;
                    ensure!(actual == size, "{what} has size {actual}, expected {size}");
                    return Ok(());
                }
                TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG => {
                    let (off, _) = self.type_info(id)?;
                    id = le_u32(self.data, off + 8)?;
                }
                kind => bail!("{what} resolves to unexpected BTF kind {kind}"),
            }
        }
        bail!("{what} exceeded the type resolution depth limit")
    }

    fn ensure_kind(&self, mut id: u32, expected: u32, what: &str) -> anyhow::Result<()> {
        for _ in 0..MAX_RESOLVE_DEPTH {
            match self.kind_of(id)? {
                kind if kind == expected => return Ok(()),
                TYPEDEF | VOLATILE | CONST | RESTRICT | TYPE_TAG => {
                    let (off, _) = self.type_info(id)?;
                    id = le_u32(self.data, off + 8)?;
                }
                kind => bail!("{what} resolves to unexpected BTF kind {kind}"),
            }
        }
        bail!("{what} exceeded the type resolution depth limit")
    }
}

fn payload_size(kind: u32, vlen: usize) -> anyhow::Result<usize> {
    Ok(match kind {
        UNKN | PTR | FWD | TYPEDEF | VOLATILE | CONST | RESTRICT | FUNC | FLOAT | TYPE_TAG => 0,
        // INT carries an encoding word, VAR a linkage, DECL_TAG a component index.
        INT | VAR | DECL_TAG => 4,
        ARRAY => 12,
        // Member, param, data-sec entry, and Enum64 value records are 12 bytes.
        STRUCT | UNION | DATASEC | ENUM64 => vlen * 12,
        ENUM | FUNC_PROTO => vlen * 8,
        other => bail!("unsupported BTF kind {other}"),
    })
}

fn le_u16(data: &[u8], off: usize) -> anyhow::Result<u16> {
    let bytes: [u8; 2] = data
        .get(off..off + 2)
        .and_then(|b| b.try_into().ok())
        .context("short read in vmlinux BTF")?;
    Ok(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], off: usize) -> anyhow::Result<u32> {
    let bytes: [u8; 4] = data
        .get(off..off + 4)
        .and_then(|b| b.try_into().ok())
        .context("short read in vmlinux BTF")?;
    Ok(u32::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests;
