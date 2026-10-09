//! Go's profile files (`profile.proto`, as `runtime/pprof` writes them,
//! usually gzipped).
//!
//! A pprof file is already symbolized by the program that wrote it: each
//! location carries its function names and lines, inlined calls included.
//! [`decode`] reads any profile type into a [`Profile`] with its names
//! resolved; what a profile becomes is its reader's business (systing-heap
//! makes heap snapshots of heap profiles). [`encode`] writes a [`Profile`]
//! the other way, so what systing reads out of a program's memory can go to
//! any pprof tool (`go tool pprof`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

/// The most a profile may decompress to: real ones are a few megabytes.
const MAX_PROFILE_BYTES: u64 = 512 << 20;

/// The parts of `profile.proto` that are read and written.
mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Profile {
        #[prost(message, repeated, tag = "1")]
        pub sample_type: Vec<ValueType>,
        #[prost(message, repeated, tag = "2")]
        pub sample: Vec<Sample>,
        #[prost(message, repeated, tag = "3")]
        pub mapping: Vec<Mapping>,
        #[prost(message, repeated, tag = "4")]
        pub location: Vec<Location>,
        #[prost(message, repeated, tag = "5")]
        pub function: Vec<Function>,
        #[prost(string, repeated, tag = "6")]
        pub string_table: Vec<String>,
        #[prost(int64, tag = "9")]
        pub time_nanos: i64,
        #[prost(int64, tag = "10")]
        pub duration_nanos: i64,
        #[prost(message, optional, tag = "11")]
        pub period_type: Option<ValueType>,
        #[prost(int64, tag = "12")]
        pub period: i64,
        #[prost(int64, tag = "14")]
        pub default_sample_type: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct ValueType {
        #[prost(int64, tag = "1")]
        pub r#type: i64,
        #[prost(int64, tag = "2")]
        pub unit: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Sample {
        #[prost(uint64, repeated, tag = "1")]
        pub location_id: Vec<u64>,
        #[prost(int64, repeated, tag = "2")]
        pub value: Vec<i64>,
        #[prost(message, repeated, tag = "3")]
        pub label: Vec<Label>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Label {
        #[prost(int64, tag = "1")]
        pub key: i64,
        #[prost(int64, tag = "2")]
        pub str: i64,
        #[prost(int64, tag = "3")]
        pub num: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Mapping {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(uint64, tag = "2")]
        pub memory_start: u64,
        #[prost(uint64, tag = "3")]
        pub memory_limit: u64,
        #[prost(uint64, tag = "4")]
        pub file_offset: u64,
        #[prost(int64, tag = "5")]
        pub filename: i64,
        #[prost(bool, tag = "7")]
        pub has_functions: bool,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Location {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(uint64, tag = "2")]
        pub mapping_id: u64,
        #[prost(uint64, tag = "3")]
        pub address: u64,
        #[prost(message, repeated, tag = "4")]
        pub line: Vec<Line>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Line {
        #[prost(uint64, tag = "1")]
        pub function_id: u64,
        #[prost(int64, tag = "2")]
        pub line: i64,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Function {
        #[prost(uint64, tag = "1")]
        pub id: u64,
        #[prost(int64, tag = "2")]
        pub name: i64,
        #[prost(int64, tag = "4")]
        pub filename: i64,
    }
}

/// One frame of a sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub function: String,
    pub file: String,
    pub line: i64,
    pub address: u64,
    /// The mapped file the address is in, as the profile names it.
    pub module: String,
    /// Inlined into the frame after it: it shares that frame's address.
    pub inlined: bool,
}

#[derive(Debug, Clone)]
pub struct ProfileSample {
    pub values: Vec<i64>,
    /// Leaf (innermost) first, inlined calls expanded.
    pub frames: Vec<Frame>,
    /// String labels (pprof.Do), and numeric ones such as `bytes`.
    pub labels: Vec<(String, String)>,
    pub num_labels: Vec<(String, i64)>,
}

/// A profile, with its string table resolved.
#[derive(Debug, Clone)]
pub struct Profile {
    /// (type, unit) of each value, e.g. ("inuse_space", "bytes").
    pub sample_types: Vec<(String, String)>,
    pub period_type: Option<(String, String)>,
    pub period: i64,
    pub time_nanos: i64,
    pub duration_nanos: i64,
    pub samples: Vec<ProfileSample>,
}

impl Profile {
    /// The index of the value named `name`.
    pub fn value_index(&self, name: &str) -> Option<usize> {
        self.sample_types.iter().position(|(t, _)| t == name)
    }
}

/// Read a profile file, gzipped or not.
pub fn read_file(path: &Path) -> Result<Profile> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    decode(&raw).with_context(|| format!("decoding {}", path.display()))
}

/// Decode a profile from its bytes, gzipped or not.
pub fn decode(raw: &[u8]) -> Result<Profile> {
    let bytes = if raw.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(raw)
            .take(MAX_PROFILE_BYTES + 1)
            .read_to_end(&mut out)
            .context("gunzip")?;
        if out.len() as u64 > MAX_PROFILE_BYTES {
            bail!("decompresses to more than {MAX_PROFILE_BYTES} bytes");
        }
        out
    } else {
        raw.to_vec()
    };
    let p: proto::Profile =
        prost::Message::decode(bytes.as_slice()).context("not a pprof profile")?;
    let s = |i: i64| -> String {
        usize::try_from(i)
            .ok()
            .and_then(|i| p.string_table.get(i))
            .cloned()
            .unwrap_or_default()
    };
    let vt = |v: &proto::ValueType| (s(v.r#type), s(v.unit));
    let functions: HashMap<u64, &proto::Function> = p.function.iter().map(|f| (f.id, f)).collect();
    let mappings: HashMap<u64, &proto::Mapping> = p.mapping.iter().map(|m| (m.id, m)).collect();
    let mut locations: HashMap<u64, Vec<Frame>> = HashMap::new();
    for loc in &p.location {
        let module = mappings
            .get(&loc.mapping_id)
            .map(|m| s(m.filename))
            .unwrap_or_default();
        let module = Path::new(&module)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default()
            .to_string();
        let n = loc.line.len();
        let frames = if n == 0 {
            vec![Frame {
                function: String::new(),
                file: String::new(),
                line: 0,
                address: loc.address,
                module,
                inlined: false,
            }]
        } else {
            // A location's lines run innermost first; all but the last are
            // inlined into it.
            loc.line
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    let f = functions.get(&l.function_id);
                    Frame {
                        function: f.map(|f| s(f.name)).unwrap_or_default(),
                        file: f.map(|f| s(f.filename)).unwrap_or_default(),
                        line: l.line,
                        address: loc.address,
                        module: module.clone(),
                        inlined: i + 1 < n,
                    }
                })
                .collect()
        };
        locations.insert(loc.id, frames);
    }
    let samples = p
        .sample
        .iter()
        .map(|smp| ProfileSample {
            values: smp.value.clone(),
            frames: smp
                .location_id
                .iter()
                .flat_map(|id| locations.get(id).cloned().unwrap_or_default())
                .collect(),
            labels: smp
                .label
                .iter()
                .filter(|l| l.str != 0)
                .map(|l| (s(l.key), s(l.str)))
                .collect(),
            num_labels: smp
                .label
                .iter()
                .filter(|l| l.str == 0)
                .map(|l| (s(l.key), l.num))
                .collect(),
        })
        .collect();
    Ok(Profile {
        sample_types: p.sample_type.iter().map(vt).collect(),
        period_type: p.period_type.as_ref().map(vt),
        period: p.period,
        time_nanos: p.time_nanos,
        duration_nanos: p.duration_nanos,
        samples,
    })
}

/// Write `profile` as a gzipped pprof file. Frames are named as they are: a
/// location per distinct (module, address, function), a function per name,
/// a mapping per module, each flagged as symbolized so that a pprof tool
/// does not look for symbols of its own. `default_sample_type` names the
/// value a viewer shows first.
pub fn encode(profile: &Profile, default_sample_type: Option<&str>) -> Result<Vec<u8>> {
    let mut strings = Strings::default();
    let vt = |s: &mut Strings, (t, u): &(String, String)| proto::ValueType {
        r#type: s.id(t),
        unit: s.id(u),
    };
    let mut out = proto::Profile {
        sample_type: profile
            .sample_types
            .iter()
            .map(|t| vt(&mut strings, t))
            .collect(),
        period_type: profile.period_type.as_ref().map(|t| vt(&mut strings, t)),
        period: profile.period,
        time_nanos: profile.time_nanos,
        duration_nanos: profile.duration_nanos,
        default_sample_type: default_sample_type.map_or(0, |t| strings.id(t)),
        ..Default::default()
    };
    let mut mappings: HashMap<&str, u64> = HashMap::new();
    let mut functions: HashMap<&str, u64> = HashMap::new();
    let mut locations: HashMap<(&str, u64, &str), u64> = HashMap::new();
    for smp in &profile.samples {
        let mut location_id = Vec::with_capacity(smp.frames.len());
        for f in &smp.frames {
            let key = (f.module.as_str(), f.address, f.function.as_str());
            let id = match locations.get(&key) {
                Some(&id) => id,
                None => {
                    let mapping_id = *mappings.entry(&f.module).or_insert_with(|| {
                        let id = out.mapping.len() as u64 + 1;
                        out.mapping.push(proto::Mapping {
                            id,
                            filename: strings.id(&f.module),
                            has_functions: true,
                            ..Default::default()
                        });
                        id
                    });
                    let function_id = *functions.entry(&f.function).or_insert_with(|| {
                        let id = out.function.len() as u64 + 1;
                        out.function.push(proto::Function {
                            id,
                            name: strings.id(&f.function),
                            filename: strings.id(&f.file),
                        });
                        id
                    });
                    let id = out.location.len() as u64 + 1;
                    out.location.push(proto::Location {
                        id,
                        mapping_id,
                        address: f.address,
                        line: vec![proto::Line {
                            function_id,
                            line: f.line,
                        }],
                    });
                    locations.insert(key, id);
                    id
                }
            };
            location_id.push(id);
        }
        let mut label: Vec<proto::Label> = smp
            .labels
            .iter()
            .map(|(k, v)| proto::Label {
                key: strings.id(k),
                str: strings.id(v),
                num: 0,
            })
            .collect();
        label.extend(smp.num_labels.iter().map(|(k, n)| proto::Label {
            key: strings.id(k),
            str: 0,
            num: *n,
        }));
        out.sample.push(proto::Sample {
            location_id,
            value: smp.values.clone(),
            label,
        });
    }
    out.string_table = strings.table;
    let raw = prost::Message::encode_to_vec(&out);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&raw).context("gzip")?;
    gz.finish().context("gzip")
}

/// A profile's string table: index 0 is the empty string.
struct Strings {
    table: Vec<String>,
    index: HashMap<String, i64>,
}

impl Default for Strings {
    fn default() -> Self {
        Strings {
            table: vec![String::new()],
            index: HashMap::from([(String::new(), 0)]),
        }
    }
}

impl Strings {
    fn id(&mut self, s: &str) -> i64 {
        if let Some(&id) = self.index.get(s) {
            return id;
        }
        let id = self.table.len() as i64;
        self.table.push(s.to_string());
        self.index.insert(s.to_string(), id);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(function: &str, address: u64) -> Frame {
        Frame {
            function: function.to_string(),
            file: String::new(),
            line: 0,
            address,
            module: "prog".to_string(),
            inlined: false,
        }
    }

    #[test]
    fn what_is_encoded_decodes_the_same() {
        let profile = Profile {
            sample_types: vec![
                ("contentions".into(), "count".into()),
                ("delay".into(), "nanoseconds".into()),
            ],
            period_type: Some(("contentions".into(), "count".into())),
            period: 1,
            time_nanos: 1_700_000_000_000_000_000,
            duration_nanos: 0,
            samples: vec![
                ProfileSample {
                    values: vec![3, 4500],
                    frames: vec![frame("main.lock", 0x401010), frame("main.main", 0x401200)],
                    labels: vec![("state".into(), "semacquire".into())],
                    num_labels: vec![],
                },
                ProfileSample {
                    values: vec![1, 10],
                    frames: vec![frame("main.main", 0x401200)],
                    labels: vec![],
                    num_labels: vec![("bytes".into(), 64)],
                },
            ],
        };
        let back = decode(&encode(&profile, Some("delay")).unwrap()).unwrap();
        assert_eq!(back.sample_types, profile.sample_types);
        assert_eq!(back.period_type, profile.period_type);
        assert_eq!(back.time_nanos, profile.time_nanos);
        assert_eq!(back.samples.len(), 2);
        for (a, b) in back.samples.iter().zip(&profile.samples) {
            assert_eq!(a.values, b.values);
            assert_eq!(a.frames, b.frames);
            assert_eq!(a.labels, b.labels);
            assert_eq!(a.num_labels, b.num_labels);
        }
    }
}
