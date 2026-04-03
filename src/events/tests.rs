use super::*;
use crate::perfetto::VecTraceWriter;
use crate::systing_core::types::task_info;
use perfetto_protos::trace_packet::TracePacket;
use rand::rngs::mock::StepRng;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use perfetto_protos::track_event::track_event::Type;

/// Helper to collect packets from SystingProbeRecorder for tests
fn generate_trace(
    recorder: &mut SystingProbeRecorder,
    pid_uuids: &HashMap<i32, u64>,
    thread_uuids: &HashMap<i32, u64>,
    id_counter: &Arc<AtomicUsize>,
) -> Vec<TracePacket> {
    let mut writer = VecTraceWriter::new();
    recorder
        .write_trace(&mut writer, pid_uuids, thread_uuids, id_counter)
        .unwrap();
    writer.packets
}

#[test]
fn test_add_event() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    recorder
        .add_event_from_str("usdt:/path/to/file:provider:name", &mut rng)
        .unwrap();
    assert_eq!(recorder.cookies.len(), 1);
    assert_eq!(recorder.config_events.len(), 1);
    assert_eq!(recorder.instant_events.len(), 1);
}

#[test]
fn test_add_event_invalid() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    assert!(recorder
        .add_event_from_str("invalid:/path/to/file:provider:name", &mut rng)
        .is_err());
}

#[test]
fn test_add_event_json() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": []
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.cookies.len(), 1);
    assert_eq!(recorder.config_events.len(), 1);
}

#[test]
fn test_add_event_json_invalid() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "invalid:/path/to/file:provider:name"
            }
        ],
        "tracks": []
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_duplicate() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": []
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_range() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    }
                ]
            }
        ]
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.start_events.len(), 1);
    assert_eq!(recorder.stop_events.len(), 1);
}

#[test]
fn test_add_event_json_range_invalid() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "invalid_event_name",
                        "end": "event_name"
                    }
                ]
            }
        ]
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_range_duplicate() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name",
                        "end": "event_name"
                    },
                    {
                        "name": "range_name",
                        "start": "event_name",
                        "end": "event_name"
                    }
                ]
            }
        ]
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_instant() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [],
                "instants": [
                  {
                    "event": "event_name"
                  }
                ]
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.instant_events.len(), 1);
}

#[test]
fn test_add_event_json_instant_invalid() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [],
                "instants": [
                  {
                    "event": "invalid_event_name"
                  }
                ]
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_instant_duplicate() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [],
                "instants": [
                  {
                    "event": "event_name"
                  }
                ]
            },
            {
                "track_name": "track_name_2",
                "ranges": [],
                "instants": [
                  {
                    "event": "event_name"
                  }
                ]
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_instant_range() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    }
                ],
                "instants": [
                  {
                    "event": "event_name1"
                  }
                ]
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_instant_range_duplicate() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name3",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    },
                    {
                        "name": "range_name",
                        "start": "event_name2",
                        "end": "event_name3"
                    }
                ],
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_add_event_json_overlapping_events() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name3",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    },
                    {
                        "name": "range_name1",
                        "start": "event_name2",
                        "end": "event_name3"
                    }
                ]
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.start_events.len(), 2);
    assert_eq!(recorder.stop_events.len(), 2);
    assert_eq!(recorder.ranges.len(), 2);
    assert_eq!(recorder.instant_events.len(), 0);
    assert_eq!(recorder.config_events.len(), 3);
    assert_eq!(recorder.cookies.len(), 3);
}

#[test]
fn test_instant_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "instants": [
                  {
                    "event": "event_name"
                  }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].track_descriptor().name(), "track_name");
    assert_eq!(
        packets[1].track_event().name(),
        "usdt:/path/to/file:provider:name"
    );
}

#[test]
fn test_range_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let mut event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    event.cookie = 1;
    event.ts = 2000;
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[0].track_descriptor().name(), "track_name");
    assert_eq!(packets[1].track_event().name(), "range_name");
    assert_eq!(packets[2].track_event().name(), "range_name");
    assert_eq!(packets[1].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[2].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[1].timestamp(), 1000);
    assert_eq!(packets[2].timestamp(), 2000);
    assert_eq!(
        packets[1].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );
    assert_eq!(
        packets[2].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );
}

#[test]
fn test_range_packet_no_end() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 0);
}

#[test]
fn test_range_packet_no_start() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 2000,
        cookie: 1,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 0);
}

#[test]
fn test_range_packet_multiple_ranges() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name3",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    },
                    {
                        "name": "range_name2",
                        "start": "event_name2",
                        "end": "event_name3"
                    }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let mut event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    event.cookie = 1;
    event.ts = 2000;
    recorder.handle_event(event);
    event.cookie = 2;
    event.ts = 3000;
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 5);
    assert_eq!(packets[0].track_descriptor().name(), "track_name");

    assert_eq!(packets[1].track_event().name(), "range_name");
    assert_eq!(packets[1].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[1].timestamp(), 1000);
    assert_eq!(
        packets[1].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[2].track_event().name(), "range_name");
    assert_eq!(packets[2].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[2].timestamp(), 2000);
    assert_eq!(
        packets[2].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[3].track_event().name(), "range_name2");
    assert_eq!(packets[3].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[3].timestamp(), 2000);
    assert_eq!(
        packets[3].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[4].track_event().name(), "range_name2");
    assert_eq!(packets[4].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[4].timestamp(), 3000);
    assert_eq!(
        packets[4].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );
}

#[test]
fn test_range_packet_multiple_ranges_multi_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name1",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name2",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "event_name3",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": [
            {
                "track_name": "track_name",
                "ranges": [
                    {
                        "name": "range_name",
                        "start": "event_name1",
                        "end": "event_name2"
                    },
                    {
                        "name": "range_name2",
                        "start": "event_name2",
                        "end": "event_name3"
                    }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let mut event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    event.cookie = 1;
    event.ts = 2000;
    recorder.handle_event(event);
    event.cookie = 2;
    event.ts = 3000;
    recorder.handle_event(event);
    event.cookie = 0;
    event.ts = 4000;
    recorder.handle_event(event);
    event.cookie = 1;
    event.ts = 5000;
    recorder.handle_event(event);
    event.cookie = 2;
    event.ts = 6000;
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 9);
    assert_eq!(packets[0].track_descriptor().name(), "track_name");

    assert_eq!(packets[1].track_event().name(), "range_name");
    assert_eq!(packets[1].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[1].timestamp(), 1000);
    assert_eq!(
        packets[1].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[2].track_event().name(), "range_name");
    assert_eq!(packets[2].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[2].timestamp(), 2000);
    assert_eq!(
        packets[2].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[3].track_event().name(), "range_name2");
    assert_eq!(packets[3].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[3].timestamp(), 2000);
    assert_eq!(
        packets[3].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[4].track_event().name(), "range_name2");
    assert_eq!(packets[4].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[4].timestamp(), 3000);
    assert_eq!(
        packets[4].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[5].track_event().name(), "range_name");
    assert_eq!(packets[5].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[5].timestamp(), 4000);
    assert_eq!(
        packets[5].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[6].track_event().name(), "range_name");
    assert_eq!(packets[6].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[6].timestamp(), 5000);
    assert_eq!(
        packets[6].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[7].track_event().name(), "range_name2");
    assert_eq!(packets[7].track_event().type_(), Type::TYPE_SLICE_BEGIN);
    assert_eq!(packets[7].timestamp(), 5000);
    assert_eq!(
        packets[7].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );

    assert_eq!(packets[8].track_event().name(), "range_name2");
    assert_eq!(packets[8].track_event().type_(), Type::TYPE_SLICE_END);
    assert_eq!(packets[8].timestamp(), 6000);
    assert_eq!(
        packets[8].track_event().track_uuid(),
        packets[0].track_descriptor().uuid()
    );
}

#[test]
fn test_uretprobe_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uretprobe_event",
                "event": "uretprobe:/path/to/file:symbol"
            }
        ],
        "tracks": [
            {
                "track_name": "uretprobe_track",
                "instants": [
                  {
                    "event": "uretprobe_event"
                  }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].track_descriptor().name(), "uretprobe_track");
    assert_eq!(packets[1].track_event().name(), "uretprobe:symbol");
}

#[test]
fn test_uprobe_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uprobe_event",
                "event": "uprobe:/path/to/file:symbol"
            }
        ],
        "tracks": [
            {
                "track_name": "uprobe_track",
                "instants": [
                  {
                    "event": "uprobe_event"
                  }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].track_descriptor().name(), "uprobe_track");
    assert_eq!(packets[1].track_event().name(), "uprobe:symbol");
}

#[test]
fn test_invalid_event_type() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let result = recorder.add_event_from_str("invalid:/path/to/file:provider:name", &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Invalid event type: invalid"
    );
}

#[test]
fn test_uprobe_variants() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uprobe_event",
                "event": "uprobe:/path/to/file:symbol"
            },
            {
                "name": "uretprobe_event",
                "event": "uretprobe:/path/to/file:symbol"
            },
            {
                "name": "uretprobe_event_plus_offset",
                "event": "uretprobe:/path/to/file:symbol+64"
            },
            {
                "name": "uprobe_event_plus_offset",
                "event": "uprobe:/path/to/file:symbol+64"
            }
        ],
        "tracks": []
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    assert_eq!(recorder.config_events.len(), 4);
    assert!(recorder.config_events.contains_key("uprobe_event"));
    assert!(recorder.config_events.contains_key("uretprobe_event"));
    assert!(recorder
        .config_events
        .contains_key("uretprobe_event_plus_offset"));
    assert!(recorder
        .config_events
        .contains_key("uprobe_event_plus_offset"));
    let event = recorder.config_events.get("uprobe_event").unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "uprobe_event");
    let event = recorder.config_events.get("uretprobe_event").unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "uretprobe_event");
    let event = recorder
        .config_events
        .get("uretprobe_event_plus_offset")
        .unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    let event = recorder
        .config_events
        .get("uprobe_event_plus_offset")
        .unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "uprobe_event_plus_offset");
}

#[test]
fn test_uprobe_variants_from_str() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let result = recorder.add_event_from_str("uprobe:/path/to/file:symbol", &mut rng);
    assert!(result.is_ok());
    let result = recorder.add_event_from_str("uretprobe:/path/to/file:symbol1", &mut rng);
    assert!(result.is_ok());
    let result = recorder.add_event_from_str("uretprobe:/path/to/file:symbol2+64", &mut rng);
    assert!(result.is_ok());
    let result = recorder.add_event_from_str("uprobe:/path/to/file:symbol3+64", &mut rng);
    assert!(result.is_ok());

    assert_eq!(recorder.config_events.len(), 4);
    assert!(recorder.config_events.contains_key("symbol"));
    assert!(recorder.config_events.contains_key("symbol1"));
    assert!(recorder.config_events.contains_key("symbol2"));
    assert!(recorder.config_events.contains_key("symbol3"));
    let event = recorder.config_events.get("symbol").unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "symbol");
    assert_eq!(event.args.len(), 0);
    let event = recorder.config_events.get("symbol1").unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "symbol1");
    assert_eq!(event.args.len(), 0);
    let event = recorder.config_events.get("symbol2").unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "symbol2");
    assert_eq!(event.args.len(), 0);
    let event = recorder.config_events.get("symbol3").unwrap();
    assert!(matches!(event.event, EventProbe::UProbe(_)));
    assert_eq!(event.name, "symbol3");
    assert_eq!(event.args.len(), 0);
}

#[test]
fn test_threshold_trigger() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "start_event",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "stop_event",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "thresholds": [
              {
                "start": "start_event",
                "end": "stop_event",
                "duration_us": 1000
              }
            ]
        }
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    assert_eq!(recorder.start_triggers.len(), 1);
    assert_eq!(recorder.end_triggers.len(), 1);
    assert_eq!(recorder.stop_triggers.len(), 1);
}

#[test]
fn test_threshold_trigger_invalid() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "start_event",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "stop_event",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "thresholds": [
              {
                "start": "invalid_start_event",
                "end": "stop_event",
                "duration_us": 1000
              }
            ]
        }
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_threshold_trigger_invalid_end() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "start_event",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "stop_event",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "thresholds": [
              {
                "start": "start_event",
                "end": "invalid_stop_event",
                "duration_us": 1000
              }
            ]
        }
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
}

#[test]
fn test_instant_trigger() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "instants": [
                {
                    "event": "event_name"
                }
            ]
        }
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    assert_eq!(recorder.instant_triggers.len(), 1);
}

#[test]
fn test_trip_threshold() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "start_event",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "stop_event",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "thresholds": [
              {
                "start": "start_event",
                "end": "stop_event",
                "duration_us": 1000
              }
            ]
        }
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let mut event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ..Default::default()
    };
    let ret = recorder.maybe_trigger(&event);
    assert!(!ret, "Trip threshold should not be triggered yet");
    event.cookie = 1;
    event.ts = 2_000_000;
    let ret = recorder.maybe_trigger(&event);
    assert!(ret, "Trip threshold should be triggered");
}

#[test]
fn test_no_trip_threshold() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "start_event",
                "event": "usdt:/path/to/file:provider:name"
            },
            {
                "name": "stop_event",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "thresholds": [
              {
                "start": "start_event",
                "end": "stop_event",
                "duration_us": 1000
              }
            ]
        }
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let mut event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ..Default::default()
    };
    let ret = recorder.maybe_trigger(&event);
    assert!(!ret, "Trip threshold should not be triggered yet");
    event.cookie = 1;
    event.ts = 500_000; // Less than the threshold of 1000 microseconds
    let ret = recorder.maybe_trigger(&event);
    assert!(!ret, "Trip threshold should not be triggered");
}

#[test]
fn test_trip_instant() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_name",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "stop_triggers": {
            "instants": [
                {
                    "event": "event_name"
                }
            ]
        }
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    let ret = recorder.maybe_trigger(&event);
    assert!(ret, "Instant trigger should be activated");
}

#[test]
fn test_kprobe_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "kprobe_event",
                "event": "kprobe:symbol"
            }
        ],
        "tracks": [
            {
                "track_name": "kprobe_track",
                "instants": [
                  {
                    "event": "kprobe_event"
                  }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].track_descriptor().name(), "kprobe_track");
    assert_eq!(packets[1].track_event().name(), "kprobe:symbol");
}

#[test]
fn test_kretprobe_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "kretprobe_event",
                "event": "kretprobe:symbol"
            }
        ],
        "tracks": [
            {
                "track_name": "kretprobe_track",
                "instants": [
                  {
                    "event": "kretprobe_event"
                  }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].track_descriptor().name(), "kretprobe_track");
    assert_eq!(packets[1].track_event().name(), "kretprobe:symbol");
}

#[test]
fn test_tracepoint_packet() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "tracepoint_event",
                "event": "tracepoint:category:name"
            }
        ],
        "tracks": [
            {
                "track_name": "tracepoint_track",
                "instants": [
                  {
                    "event": "tracepoint_event"
                  }
                ]
            }
        ]
    }
    "#;

    recorder.load_config_from_json(json, &mut rng).unwrap();
    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        ..Default::default()
    };
    recorder.handle_event(event);
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(1234, 1);
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &thread_uuids,
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].track_descriptor().name(), "tracepoint_track");
    assert_eq!(packets[1].track_event().name(), "tracepoint:category:name");
}

#[test]
fn test_event_with_args() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_with_string_arg",
                "event": "usdt:/path/to/file:provider:name",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "string",
                    "arg_name": "filename"
                  }
                ]
            },
            {
                "name": "event_with_long_arg",
                "event": "usdt:/path/to/file:provider:name",
                "args": [
                  {
                    "arg_index": 1,
                    "arg_type": "long",
                    "arg_name": "size"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 2);
    let event = recorder.config_events.get("event_with_string_arg").unwrap();
    assert_eq!(event.name, "event_with_string_arg");
    assert_eq!(event.args.len(), 1);
    assert_eq!(event.args[0].arg_index, 0);
    assert!(matches!(event.args[0].arg_type, EventKeyType::String));
    assert_eq!(event.args[0].arg_name, "filename");
    let event = recorder.config_events.get("event_with_long_arg").unwrap();
    assert_eq!(event.args.len(), 1);
    assert_eq!(event.args[0].arg_index, 1);
    assert!(matches!(event.args[0].arg_type, EventKeyType::Long));
    assert_eq!(event.args[0].arg_name, "size");
}

#[test]
fn test_event_bad_arg_type() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_with_bad_arg",
                "event": "usdt:/path/to/file:provider:name",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "invalid_type",
                    "arg_name": "test"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Invalid arg type: invalid_type"
    );
}

#[test]
fn test_event_with_multiple_args() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_with_multiple_args",
                "event": "usdt:/path/to/file:provider:name",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "string",
                    "arg_name": "filename"
                  },
                  {
                    "arg_index": 1,
                    "arg_type": "long",
                    "arg_name": "size"
                  },
                  {
                    "arg_index": 2,
                    "arg_type": "long",
                    "arg_name": "offset"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 1);
    let event = recorder
        .config_events
        .get("event_with_multiple_args")
        .unwrap();
    assert_eq!(event.args.len(), 3);
    assert_eq!(event.args[0].arg_index, 0);
    assert!(matches!(event.args[0].arg_type, EventKeyType::String));
    assert_eq!(event.args[0].arg_name, "filename");
    assert_eq!(event.args[1].arg_index, 1);
    assert!(matches!(event.args[1].arg_type, EventKeyType::Long));
    assert_eq!(event.args[1].arg_name, "size");
    assert_eq!(event.args[2].arg_index, 2);
    assert!(matches!(event.args[2].arg_type, EventKeyType::Long));
    assert_eq!(event.args[2].arg_name, "offset");
}

#[test]
fn test_event_with_retval() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uretprobe_event",
                "event": "uretprobe:/path/to/file:symbol",
                "args": [
                  {
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            },
            {
                "name": "kretprobe_event",
                "event": "kretprobe:symbol",
                "args": [
                  {
                    "arg_type": "retval",
                    "arg_name": "result"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    let event = recorder.config_events.get("uretprobe_event").unwrap();
    assert_eq!(event.args.len(), 1);
    assert!(matches!(event.args[0].arg_type, EventKeyType::Retval));
    assert_eq!(event.args[0].arg_name, "return_value");
    let event = recorder.config_events.get("kretprobe_event").unwrap();
    assert_eq!(event.args.len(), 1);
    assert!(matches!(event.args[0].arg_type, EventKeyType::Retval));
    assert_eq!(event.args[0].arg_name, "result");
}

#[test]
fn test_event_with_retval_no_arg_index() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uretprobe_event",
                "event": "uretprobe:/path/to/file:symbol",
                "args": [
                  {
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    let event = recorder.config_events.get("uretprobe_event").unwrap();
    assert_eq!(event.args.len(), 1);
    assert!(matches!(event.args[0].arg_type, EventKeyType::Retval));
    assert_eq!(event.args[0].arg_name, "return_value");
    assert_eq!(event.args[0].arg_index, 0);
}

#[test]
fn test_retval_with_nonzero_arg_index_rejected() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uretprobe_event",
                "event": "uretprobe:/path/to/file:symbol",
                "args": [
                  {
                    "arg_index": 1,
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "arg_index must be 0 or omitted for retval type in event: uretprobe_event"
    );
}

#[test]
fn test_retval_invalid_on_uprobe() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "uprobe_event",
                "event": "uprobe:/path/to/file:symbol",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "retval arg type requires uretprobe, not uprobe: uprobe_event"
    );
}

#[test]
fn test_retval_invalid_on_kprobe() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "kprobe_event",
                "event": "kprobe:symbol",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "retval arg type requires kretprobe, not kprobe: kprobe_event"
    );
}

#[test]
fn test_retval_invalid_on_usdt() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "usdt_event",
                "event": "usdt:/path/to/file:provider:name",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "retval arg type is not supported for usdt probes: usdt_event"
    );
}

#[test]
fn test_retval_invalid_on_tracepoint() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "tracepoint_event",
                "event": "tracepoint:category:name",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "retval",
                    "arg_name": "return_value"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "retval arg type is not supported for tracepoint events: tracepoint_event"
    );
}

#[test]
fn test_event_too_many_args() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_with_too_many_args",
                "event": "usdt:/path/to/file:provider:name",
                "args": [
                  {
                    "arg_index": 0,
                    "arg_type": "string",
                    "arg_name": "file"
                  },
                  {
                    "arg_index": 1,
                    "arg_type": "long",
                    "arg_name": "size"
                  },
                  {
                    "arg_index": 2,
                    "arg_type": "string",
                    "arg_name": "extra"
                  },
                  {
                    "arg_index": 3,
                    "arg_type": "long",
                    "arg_name": "fourth"
                  },
                  {
                    "arg_index": 4,
                    "arg_type": "long",
                    "arg_name": "fifth"
                  }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Maximum 4 args allowed per event, got 5 for event: event_with_too_many_args"
    );
}

#[test]
fn test_event_cpu_scope() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_percpu",
                "event": "usdt:/path/to/file:provider:name",
                "scope": "cpu"
            }
        ],
        "tracks": [
            {
                "track_name": "percpu_track",
                "instants": [
                  {
                    "event": "event_percpu"
                  }
                ]
            }
        ]
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 1);
    let event = recorder.config_events.get("event_percpu").unwrap();
    assert_eq!(event.scope, EventScope::Cpu);

    let event = probe_event {
        task: task_info {
            tgidpid: 1234,
            ..Default::default()
        },
        ts: 1000,
        cpu: 1,
        ..Default::default()
    };
    recorder.handle_event(event);
    assert!(recorder.cpu_events.contains_key(&1));
    let packets = generate_trace(
        &mut recorder,
        &HashMap::new(),
        &HashMap::new(),
        &Arc::new(AtomicUsize::new(0)),
    );
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[0].track_descriptor().name(), "percpu_track");
    assert_eq!(packets[1].track_descriptor().name(), "CPU 1");
    assert_eq!(
        packets[0].track_descriptor().uuid(),
        packets[1].track_descriptor().parent_uuid()
    );
    assert_eq!(
        packets[2].track_event().name(),
        "usdt:/path/to/file:provider:name"
    );
    assert_eq!(packets[2].track_event().type_(), Type::TYPE_INSTANT);
    assert_eq!(packets[2].timestamp(), 1000);
    assert_eq!(
        packets[2].track_event().track_uuid(),
        packets[1].track_descriptor().uuid()
    );
}

#[test]
fn test_stack_field_true() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_with_stack",
                "event": "usdt:/path/to/file:provider:name",
                "stack": true
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 1);
    let event = recorder.config_events.get("event_with_stack").unwrap();
    assert!(event.stack);
}

#[test]
fn test_stack_field_false() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_without_stack",
                "event": "usdt:/path/to/file:provider:name",
                "stack": false
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 1);
    let event = recorder.config_events.get("event_without_stack").unwrap();
    assert!(!event.stack);
}

#[test]
fn test_stack_field_default() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_default_stack",
                "event": "usdt:/path/to/file:provider:name"
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 1);
    let event = recorder.config_events.get("event_default_stack").unwrap();
    assert!(!event.stack);
}

#[test]
fn test_stack_field_with_args() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            {
                "name": "event_with_stack_and_args",
                "event": "uprobe:/path/to/file:symbol",
                "stack": true,
                "args": [
                    {
                        "arg_index": 0,
                        "arg_type": "long",
                        "arg_name": "arg1"
                    }
                ]
            }
        ],
        "tracks": []
    }
    "#;

    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_ok());
    assert_eq!(recorder.config_events.len(), 1);
    let event = recorder
        .config_events
        .get("event_with_stack_and_args")
        .unwrap();
    assert!(event.stack);
    assert_eq!(event.args.len(), 1);
}

fn create_test_task_info(tgid: u32, pid: u32) -> task_info {
    task_info {
        tgidpid: ((tgid as u64) << 32) | (pid as u64),
        comm: [0; 16],
    }
}

fn create_syscall_enter_event(tgid: u32, pid: u32, ts: u64, syscall_nr: u64) -> probe_event {
    let mut event = probe_event {
        task: create_test_task_info(tgid, pid),
        ts,
        cookie: SYS_ENTER_COOKIE,
        num_args: 1,
        ..Default::default()
    };
    event.args[0].r#type = crate::systing_core::types::arg_type::ARG_LONG;
    event.args[0].size = 8;
    let bytes = syscall_nr.to_ne_bytes();
    event.args[0].value[..8].copy_from_slice(&bytes);
    event
}

fn create_syscall_exit_event(
    tgid: u32,
    pid: u32,
    ts: u64,
    syscall_nr: u64,
    ret: u64,
) -> probe_event {
    let mut event = probe_event {
        task: create_test_task_info(tgid, pid),
        ts,
        cookie: SYS_ENTER_COOKIE + 1,
        num_args: 2,
        ..Default::default()
    };
    event.args[0].r#type = crate::systing_core::types::arg_type::ARG_LONG;
    event.args[0].size = 8;
    let bytes = syscall_nr.to_ne_bytes();
    event.args[0].value[..8].copy_from_slice(&bytes);
    event.args[1].r#type = crate::systing_core::types::arg_type::ARG_LONG;
    event.args[1].size = 8;
    let ret_bytes = ret.to_ne_bytes();
    event.args[1].value[..8].copy_from_slice(&ret_bytes);
    event
}

#[test]
fn test_syscall_sys_enter() {
    let mut recorder = SystingProbeRecorder::default();
    let event = create_syscall_enter_event(100, 101, 1000, 1);

    recorder.handle_event(event);

    let tgidpid = (100u64 << 32) | 101u64;
    assert_eq!(recorder.pending_syscalls.len(), 1);
    assert!(recorder.pending_syscalls.contains_key(&tgidpid));
    assert_eq!(recorder.pending_syscalls[&tgidpid].len(), 1);
    assert!(recorder.pending_syscalls[&tgidpid].contains_key(&1));
    assert!(recorder.completed_syscalls.is_empty());
}

#[test]
fn test_syscall_sys_exit_without_enter() {
    let mut recorder = SystingProbeRecorder::default();
    let event = create_syscall_exit_event(100, 101, 2000, 1, 42);

    recorder.handle_event(event);

    assert!(recorder.pending_syscalls.is_empty());
    assert!(recorder.completed_syscalls.is_empty());
}

#[test]
fn test_syscall_complete_pair() {
    let mut recorder = SystingProbeRecorder::default();
    let enter = create_syscall_enter_event(100, 101, 1000, 1);
    let exit = create_syscall_exit_event(100, 101, 2000, 1, 42);

    recorder.handle_event(enter);
    recorder.handle_event(exit);

    let tgidpid = (100u64 << 32) | 101u64;
    assert_eq!(recorder.pending_syscalls.len(), 1);
    assert!(recorder.pending_syscalls[&tgidpid].is_empty());
    assert_eq!(recorder.completed_syscalls.len(), 1);
    assert_eq!(recorder.completed_syscalls[&tgidpid].len(), 1);
    assert_eq!(recorder.completed_syscalls[&tgidpid][0], (1000, 2000, 1));
}

#[test]
fn test_syscall_multiple_threads() {
    let mut recorder = SystingProbeRecorder::default();

    let enter1 = create_syscall_enter_event(100, 101, 1000, 1);
    let enter2 = create_syscall_enter_event(200, 201, 1500, 2);
    let exit1 = create_syscall_exit_event(100, 101, 2000, 1, 10);
    let exit2 = create_syscall_exit_event(200, 201, 2500, 2, 20);

    recorder.handle_event(enter1);
    recorder.handle_event(enter2);
    recorder.handle_event(exit1);
    recorder.handle_event(exit2);

    let tgidpid1 = (100u64 << 32) | 101u64;
    let tgidpid2 = (200u64 << 32) | 201u64;
    assert_eq!(recorder.completed_syscalls.len(), 2);
    assert_eq!(recorder.completed_syscalls[&tgidpid1].len(), 1);
    assert_eq!(recorder.completed_syscalls[&tgidpid2].len(), 1);
    assert_eq!(recorder.completed_syscalls[&tgidpid1][0], (1000, 2000, 1));
    assert_eq!(recorder.completed_syscalls[&tgidpid2][0], (1500, 2500, 2));
}

#[test]
fn test_syscall_generate_trace_packets() {
    let mut recorder = SystingProbeRecorder::default();
    let mut thread_uuids = HashMap::new();
    thread_uuids.insert(101, 500);
    let pid_uuids: HashMap<i32, u64> = HashMap::new();
    let id_counter = Arc::new(AtomicUsize::new(1000));

    let enter = create_syscall_enter_event(100, 101, 1000, 1);
    let exit = create_syscall_exit_event(100, 101, 2000, 1, 42);

    recorder.handle_event(enter);
    recorder.handle_event(exit);

    let packets = generate_trace(&mut recorder, &pid_uuids, &thread_uuids, &id_counter);

    let syscall_packets: Vec<_> = packets
        .iter()
        .filter(|p| p.has_track_descriptor() && p.track_descriptor().name() == "Syscalls")
        .collect();
    assert_eq!(syscall_packets.len(), 1);

    let slice_packets: Vec<_> = packets.iter().filter(|p| p.has_track_event()).collect();
    assert!(slice_packets.len() >= 2);

    let interned_packets: Vec<_> = packets
        .iter()
        .filter(|p| p.interned_data.is_some())
        .collect();
    assert_eq!(interned_packets.len(), 1);

    assert!(recorder.completed_syscalls.is_empty());
    assert!(recorder.pending_syscalls.is_empty());
}

#[test]
fn test_syscall_name_interning() {
    let mut recorder = SystingProbeRecorder::default();
    let id_counter = Arc::new(AtomicUsize::new(1000));

    let iid1 = recorder.get_or_create_syscall_name_iid(1, &id_counter);
    let iid2 = recorder.get_or_create_syscall_name_iid(1, &id_counter);
    let iid3 = recorder.get_or_create_syscall_name_iid(2, &id_counter);

    assert_eq!(iid1, iid2);
    assert_ne!(iid1, iid3);
    assert_eq!(recorder.syscall_iids.len(), 2);
}

#[test]
fn test_thread_scope_no_cross_thread_match() {
    // With default Thread scope, start/end on different TGIDPIDs do not match.
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            { "name": "span_start", "event": "usdt:/bin/app:myapp:begin" },
            { "name": "span_end",   "event": "usdt:/bin/app:myapp:end" }
        ],
        "tracks": [{
            "track_name": "spans",
            "ranges": [{ "name": "my_span", "start": "span_start", "end": "span_end" }]
        }]
    }
    "#;
    recorder.load_config_from_json(json, &mut rng).unwrap();
    assert_eq!(
        recorder.config_events.get("span_start").unwrap().scope,
        EventScope::Thread
    );

    let start_cookie = recorder.config_events.get("span_start").unwrap().cookie;
    let end_cookie = recorder.config_events.get("span_end").unwrap().cookie;

    // TGID=100, TID=200 starts; TGID=100, TID=300 ends (same process, different thread)
    let tgidpid_thread1: u64 = (100u64 << 32) | 200;
    let tgidpid_thread2: u64 = (100u64 << 32) | 300;
    recorder.handle_event(probe_event {
        task: task_info {
            tgidpid: tgidpid_thread1,
            ..Default::default()
        },
        ts: 1000,
        cookie: start_cookie,
        ..Default::default()
    });
    recorder.handle_event(probe_event {
        task: task_info {
            tgidpid: tgidpid_thread2,
            ..Default::default()
        },
        ts: 2000,
        cookie: end_cookie,
        ..Default::default()
    });

    // No completed ranges — cross-thread start/end did not match under Thread scope
    assert!(recorder.recorded_ranges.is_empty());
}

#[test]
fn test_process_scope_cross_thread_match() {
    // With Process scope, start/end on different TGIDPIDs within the same process match.
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            { "name": "span_start", "event": "usdt:/bin/app:myapp:begin", "scope": "process" },
            { "name": "span_end",   "event": "usdt:/bin/app:myapp:end",   "scope": "process" }
        ],
        "tracks": [{
            "track_name": "spans",
            "ranges": [{ "name": "my_span", "start": "span_start", "end": "span_end" }]
        }]
    }
    "#;
    recorder.load_config_from_json(json, &mut rng).unwrap();
    assert_eq!(
        recorder.config_events.get("span_start").unwrap().scope,
        EventScope::Process
    );

    let start_cookie = recorder.config_events.get("span_start").unwrap().cookie;
    let end_cookie = recorder.config_events.get("span_end").unwrap().cookie;

    // TGID=100, TID=200 starts; TGID=100, TID=300 ends (same process, different threads)
    let tgidpid_thread1: u64 = (100u64 << 32) | 200;
    let tgidpid_thread2: u64 = (100u64 << 32) | 300;
    recorder.handle_event(probe_event {
        task: task_info {
            tgidpid: tgidpid_thread1,
            ..Default::default()
        },
        ts: 1000,
        cookie: start_cookie,
        ..Default::default()
    });
    recorder.handle_event(probe_event {
        task: task_info {
            tgidpid: tgidpid_thread2,
            ..Default::default()
        },
        ts: 2000,
        cookie: end_cookie,
        ..Default::default()
    });

    // Range matched across threads via TGID key
    assert!(!recorder.recorded_ranges.is_empty());
    let ranges = recorder.recorded_ranges.values().next().unwrap();
    let track_ranges = ranges.values().next().unwrap();
    assert_eq!(track_ranges[0].start, 1000);
    assert_eq!(track_ranges[0].end, 2000);
}

#[test]
fn test_range_mismatched_scope_is_rejected() {
    let mut rng = StepRng::new(0, 1);
    let mut recorder = SystingProbeRecorder::default();
    let json = r#"
    {
        "events": [
            { "name": "span_start", "event": "usdt:/bin/app:myapp:begin", "scope": "process" },
            { "name": "span_end",   "event": "usdt:/bin/app:myapp:end" }
        ],
        "tracks": [{
            "track_name": "spans",
            "ranges": [{ "name": "my_span", "start": "span_start", "end": "span_end" }]
        }]
    }
    "#;
    let result = recorder.load_config_from_json(json, &mut rng);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("scope"));
}
