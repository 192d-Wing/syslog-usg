//! Parse and serializer benchmarks.
//!
//! Targets:
//! - RFC 5424 parse: p99 < 10μs
//! - RFC 3164 parse: best-effort, comparable
//! - Serializer round-trip

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

// ---------------------------------------------------------------------------
// Test messages
// ---------------------------------------------------------------------------

/// Minimal RFC 5424 message (no SD, no MSG).
const RFC5424_MINIMAL: &[u8] = b"<34>1 2023-10-11T22:14:15.003Z - - - - -";

/// Typical RFC 5424 message with hostname, app, and body.
const RFC5424_TYPICAL: &[u8] = b"<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 - An application event log entry";

/// RFC 5424 message with structured data.
const RFC5424_WITH_SD: &[u8] = b"<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] An application event log entry";

/// RFC 5424 message with multiple SD elements.
const RFC5424_MULTI_SD: &[u8] = b"<165>1 2023-10-11T22:14:15.003Z host app 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] BOMAn application event log entry";

/// Legacy RFC 3164 (BSD syslog) message.
const RFC3164_MSG: &[u8] =
    b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";

/// Large RFC 5424 message (~1KB body).
fn large_rfc5424() -> Vec<u8> {
    let header = b"<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [exampleSDID@32473 iut=\"3\"] ";
    let body = "A".repeat(1024);
    let mut msg = Vec::with_capacity(header.len() + body.len());
    msg.extend_from_slice(header);
    msg.extend_from_slice(body.as_bytes());
    msg
}

// ---------------------------------------------------------------------------
// Parse benchmarks
// ---------------------------------------------------------------------------

fn bench_parse_rfc5424(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_rfc5424");

    let cases: &[(&str, &[u8])] = &[
        ("minimal", RFC5424_MINIMAL),
        ("typical", RFC5424_TYPICAL),
        ("with_sd", RFC5424_WITH_SD),
        ("multi_sd", RFC5424_MULTI_SD),
    ];

    for (name, msg) in cases {
        group.throughput(Throughput::Bytes(msg.len() as u64));
        group.bench_with_input(BenchmarkId::new("strict", name), msg, |b, input| {
            b.iter(|| syslog_parse::parse_strict(black_box(input)));
        });
        group.bench_with_input(BenchmarkId::new("auto", name), msg, |b, input| {
            b.iter(|| syslog_parse::parse(black_box(input)));
        });
    }

    let large = large_rfc5424();
    group.throughput(Throughput::Bytes(large.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("strict", "large_1kb"),
        &large,
        |b, input| {
            b.iter(|| syslog_parse::parse_strict(black_box(input)));
        },
    );

    group.finish();
}

fn bench_parse_rfc3164(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_rfc3164");
    group.throughput(Throughput::Bytes(RFC3164_MSG.len() as u64));
    group.bench_function("auto_detect", |b| {
        b.iter(|| syslog_parse::parse(black_box(RFC3164_MSG)));
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Serializer benchmarks
// ---------------------------------------------------------------------------

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    // Parse first to get a SyslogMessage
    let typical = syslog_parse::parse_strict(RFC5424_TYPICAL).expect("parse typical");
    let with_sd = syslog_parse::parse_strict(RFC5424_WITH_SD).expect("parse with_sd");

    group.bench_function("typical", |b| {
        b.iter(|| syslog_parse::rfc5424::serializer::serialize(black_box(&typical)));
    });

    group.bench_function("with_sd", |b| {
        b.iter(|| syslog_parse::rfc5424::serializer::serialize(black_box(&with_sd)));
    });

    // Round-trip: parse → serialize
    group.bench_function("round_trip_typical", |b| {
        b.iter(|| {
            let msg = syslog_parse::parse_strict(black_box(RFC5424_TYPICAL)).unwrap();
            syslog_parse::rfc5424::serializer::serialize(&msg)
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Parse throughput (batch)
// ---------------------------------------------------------------------------

fn bench_parse_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_throughput");

    // Simulate batch of 1000 messages
    let batch_size = 1000u64;
    let messages: Vec<&[u8]> = (0..batch_size).map(|_| RFC5424_WITH_SD).collect();
    let total_bytes: u64 = messages.iter().map(|m| m.len() as u64).sum();

    group.throughput(Throughput::Bytes(total_bytes));
    group.throughput(Throughput::Elements(batch_size));

    group.bench_function("batch_1000", |b| {
        b.iter(|| {
            for msg in &messages {
                let _ = syslog_parse::parse(black_box(msg));
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse_rfc5424,
    bench_parse_rfc3164,
    bench_serialize,
    bench_parse_throughput,
);
criterion_main!(benches);
