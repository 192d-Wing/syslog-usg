//! Benchmarks for output types: signing, file output, buffer output.

use bytes::Bytes;
use compact_str::CompactString;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use syslog_proto::{Facility, Severity, StructuredData, SyslogMessage, SyslogTimestamp};
use syslog_relay::{BufferOutput, FileOutput, ForwardOutput, Output, Pipeline};

fn make_message(i: u64) -> SyslogMessage {
    SyslogMessage {
        facility: Facility::User,
        severity: Severity::Notice,
        version: 1,
        timestamp: SyslogTimestamp::Nil,
        hostname: Some(CompactString::new("benchhost")),
        app_name: Some(CompactString::new("benchapp")),
        proc_id: Some(CompactString::new("1234")),
        msg_id: None,
        structured_data: StructuredData::nil(),
        msg: Some(Bytes::from(format!("benchmark message {i}"))),
        raw: None,
    }
}

// ---------------------------------------------------------------------------
// Signing pipeline benchmark
// ---------------------------------------------------------------------------

fn bench_signing_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("signing_pipeline");
    let batch_size = 1_000u64;
    group.throughput(Throughput::Elements(batch_size));

    group.bench_function("sign_1000_messages", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Generate a fresh key for each iteration
                let (signing_key, _) = match syslog_sign::SigningKey::generate() {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let rsid = syslog_sign::counter::RebootSessionId::unpersisted();
                let signer_config = syslog_sign::SignerConfig::default();
                let signer = syslog_sign::Signer::new(signing_key, rsid, signer_config);

                let template = make_message(0);
                let signing_stage = syslog_relay::SigningStage::new(
                    signer,
                    None,
                    std::time::Duration::from_secs(3600),
                    template,
                );

                let output = ForwardOutput::new("bench");
                let (pipeline, ingress, _shutdown) = Pipeline::with_signing(
                    batch_size as usize + 1024,
                    vec![],
                    vec![output],
                    Some(signing_stage),
                    None,
                );

                let handle = tokio::spawn(async move {
                    let _ = pipeline.run().await;
                });

                for i in 0..batch_size {
                    ingress.send(make_message(i)).await.unwrap();
                }

                drop(ingress);
                let _ = handle.await;
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Buffer output benchmark
// ---------------------------------------------------------------------------

fn bench_buffer_output(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("buffer_output");

    for &batch_size in &[1_000u64, 10_000] {
        group.throughput(Throughput::Elements(batch_size));

        group.bench_function(format!("send_{batch_size}"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let output = BufferOutput::new("bench-buffer", 1000);
                    for i in 0..batch_size {
                        let _ = output.send(make_message(i)).await;
                    }
                });
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// File output benchmark
// ---------------------------------------------------------------------------

fn bench_file_output(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("file_output");
    let batch_size = 1_000u64;
    group.throughput(Throughput::Elements(batch_size));

    group.bench_function("write_1000_messages", |b| {
        b.iter(|| {
            rt.block_on(async {
                let dir = std::env::temp_dir().join("syslog-bench-file");
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join("bench.log");
                let _ = std::fs::remove_file(&path);

                let output = FileOutput::new("bench-file", path.clone());
                for i in 0..batch_size {
                    let _ = output.send(make_message(i)).await;
                }
                let _ = output.flush().await;

                let _ = std::fs::remove_file(&path);
            });
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Serializer throughput (for reference)
// ---------------------------------------------------------------------------

fn bench_serialize_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize_throughput");
    let batch_size = 10_000u64;
    group.throughput(Throughput::Elements(batch_size));

    let messages: Vec<SyslogMessage> = (0..batch_size).map(make_message).collect();

    group.bench_function("serialize_10k", |b| {
        b.iter(|| {
            for msg in &messages {
                let _ = syslog_parse::rfc5424::serializer::serialize(msg);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_signing_pipeline,
    bench_buffer_output,
    bench_file_output,
    bench_serialize_throughput,
);
criterion_main!(benches);
