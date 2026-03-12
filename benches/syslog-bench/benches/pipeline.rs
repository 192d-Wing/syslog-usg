//! Pipeline throughput benchmarks.
//!
//! Measures end-to-end throughput: message creation → pipeline send → output receive.

use bytes::Bytes;
use compact_str::CompactString;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use syslog_proto::{Facility, Severity, StructuredData, SyslogMessage, SyslogTimestamp};
use syslog_relay::{ForwardOutput, Pipeline};

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

fn bench_pipeline_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("pipeline");

    for &batch_size in &[100u64, 1_000, 10_000] {
        group.throughput(Throughput::Elements(batch_size));

        group.bench_function(format!("send_{batch_size}"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let output = ForwardOutput::new("bench");
                    let (pipeline, ingress, _shutdown) =
                        Pipeline::new(batch_size as usize + 1024, None, vec![output]);

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
    }

    group.finish();
}

fn bench_pipeline_with_filter(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("pipeline_filtered");

    let batch_size = 10_000u64;
    group.throughput(Throughput::Elements(batch_size));

    group.bench_function("severity_filter_10k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let output = ForwardOutput::new("bench");
                let filter = syslog_relay::SeverityFilter::new(Severity::Warning);
                let (pipeline, ingress, _shutdown) =
                    Pipeline::new(batch_size as usize + 1024, Some(filter), vec![output]);

                let handle = tokio::spawn(async move {
                    let _ = pipeline.run().await;
                });

                // Alternate: half pass (Error=3), half filtered (Debug=7)
                for i in 0..batch_size {
                    let severity = if i % 2 == 0 {
                        Severity::Error
                    } else {
                        Severity::Debug
                    };
                    let mut msg = make_message(i);
                    msg.severity = severity;
                    ingress.send(msg).await.unwrap();
                }

                drop(ingress);
                let _ = handle.await;
            });
        });
    });

    group.finish();
}

fn bench_pipeline_fanout(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("pipeline_fanout");

    let batch_size = 1_000u64;
    group.throughput(Throughput::Elements(batch_size));

    for &num_outputs in &[1u32, 2, 4] {
        group.bench_function(format!("outputs_{num_outputs}"), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let outputs: Vec<_> = (0..num_outputs)
                        .map(|i| ForwardOutput::new(format!("out-{i}")))
                        .collect();

                    let (pipeline, ingress, _shutdown) =
                        Pipeline::new(batch_size as usize + 1024, None, outputs);

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
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_pipeline_throughput,
    bench_pipeline_with_filter,
    bench_pipeline_fanout,
);
criterion_main!(benches);
