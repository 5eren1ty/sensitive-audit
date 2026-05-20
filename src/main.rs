use anyhow::{bail, Context, Result};
use blake3::Hasher;
use clap::{ArgAction, Parser, Subcommand};
use ignore::WalkBuilder;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: i64 = 2;
const DEFAULT_PARTIAL_BYTES: u64 = 64 * 1024;
const DEFAULT_COMMIT_EVERY: u64 = 1000;
const DEFAULT_PROGRESS_EVERY_SECONDS: u64 = 10;
const READ_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Debug, Parser)]
#[command(name = "sensitive-audit")]
#[command(about = "Audit destination trees for sensitive source content")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Index sensitive source files listed as paths relative to --root.
    IndexSensitive {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        list: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long, default_value_t = DEFAULT_PARTIAL_BYTES)]
        partial_bytes: u64,
        #[arg(long, default_value_t = 0)]
        min_size_bytes: u64,
        #[arg(long, default_value_t = DEFAULT_COMMIT_EVERY)]
        commit_every: u64,
        #[arg(long, default_value_t = DEFAULT_PROGRESS_EVERY_SECONDS)]
        progress_every_seconds: u64,
        #[arg(long = "no-clear-existing", action = ArgAction::SetFalse)]
        clear_existing: bool,
    },
    /// Scan a destination tree for indexed sensitive content.
    ScanDest {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        csv: Option<PathBuf>,
        #[arg(long = "no-cache", action = ArgAction::SetFalse)]
        use_cache: bool,
        #[arg(long, default_value_t = 0)]
        min_size_bytes: u64,
        #[arg(long, default_value_t = DEFAULT_COMMIT_EVERY)]
        commit_every: u64,
        #[arg(long, default_value_t = DEFAULT_PROGRESS_EVERY_SECONDS)]
        progress_every_seconds: u64,
        #[arg(long, default_value_t = 1)]
        threads: usize,
        #[arg(long, default_value_t = false)]
        follow_links: bool,
    },
    /// Print database summary information.
    DbSummary {
        #[arg(long)]
        db: PathBuf,
    },
    /// Remove destination metadata/cache rows not seen in the latest scan run.
    PruneDest {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        root: PathBuf,
    },
}

#[derive(Debug, Clone)]
struct SensitiveRecord {
    source_rel: String,
    size: u64,
    partial_hash: String,
    full_hash: String,
}

#[derive(Debug, Clone)]
struct CandidateRecord {
    source_rel: String,
    full_hash: String,
}

#[derive(Debug, Default, Serialize)]
struct IndexMetrics {
    sensitive_paths_seen: u64,
    files_indexed: u64,
    missing_paths: u64,
    skipped_non_files: u64,
    files_skipped_min_size: u64,
    read_errors: u64,
    bytes_hashed: u64,
    files_per_second: f64,
    elapsed_ms: u128,
}

#[derive(Debug, Default, Serialize)]
struct ScanMetrics {
    files_seen: u64,
    metadata_cached: u64,
    files_skipped_min_size: u64,
    files_skipped_size: u64,
    size_candidates: u64,
    cache_hits: u64,
    partial_hashed: u64,
    full_hashed: u64,
    partial_candidates: u64,
    matches_found: u64,
    read_errors: u64,
    bytes_hashed: u64,
    files_per_second: f64,
    elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
struct MatchReport {
    dest_path: String,
    source_path: String,
    size: u64,
    hash_algorithm: &'static str,
    full_hash: String,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    size: u64,
    mtime_ns: i64,
    partial_hash: String,
    full_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct FileFingerprint {
    size: u64,
    mtime_ns: i64,
    partial_hash: String,
    full_hash: Option<String>,
    bytes_read: u64,
}

#[derive(Debug)]
struct HashJob {
    path: PathBuf,
    dest_rel: String,
    size: u64,
}

#[derive(Debug)]
struct HashOutcome {
    path: PathBuf,
    dest_rel: String,
    size: u64,
    result: std::result::Result<WorkerFingerprint, String>,
}

#[derive(Debug)]
struct WorkerFingerprint {
    fingerprint: FileFingerprint,
    partial_hashed: u64,
    full_hashed: u64,
    bytes_hashed: u64,
}

#[derive(Debug)]
struct SensitiveIndex {
    sizes: HashSet<u64>,
    by_partial: HashMap<(u64, String), Vec<CandidateRecord>>,
    partial_bytes: u64,
    source_root: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::IndexSensitive {
            root,
            list,
            db,
            partial_bytes,
            min_size_bytes,
            commit_every,
            progress_every_seconds,
            clear_existing,
        } => index_sensitive(
            &normalize_arg_path(&root)?,
            &normalize_arg_path(&list)?,
            &normalize_arg_path(&db)?,
            partial_bytes,
            min_size_bytes,
            commit_every,
            progress_every_seconds,
            clear_existing,
        ),
        Command::ScanDest {
            root,
            db,
            report,
            csv,
            use_cache,
            min_size_bytes,
            commit_every,
            progress_every_seconds,
            threads,
            follow_links,
        } => {
            let csv = csv.map(|path| normalize_arg_path(&path)).transpose()?;
            scan_dest(
                &normalize_arg_path(&root)?,
                &normalize_arg_path(&db)?,
                &normalize_arg_path(&report)?,
                csv.as_deref(),
                use_cache,
                min_size_bytes,
                commit_every,
                progress_every_seconds,
                threads,
                follow_links,
            )
        }
        Command::DbSummary { db } => db_summary(&normalize_arg_path(&db)?),
        Command::PruneDest { db, root } => {
            prune_dest(&normalize_arg_path(&db)?, &normalize_arg_path(&root)?)
        }
    }
}

fn index_sensitive(
    root: &Path,
    list: &Path,
    db: &Path,
    partial_bytes: u64,
    min_size_bytes: u64,
    commit_every: u64,
    progress_every_seconds: u64,
    clear_existing: bool,
) -> Result<()> {
    if partial_bytes == 0 {
        bail!("--partial-bytes must be greater than zero");
    }
    if commit_every == 0 {
        bail!("--commit-every must be greater than zero");
    }

    fs::create_dir_all(db.parent().unwrap_or_else(|| Path::new(".")))
        .with_context(|| format!("creating database parent for {}", db.display()))?;
    let mut conn = open_db(db)?;
    init_schema(&conn)?;
    set_meta(&conn, "partial_bytes", &partial_bytes.to_string())?;
    set_meta(&conn, "source_root", &root.display().to_string())?;

    if clear_existing {
        conn.execute("DELETE FROM sensitive_files", [])?;
    }

    let started = Instant::now();
    let mut last_progress = started;
    let input = File::open(list).with_context(|| format!("opening {}", list.display()))?;
    let reader = BufReader::new(input);
    let mut tx = conn.transaction()?;
    let mut pending_writes = 0_u64;
    let mut metrics = IndexMetrics::default();

    for line in reader.lines() {
        let source_rel = line.with_context(|| format!("reading {}", list.display()))?;
        let source_rel = source_rel.trim();
        if source_rel.is_empty() || source_rel.starts_with('#') {
            continue;
        }

        metrics.sensitive_paths_seen += 1;
        if should_report_progress(&mut last_progress, progress_every_seconds) {
            eprintln!(
                "index progress: paths_seen={} files_indexed={} files_per_second={:.2} bytes_hashed={} elapsed_s={:.1}",
                metrics.sensitive_paths_seen,
                metrics.files_indexed,
                rate(metrics.sensitive_paths_seen, started),
                metrics.bytes_hashed,
                elapsed_seconds(started)
            );
        }
        let path = root.join(source_rel);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                metrics.missing_paths += 1;
                eprintln!("skipping missing or unreadable source path: {}", path.display());
                continue;
            }
        };

        if !metadata.is_file() {
            metrics.skipped_non_files += 1;
            continue;
        }

        let size = metadata.len();
        if size < min_size_bytes {
            metrics.files_skipped_min_size += 1;
            continue;
        }
        match hash_file(&path, size, partial_bytes, true) {
            Ok(fingerprint) => {
                let full_hash = fingerprint
                    .full_hash
                    .as_deref()
                    .expect("full hash requested");
                tx.execute(
                    "INSERT INTO sensitive_files (source_rel, size, partial_hash, full_hash, indexed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(source_rel) DO UPDATE SET
                        size = excluded.size,
                        partial_hash = excluded.partial_hash,
                        full_hash = excluded.full_hash,
                        indexed_at = excluded.indexed_at",
                    params![
                        source_rel,
                        size_to_i64(size)?,
                        fingerprint.partial_hash,
                        full_hash,
                        now_string()
                    ],
                )?;
                pending_writes += 1;
                metrics.files_indexed += 1;
                metrics.bytes_hashed += fingerprint.bytes_read;
                if pending_writes >= commit_every {
                    tx.commit()?;
                    tx = conn.transaction()?;
                    pending_writes = 0;
                }
            }
            Err(_) => {
                metrics.read_errors += 1;
                eprintln!("skipping unreadable source file: {}", path.display());
            }
        }
    }

    tx.commit()?;
    metrics.elapsed_ms = started.elapsed().as_millis();
    metrics.files_per_second = rate(metrics.sensitive_paths_seen, started);
    println!("{}", serde_json::to_string_pretty(&metrics)?);
    Ok(())
}

fn scan_dest(
    root: &Path,
    db: &Path,
    report: &Path,
    csv: Option<&Path>,
    use_cache: bool,
    min_size_bytes: u64,
    commit_every: u64,
    progress_every_seconds: u64,
    threads: usize,
    follow_links: bool,
) -> Result<()> {
    if threads == 0 {
        bail!("--threads must be greater than zero");
    }
    if commit_every == 0 {
        bail!("--commit-every must be greater than zero");
    }

    fs::create_dir_all(report.parent().unwrap_or_else(|| Path::new(".")))
        .with_context(|| format!("creating report parent for {}", report.display()))?;
    if let Some(csv) = csv {
        fs::create_dir_all(csv.parent().unwrap_or_else(|| Path::new(".")))
            .with_context(|| format!("creating csv parent for {}", csv.display()))?;
    }

    let mut conn = open_db(db)?;
    init_schema(&conn)?;
    let index = Arc::new(load_sensitive_index(&conn)?);
    if index.sizes.is_empty() {
        bail!("database contains no sensitive file index; run index-sensitive first");
    }

    let root_key = root_key(root);
    let run_id = create_scan_run(&conn, root, report)?;
    let started = Instant::now();
    let mut last_progress = started;
    let report_file = File::create(report).with_context(|| format!("creating {}", report.display()))?;
    let mut report_writer = BufWriter::new(report_file);
    let mut csv_writer = match csv {
        Some(path) => Some(BufWriter::new(
            File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => None,
    };
    if let Some(writer) = csv_writer.as_mut() {
        writeln!(writer, "dest_path,source_path,size,hash_algorithm,full_hash")?;
    }

    let mut tx = conn.transaction()?;
    let mut pending_writes = 0_u64;
    let mut metrics = ScanMetrics::default();
    let worker_pool = if threads > 1 {
        Some(start_hash_workers(threads, Arc::clone(&index)))
    } else {
        None
    };
    let mut outstanding_hash_jobs = 0_u64;
    let mut walker = WalkBuilder::new(root);
    walker.hidden(false).git_ignore(false).git_exclude(false).follow_links(follow_links);

    for entry in walker.build() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                metrics.read_errors += 1;
                eprintln!("skipping unreadable directory entry under {}", root.display());
                continue;
            }
        };

        let file_type = match entry.file_type() {
            Some(file_type) if file_type.is_file() => file_type,
            _ => continue,
        };
        if !file_type.is_file() {
            continue;
        }

        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                metrics.read_errors += 1;
                eprintln!("skipping file with unreadable metadata: {}", path.display());
                continue;
            }
        };
        let size = metadata.len();
        let mtime_ns = metadata_mtime_ns(&metadata);
        let dest_rel = normalize_rel(path, root)?;
        metrics.files_seen += 1;
        if should_report_progress(&mut last_progress, progress_every_seconds) {
            eprintln!(
                "scan progress: files_seen={} files_per_second={:.2} matches_found={} cache_hits={} bytes_hashed={} elapsed_s={:.1}",
                metrics.files_seen,
                rate(metrics.files_seen, started),
                metrics.matches_found,
                metrics.cache_hits,
                metrics.bytes_hashed,
                elapsed_seconds(started)
            );
        }
        upsert_dest_metadata(&tx, &root_key, run_id, &dest_rel, size, mtime_ns)?;
        pending_writes += 1;
        metrics.metadata_cached += 1;
        if pending_writes >= commit_every {
            tx.commit()?;
            tx = conn.transaction()?;
            pending_writes = 0;
        }

        if size < min_size_bytes {
            metrics.files_skipped_min_size += 1;
            continue;
        }

        if !index.sizes.contains(&size) {
            metrics.files_skipped_size += 1;
            continue;
        }
        metrics.size_candidates += 1;

        let cached = if use_cache {
            load_cache_entry(&tx, &root_key, &dest_rel, size, mtime_ns, index.partial_bytes)?
        } else {
            None
        };

        let mut fingerprint = if let Some(cache) = cached {
            metrics.cache_hits += 1;
            FileFingerprint {
                size: cache.size,
                mtime_ns: cache.mtime_ns,
                partial_hash: cache.partial_hash,
                full_hash: cache.full_hash,
                bytes_read: 0,
            }
        } else {
            if let Some((job_tx, outcome_rx, _handles)) = &worker_pool {
                job_tx
                    .send(HashJob {
                        path: path.to_path_buf(),
                        dest_rel,
                        size,
                    })
                    .context("sending hash job to worker")?;
                outstanding_hash_jobs += 1;
                while let Ok(outcome) = outcome_rx.try_recv() {
                    apply_completed_fingerprint(
                        &tx,
                        root,
                        &root_key,
                        run_id,
                        &index,
                        outcome,
                        &mut report_writer,
                        &mut csv_writer,
                        &mut metrics,
                        &mut pending_writes,
                    )?;
                    outstanding_hash_jobs -= 1;
                    if pending_writes >= commit_every {
                        tx.commit()?;
                        tx = conn.transaction()?;
                        pending_writes = 0;
                    }
                }
                continue;
            }

            let partial = match hash_file(path, size, index.partial_bytes, false) {
                Ok(fingerprint) => fingerprint,
                Err(_) => {
                    metrics.read_errors += 1;
                    eprintln!("skipping unreadable destination file: {}", path.display());
                    continue;
                }
            };
            metrics.partial_hashed += 1;
            metrics.bytes_hashed += partial.bytes_read;
            let key = (size, partial.partial_hash.clone());
            if !index.by_partial.contains_key(&key) {
                upsert_cache(&tx, &root_key, &dest_rel, index.partial_bytes, &partial)?;
                pending_writes += 1;
                if pending_writes >= commit_every {
                    tx.commit()?;
                    tx = conn.transaction()?;
                    pending_writes = 0;
                }
                continue;
            }

            if partial.full_hash.is_some() {
                upsert_cache(&tx, &root_key, &dest_rel, index.partial_bytes, &partial)?;
                pending_writes += 1;
                partial
            } else {
                let full = match hash_file(path, size, index.partial_bytes, true) {
                    Ok(fingerprint) => fingerprint,
                    Err(_) => {
                        metrics.read_errors += 1;
                        eprintln!("skipping unreadable destination file: {}", path.display());
                        continue;
                    }
                };
                metrics.full_hashed += 1;
                metrics.bytes_hashed += full.bytes_read;
                upsert_cache(&tx, &root_key, &dest_rel, index.partial_bytes, &full)?;
                pending_writes += 1;
                full
            }
        };

        let key = (size, fingerprint.partial_hash.clone());
        let candidates = match index.by_partial.get(&key) {
            Some(candidates) => {
                metrics.partial_candidates += 1;
                candidates
            }
            None => continue,
        };

        if fingerprint.full_hash.is_none() {
            let full = match hash_file(path, size, index.partial_bytes, true) {
                Ok(fingerprint) => fingerprint,
                Err(_) => {
                    metrics.read_errors += 1;
                    eprintln!("skipping unreadable destination file: {}", path.display());
                    continue;
                }
            };
            metrics.full_hashed += 1;
            metrics.bytes_hashed += full.bytes_read;
            upsert_cache(&tx, &root_key, &dest_rel, index.partial_bytes, &full)?;
            pending_writes += 1;
            fingerprint = full;
        }

        let Some(full_hash) = fingerprint.full_hash.as_deref() else {
            continue;
        };

        for candidate in candidates {
            if candidate.full_hash == full_hash {
                let dest_path = root.join(&dest_rel).display().to_string();
                let source_path = index.source_root.join(&candidate.source_rel).display().to_string();
                let item = MatchReport {
                    dest_path,
                    source_path,
                    size,
                    hash_algorithm: "blake3",
                    full_hash: full_hash.to_string(),
                };
                writeln!(report_writer, "{}", serde_json::to_string(&item)?)?;
                if let Some(writer) = csv_writer.as_mut() {
                    writeln!(
                        writer,
                        "{},{},{},blake3,{}",
                        csv_escape(&item.dest_path),
                        csv_escape(&item.source_path),
                        item.size,
                        item.full_hash
                    )?;
                }
                tx.execute(
                    "INSERT INTO scan_matches (run_id, dest_rel, source_rel, size, full_hash, matched_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        run_id,
                        &dest_rel,
                        &candidate.source_rel,
                        size_to_i64(item.size)?,
                        &item.full_hash,
                        now_string()
                    ],
                )?;
                pending_writes += 1;
                metrics.matches_found += 1;
            }
        }

        if pending_writes >= commit_every {
            tx.commit()?;
            tx = conn.transaction()?;
            pending_writes = 0;
        }
    }

    if let Some((job_tx, outcome_rx, handles)) = worker_pool {
        drop(job_tx);
        while outstanding_hash_jobs > 0 {
            let outcome = outcome_rx
                .recv()
                .context("receiving hash worker result")?;
            apply_completed_fingerprint(
                &tx,
                root,
                &root_key,
                run_id,
                &index,
                outcome,
                &mut report_writer,
                &mut csv_writer,
                &mut metrics,
                &mut pending_writes,
            )?;
            outstanding_hash_jobs -= 1;
            if pending_writes >= commit_every {
                tx.commit()?;
                tx = conn.transaction()?;
                pending_writes = 0;
            }
        }
        for handle in handles {
            handle.join().map_err(|_| anyhow::anyhow!("hash worker panicked"))?;
        }
    }

    report_writer.flush()?;
    if let Some(writer) = csv_writer.as_mut() {
        writer.flush()?;
    }
    metrics.elapsed_ms = started.elapsed().as_millis();
    metrics.files_per_second = rate(metrics.files_seen, started);
    finish_scan_run(&tx, run_id, &metrics)?;
    tx.commit()?;

    println!("{}", serde_json::to_string_pretty(&metrics)?);
    if metrics.matches_found > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn db_summary(db: &Path) -> Result<()> {
    let conn = open_db(db)?;
    init_schema(&conn)?;
    let sensitive_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM sensitive_files", [], |row| row.get(0))?;
    let distinct_sizes: i64 =
        conn.query_row("SELECT COUNT(DISTINCT size) FROM sensitive_files", [], |row| row.get(0))?;
    let cached_dest: i64 =
        conn.query_row("SELECT COUNT(*) FROM dest_cache", [], |row| row.get(0))?;
    let metadata_dest: i64 =
        conn.query_row("SELECT COUNT(*) FROM dest_files", [], |row| row.get(0))?;
    let scan_runs: i64 =
        conn.query_row("SELECT COUNT(*) FROM scan_runs", [], |row| row.get(0))?;
    let partial_bytes = get_meta(&conn, "partial_bytes")?.unwrap_or_else(|| "unknown".to_string());
    let source_root = get_meta(&conn, "source_root")?.unwrap_or_else(|| "unknown".to_string());
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "partial_bytes": partial_bytes,
            "source_root": source_root,
            "sensitive_files": sensitive_count,
            "distinct_sensitive_sizes": distinct_sizes,
            "cached_dest_files": cached_dest,
            "dest_metadata_files": metadata_dest,
            "scan_runs": scan_runs
        }))?
    );
    Ok(())
}

fn prune_dest(db: &Path, root: &Path) -> Result<()> {
    let conn = open_db(db)?;
    init_schema(&conn)?;
    let root = root_key(root);
    let Some(latest_run_id) = conn
        .query_row(
            "SELECT MAX(id) FROM scan_runs WHERE root = ?1 AND finished_at IS NOT NULL",
            params![root],
            |row| row.get::<_, Option<i64>>(0),
        )?
    else {
        bail!("no finished scan runs found for root");
    };

    let stale_metadata = conn.execute(
        "DELETE FROM dest_files WHERE root = ?1 AND last_seen_run_id <> ?2",
        params![root, latest_run_id],
    )?;
    let stale_cache = conn.execute(
        "DELETE FROM dest_cache
         WHERE root = ?1
         AND NOT EXISTS (
            SELECT 1 FROM dest_files
            WHERE dest_files.root = dest_cache.root
            AND dest_files.dest_rel = dest_cache.dest_rel
         )",
        params![root],
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "root": root,
            "latest_run_id": latest_run_id,
            "metadata_rows_pruned": stale_metadata,
            "cache_rows_pruned": stale_cache
        }))?
    );
    Ok(())
}

fn start_hash_workers(
    threads: usize,
    index: Arc<SensitiveIndex>,
) -> (
    crossbeam_channel::Sender<HashJob>,
    crossbeam_channel::Receiver<HashOutcome>,
    Vec<thread::JoinHandle<()>>,
) {
    let capacity = threads.saturating_mul(4).max(1);
    let (job_tx, job_rx) = crossbeam_channel::bounded::<HashJob>(capacity);
    let (outcome_tx, outcome_rx) = crossbeam_channel::unbounded::<HashOutcome>();
    let mut handles = Vec::with_capacity(threads);

    for _ in 0..threads {
        let job_rx = job_rx.clone();
        let outcome_tx = outcome_tx.clone();
        let index = Arc::clone(&index);
        handles.push(thread::spawn(move || {
            while let Ok(job) = job_rx.recv() {
                let result = hash_for_scan_worker(&job, &index).map_err(|err| err.to_string());
                if outcome_tx
                    .send(HashOutcome {
                        path: job.path,
                        dest_rel: job.dest_rel,
                        size: job.size,
                        result,
                    })
                    .is_err()
                {
                    break;
                }
            }
        }));
    }

    (job_tx, outcome_rx, handles)
}

fn hash_for_scan_worker(job: &HashJob, index: &SensitiveIndex) -> Result<WorkerFingerprint> {
    let partial = hash_file(&job.path, job.size, index.partial_bytes, false)?;
    let partial_hashed = 1;
    let mut full_hashed = 0;
    let mut bytes_hashed = partial.bytes_read;
    let key = (job.size, partial.partial_hash.clone());

    let fingerprint = if !index.by_partial.contains_key(&key) || partial.full_hash.is_some() {
        partial
    } else {
        let full = hash_file(&job.path, job.size, index.partial_bytes, true)?;
        full_hashed = 1;
        bytes_hashed += full.bytes_read;
        full
    };

    Ok(WorkerFingerprint {
        fingerprint,
        partial_hashed,
        full_hashed,
        bytes_hashed,
    })
}

fn apply_completed_fingerprint(
    tx: &Connection,
    root: &Path,
    root_key: &str,
    run_id: i64,
    index: &SensitiveIndex,
    outcome: HashOutcome,
    report_writer: &mut BufWriter<File>,
    csv_writer: &mut Option<BufWriter<File>>,
    metrics: &mut ScanMetrics,
    pending_writes: &mut u64,
) -> Result<()> {
    let worker = match outcome.result {
        Ok(worker) => worker,
        Err(err) => {
            metrics.read_errors += 1;
            eprintln!(
                "skipping unreadable destination file: {} ({err})",
                outcome.path.display()
            );
            return Ok(());
        }
    };

    metrics.partial_hashed += worker.partial_hashed;
    metrics.full_hashed += worker.full_hashed;
    metrics.bytes_hashed += worker.bytes_hashed;

    upsert_cache(
        tx,
        root_key,
        &outcome.dest_rel,
        index.partial_bytes,
        &worker.fingerprint,
    )?;
    *pending_writes += 1;

    let key = (outcome.size, worker.fingerprint.partial_hash.clone());
    let Some(candidates) = index.by_partial.get(&key) else {
        return Ok(());
    };
    metrics.partial_candidates += 1;

    let Some(full_hash) = worker.fingerprint.full_hash.as_deref() else {
        return Ok(());
    };

    for candidate in candidates {
        if candidate.full_hash == full_hash {
            let dest_path = root.join(&outcome.dest_rel).display().to_string();
            let source_path = index.source_root.join(&candidate.source_rel).display().to_string();
            let item = MatchReport {
                dest_path,
                source_path,
                size: outcome.size,
                hash_algorithm: "blake3",
                full_hash: full_hash.to_string(),
            };
            writeln!(report_writer, "{}", serde_json::to_string(&item)?)?;
            if let Some(writer) = csv_writer.as_mut() {
                writeln!(
                    writer,
                    "{},{},{},blake3,{}",
                    csv_escape(&item.dest_path),
                    csv_escape(&item.source_path),
                    item.size,
                    item.full_hash
                )?;
            }
            tx.execute(
                "INSERT INTO scan_matches (run_id, dest_rel, source_rel, size, full_hash, matched_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    run_id,
                    &outcome.dest_rel,
                    &candidate.source_rel,
                    size_to_i64(item.size)?,
                    &item.full_hash,
                    now_string()
                ],
            )?;
            *pending_writes += 1;
            metrics.matches_found += 1;
        }
    }

    Ok(())
}

fn open_db(db: &Path) -> Result<Connection> {
    let conn = Connection::open(db).with_context(|| format!("opening {}", db.display()))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sensitive_files (
            id INTEGER PRIMARY KEY,
            source_rel TEXT NOT NULL,
            size INTEGER NOT NULL,
            partial_hash TEXT NOT NULL,
            full_hash TEXT NOT NULL,
            indexed_at TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_sensitive_source_rel ON sensitive_files(source_rel);
        CREATE INDEX IF NOT EXISTS idx_sensitive_size ON sensitive_files(size);
        CREATE INDEX IF NOT EXISTS idx_sensitive_partial ON sensitive_files(size, partial_hash);
        CREATE INDEX IF NOT EXISTS idx_sensitive_full ON sensitive_files(size, full_hash);
        CREATE TABLE IF NOT EXISTS dest_cache (
            root TEXT NOT NULL,
            dest_rel TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            partial_bytes INTEGER NOT NULL DEFAULT 65536,
            partial_hash TEXT NOT NULL,
            full_hash TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(root, dest_rel, partial_bytes)
        );
        CREATE TABLE IF NOT EXISTS dest_files (
            root TEXT NOT NULL,
            dest_rel TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(root, dest_rel)
        );
        CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY,
            root TEXT NOT NULL,
            report TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            metrics_json TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_matches (
            id INTEGER PRIMARY KEY,
            run_id INTEGER NOT NULL,
            dest_rel TEXT NOT NULL,
            source_rel TEXT NOT NULL,
            size INTEGER NOT NULL,
            full_hash TEXT NOT NULL,
            matched_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id)
        );
        ",
    )?;
    migrate_cache_tables(conn)?;
    set_meta(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
    Ok(())
}

fn migrate_cache_tables(conn: &Connection) -> Result<()> {
    if table_exists(conn, "dest_cache")? && !table_has_column(conn, "dest_cache", "root")? {
        conn.execute("DROP TABLE dest_cache", [])?;
    }
    if table_exists(conn, "dest_files")? && !table_has_column(conn, "dest_files", "root")? {
        conn.execute("DROP TABLE dest_files", [])?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS dest_cache (
            root TEXT NOT NULL,
            dest_rel TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            partial_bytes INTEGER NOT NULL,
            partial_hash TEXT NOT NULL,
            full_hash TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(root, dest_rel, partial_bytes)
        );
        CREATE TABLE IF NOT EXISTS dest_files (
            root TEXT NOT NULL,
            dest_rel TEXT NOT NULL,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            last_seen_run_id INTEGER NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(root, dest_rel)
        );
        ",
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        params![table],
        |row| row.get(0),
    )?;
    Ok(exists > 0)
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |row| row.get(0))
        .optional()
        .map_err(Into::into)
}

fn load_sensitive_index(conn: &Connection) -> Result<SensitiveIndex> {
    let partial_bytes = get_meta(conn, "partial_bytes")?
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_PARTIAL_BYTES);
    let source_root = get_meta(conn, "source_root")?
        .map(PathBuf::from)
        .context("database is missing source_root metadata; rerun index-sensitive with this version")?;
    let mut stmt = conn.prepare(
        "SELECT source_rel, size, partial_hash, full_hash
         FROM sensitive_files
         ORDER BY size, partial_hash, full_hash, source_rel",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SensitiveRecord {
            source_rel: row.get(0)?,
            size: i64_to_u64(row.get::<_, i64>(1)?)?,
            partial_hash: row.get(2)?,
            full_hash: row.get(3)?,
        })
    })?;

    let mut sizes = HashSet::new();
    let mut by_partial: HashMap<(u64, String), Vec<CandidateRecord>> = HashMap::new();
    for row in rows {
        let record = row?;
        sizes.insert(record.size);
        by_partial
            .entry((record.size, record.partial_hash))
            .or_default()
            .push(CandidateRecord {
                source_rel: record.source_rel,
                full_hash: record.full_hash,
            });
    }

    Ok(SensitiveIndex {
        sizes,
        by_partial,
        partial_bytes,
        source_root,
    })
}

fn create_scan_run(conn: &Connection, root: &Path, report: &Path) -> Result<i64> {
    conn.execute(
        "INSERT INTO scan_runs (root, report, started_at) VALUES (?1, ?2, ?3)",
        params![root_key(root), report.display().to_string(), now_string()],
    )?;
    Ok(conn.last_insert_rowid())
}

fn finish_scan_run(conn: &Connection, run_id: i64, metrics: &ScanMetrics) -> Result<()> {
    conn.execute(
        "UPDATE scan_runs SET finished_at = ?1, metrics_json = ?2 WHERE id = ?3",
        params![now_string(), serde_json::to_string(metrics)?, run_id],
    )?;
    Ok(())
}

fn load_cache_entry(
    conn: &Connection,
    root: &str,
    dest_rel: &str,
    size: u64,
    mtime_ns: i64,
    partial_bytes: u64,
) -> Result<Option<CacheEntry>> {
    conn.query_row(
        "SELECT size, mtime_ns, partial_hash, full_hash
         FROM dest_cache
         WHERE root = ?1 AND dest_rel = ?2 AND size = ?3 AND mtime_ns = ?4 AND partial_bytes = ?5",
        params![root, dest_rel, size_to_i64(size)?, mtime_ns, size_to_i64(partial_bytes)?],
        |row| {
            Ok(CacheEntry {
                size: i64_to_u64(row.get(0)?)?,
                mtime_ns: row.get(1)?,
                partial_hash: row.get(2)?,
                full_hash: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn upsert_cache(
    conn: &Connection,
    root: &str,
    dest_rel: &str,
    partial_bytes: u64,
    fingerprint: &FileFingerprint,
) -> Result<()> {
    conn.execute(
        "INSERT INTO dest_cache (root, dest_rel, size, mtime_ns, partial_bytes, partial_hash, full_hash, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(root, dest_rel, partial_bytes) DO UPDATE SET
            size = excluded.size,
            mtime_ns = excluded.mtime_ns,
            partial_hash = excluded.partial_hash,
            full_hash = excluded.full_hash,
            updated_at = excluded.updated_at",
        params![
            root,
            dest_rel,
            size_to_i64(fingerprint.size)?,
            fingerprint.mtime_ns,
            size_to_i64(partial_bytes)?,
            fingerprint.partial_hash,
            fingerprint.full_hash,
            now_string()
        ],
    )?;
    Ok(())
}

fn upsert_dest_metadata(
    conn: &Connection,
    root: &str,
    run_id: i64,
    dest_rel: &str,
    size: u64,
    mtime_ns: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO dest_files (root, dest_rel, size, mtime_ns, last_seen_run_id, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(root, dest_rel) DO UPDATE SET
            size = excluded.size,
            mtime_ns = excluded.mtime_ns,
            last_seen_run_id = excluded.last_seen_run_id,
            updated_at = excluded.updated_at",
        params![root, dest_rel, size_to_i64(size)?, mtime_ns, run_id, now_string()],
    )?;
    Ok(())
}

fn hash_file(path: &Path, size: u64, partial_bytes: u64, full: bool) -> Result<FileFingerprint> {
    let metadata = fs::metadata(path).with_context(|| format!("reading metadata {}", path.display()))?;
    let mtime_ns = metadata_mtime_ns(&metadata);
    if full {
        let (partial_hash, full_hash, bytes_read) = hash_full_with_partial(path, partial_bytes)?;
        return Ok(FileFingerprint {
            size,
            mtime_ns,
            partial_hash,
            full_hash: Some(full_hash),
            bytes_read,
        });
    }

    let partial_hash = hash_prefix(path, Some(partial_bytes))?;
    let full_hash = if size <= partial_bytes {
        Some(partial_hash.clone())
    } else {
        None
    };
    Ok(FileFingerprint {
        size,
        mtime_ns,
        partial_hash,
        full_hash,
        bytes_read: partial_bytes.min(size),
    })
}

fn hash_full_with_partial(path: &Path, partial_bytes: u64) -> Result<(String, String, u64)> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut full_hasher = Hasher::new();
    let mut partial_hasher = Hasher::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES];
    let mut bytes_read = 0_u64;
    let mut partial_remaining = partial_bytes;

    loop {
        let bytes = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if bytes == 0 {
            break;
        }

        full_hasher.update(&buffer[..bytes]);
        if partial_remaining > 0 {
            let partial_len = bytes.min(partial_remaining as usize);
            partial_hasher.update(&buffer[..partial_len]);
            partial_remaining -= partial_len as u64;
        }
        bytes_read += bytes as u64;
    }

    Ok((
        partial_hasher.finalize().to_hex().to_string(),
        full_hasher.finalize().to_hex().to_string(),
        bytes_read,
    ))
}

fn hash_prefix(path: &Path, limit: Option<u64>) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Hasher::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES];
    let mut remaining = limit.unwrap_or(u64::MAX);
    loop {
        if remaining == 0 {
            break;
        }
        let read_size = buffer.len().min(remaining as usize);
        let bytes = file
            .read(&mut buffer[..read_size])
            .with_context(|| format!("reading {}", path.display()))?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
        remaining -= bytes as u64;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn normalize_rel(path: &Path, root: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    Ok(rel.to_string_lossy().replace('\\', "/"))
}

fn normalize_arg_path(path: &Path) -> Result<PathBuf> {
    let expanded = expand_tilde(path)?;
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Ok(env::current_dir()
            .context("reading current directory")?
            .join(expanded))
    }
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let raw = path.to_string_lossy();
    let Some(rest) = raw
        .strip_prefix("~/")
        .or_else(|| raw.strip_prefix("~\\"))
        .or_else(|| (raw == "~").then_some(""))
    else {
        return Ok(path.to_path_buf());
    };

    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .context("path uses ~ but HOME/USERPROFILE is not set")?;
    Ok(PathBuf::from(home).join(rest))
}

fn should_report_progress(last_progress: &mut Instant, every_seconds: u64) -> bool {
    if every_seconds == 0 {
        return false;
    }
    let now = Instant::now();
    if now.duration_since(*last_progress).as_secs() >= every_seconds {
        *last_progress = now;
        true
    } else {
        false
    }
}

fn rate(count: u64, started: Instant) -> f64 {
    let elapsed = started.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        0.0
    } else {
        count as f64 / elapsed
    }
}

fn elapsed_seconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64()
}

fn root_key(root: &Path) -> String {
    root.to_string_lossy().replace('\\', "/")
}

fn metadata_mtime_ns(metadata: &fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| {
            let nanos = duration.as_nanos();
            if nanos > i64::MAX as u128 {
                i64::MAX
            } else {
                nanos as i64
            }
        })
        .unwrap_or(0)
}

fn now_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn size_to_i64(size: u64) -> Result<i64> {
    if size > i64::MAX as u64 {
        bail!("file size {size} exceeds SQLite INTEGER range");
    }
    Ok(size as i64)
}

fn i64_to_u64(value: i64) -> rusqlite::Result<u64> {
    if value < 0 {
        return Err(rusqlite::Error::IntegralValueOutOfRange(0, value));
    }
    Ok(value as u64)
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
