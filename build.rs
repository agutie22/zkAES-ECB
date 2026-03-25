use std::{env, fs::OpenOptions, io::Write};

fn main() {
    // #region agent log
    let log_path = "/home/alexguti/projects/zkAES/AES_zero_knowledge_proof_circuit/.cursor/debug-40f02e.log";
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path) {
        let pkg = env::var("CARGO_PKG_NAME").unwrap_or_default();
        let features = env::vars()
            .filter_map(|(k, _)| k.strip_prefix("CARGO_FEATURE_").map(|s| s.to_owned()))
            .collect::<Vec<_>>();
        let _ = writeln!(
            f,
            "{{\"sessionId\":\"40f02e\",\"runId\":\"milestone-a\",\"hypothesisId\":\"H_build\",\"location\":\"build.rs:1\",\"message\":\"cargo build script start\",\"data\":{{\"pkg\":\"{}\",\"features\":{:?}}},\"timestamp\":{}}}",
            pkg,
            features,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );
    }
    // #endregion
}

