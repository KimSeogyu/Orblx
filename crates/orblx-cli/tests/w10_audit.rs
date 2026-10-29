use std::fs;
use std::process::Command;

#[test]
fn audit_cli_writes_a_chain_and_checks_it() {
    let dir = std::env::temp_dir().join(format!("orblx-w10-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("the temp directory was not created");
    let chain = dir.join("chain.jsonl");
    let bin = env!("CARGO_BIN_EXE_orblx");

    let demo = Command::new(bin)
        .args([
            "audit",
            "demo",
            "--out",
            chain.to_str().expect("the chain path is utf-8"),
        ])
        .output()
        .expect("the demo command did not start");
    assert!(
        demo.status.success(),
        "demo failed: {}",
        String::from_utf8_lossy(&demo.stderr)
    );
    let demo_text = String::from_utf8(demo.stdout).expect("the demo output is utf-8");
    assert!(demo_text.contains("start 1\n"), "{demo_text}");
    assert!(demo_text.contains("end 1\n"), "{demo_text}");
    assert!(demo_text.contains("deny 1\n"), "{demo_text}");
    assert!(demo_text.contains("records 3\n"), "{demo_text}");
    assert!(chain.is_file());

    let verify = Command::new(bin)
        .args([
            "audit",
            "verify",
            "--file",
            chain.to_str().expect("the chain path is utf-8"),
        ])
        .output()
        .expect("the verify command did not start");
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_text = String::from_utf8(verify.stdout).expect("the verify output is utf-8");
    assert!(verify_text.starts_with("ok\n"), "{verify_text}");
    assert!(verify_text.contains("start 1\n"), "{verify_text}");
    assert!(verify_text.contains("end 1\n"), "{verify_text}");
    assert!(verify_text.contains("deny 1\n"), "{verify_text}");
    assert!(verify_text.contains("records 3\n"), "{verify_text}");
    let demo_tip = tip_line(&demo_text);
    let verify_tip = tip_line(&verify_text);
    assert_eq!(demo_tip, verify_tip);

    let text = fs::read_to_string(&chain).expect("the chain file was not read");
    let bad = text.replace(
        "spiffe://orblx.local/agent/worker",
        "spiffe://orblx.local/agent/others",
    );
    assert_ne!(text, bad);
    fs::write(&chain, bad).expect("the chain file was not changed");
    let failed = Command::new(bin)
        .args([
            "audit",
            "verify",
            "--file",
            chain.to_str().expect("the chain path is utf-8"),
        ])
        .output()
        .expect("the verify command did not start");
    assert!(!failed.status.success());
    let err = String::from_utf8_lossy(&failed.stderr);
    assert!(err.contains("hash check"), "{err}");

    fs::remove_dir_all(&dir).expect("the temp directory was not removed");
}

fn tip_line(text: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix("tip "))
        .expect("the output has a tip line")
        .to_string()
}
