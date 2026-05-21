use std::fmt::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

pub fn pamtester(example: &str, service_lines: &[&str], user: Option<&str>, op: &str) -> Output {
    let module = example_module_path(example);
    let test_dir = tempfile::tempdir().unwrap();
    let user = user.unwrap_or("user");
    let svc = "test";
    let mut contents = String::new();
    for line in service_lines {
        writeln!(contents, "{line} {}", module.display()).unwrap();
    }
    std::fs::write(test_dir.path().join(svc), contents).unwrap();
    Command::new("bwrap")
        .args(["--bind", "/", "/"])
        .args(["--bind", &test_dir.path().to_string_lossy(), "/etc/pam.d"])
        .args(["--dev", "/dev"])
        .args(["pamtester", svc, user, op])
        .output()
        .unwrap()
}

fn example_module_path(name: &str) -> PathBuf {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let release = (!cfg!(debug_assertions)).then_some("--release");
        let status = Command::new(cargo)
            .args(["build", "--examples", "--package", "pam-bindings"])
            .args(release)
            .status()
            .unwrap();
        assert!(status.success());
    });

    std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(|deps| deps.parent())
        .unwrap()
        .join("examples")
        .join(format!("lib{name}.so"))
}
