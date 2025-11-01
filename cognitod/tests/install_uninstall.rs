use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn install_then_uninstall_removes_files() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping install/uninstall test (requires root)");
        return;
    }
    // prepare stub cognitod binary
    let stub_bin_dir = Path::new("../target/release");
    fs::create_dir_all(stub_bin_dir).unwrap();
    let bin_path = stub_bin_dir.join("cognitod");
    {
        let mut f = File::create(&bin_path).unwrap();
        // shell script that handles --detach
        writeln!(
            f,
            "#!/bin/sh\n[ \"$1\" = \"--detach\" ] && exit 0\necho cognitod"
        )
        .unwrap();
    }
    let mut perms = fs::metadata(&bin_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bin_path, perms).unwrap();

    // stub systemctl
    let stub_dir = tempfile::tempdir().unwrap();
    let log_path = stub_dir.path().join("systemctl.log");
    let stub_path = stub_dir.path().join("systemctl");
    {
        let mut f = File::create(&stub_path).unwrap();
        writeln!(f, "#!/bin/sh\necho \"$@\" >> \"{}\"", log_path.display()).unwrap();
    }
    let mut perms = fs::metadata(&stub_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&stub_path, perms).unwrap();

    let path_env = format!(
        "{}:{}",
        stub_dir.path().display(),
        std::env::var("PATH").unwrap()
    );

    // temporary install locations
    let install_root = tempfile::tempdir().unwrap();
    let bin_dir = install_root.path().join("bin");
    let config_dir = install_root.path().join("etc");
    let service_dir = install_root.path().join("systemd");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::create_dir_all(&config_dir).unwrap();
    fs::create_dir_all(&service_dir).unwrap();

    // run install script
    Command::new("scripts/install.sh")
        .current_dir("..")
        .env("PATH", &path_env)
        .env("BIN_DIR", &bin_dir)
        .env("CONFIG_DIR", &config_dir)
        .env("SERVICE_DIR", &service_dir)
        .status()
        .expect("install script");

    assert!(bin_dir.join("cognitod").exists());
    assert!(config_dir.join("linnix.toml").exists());
    assert!(service_dir.join("cognitod.service").exists());

    // run uninstall script
    Command::new("scripts/uninstall.sh")
        .current_dir("..")
        .env("PATH", &path_env)
        .env("BIN_DIR", &bin_dir)
        .env("CONFIG_DIR", &config_dir)
        .env("SERVICE_DIR", &service_dir)
        .status()
        .expect("uninstall script");

    assert!(!bin_dir.join("cognitod").exists());
    assert!(!config_dir.join("linnix.toml").exists());
    assert!(!service_dir.join("cognitod.service").exists());

    let log = fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("disable --now cognitod.service"));
}
