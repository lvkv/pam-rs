use crate::harness::pamtester;

#[test]
fn test_username_example_module() {
    let test_username = "testuser";
    let output = pamtester(
        "username",
        &["session required"],
        Some(test_username),
        "open_session",
    );

    let expected_stdout = "pamtester: successfully opened a session\n";
    let expected_stderr = format!("username: {}\n", test_username);
    let actual_stdout = String::from_utf8_lossy(&output.stdout);
    let actual_stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        actual_stdout,
        actual_stderr
    );
    assert_eq!(expected_stdout, String::from_utf8_lossy(&output.stdout));
    assert_eq!(expected_stderr, String::from_utf8_lossy(&output.stderr));
}
