use crate::harness::pamtester;

#[test]
fn test_trivial_example_module() {
    let output = pamtester("trivial", &["auth required"], None, "authenticate");

    let expected_stdout = "pamtester: successfully authenticated\n";
    let expected_stderr = "";
    let actual_stdout = String::from_utf8_lossy(&output.stdout);
    let actual_stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "stdout: {} stderr: {}",
        actual_stdout,
        actual_stderr
    );
    assert_eq!(expected_stdout, actual_stdout);
    assert_eq!(expected_stderr, actual_stderr);
}
