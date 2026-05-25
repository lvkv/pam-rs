use crate::harness::pamtester;

#[test]
fn test_data_example_module() {
    let output = pamtester("data", &["auth required"], None, "authenticate", &[]);

    let expected_stdout = "pamtester: successfully authenticated\n";
    let expected_stderr = "data: hello\n";
    let actual_stdout = String::from_utf8_lossy(&output.stdout);
    let actual_stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "stdout: {actual_stdout} stderr: {actual_stderr}"
    );
    assert_eq!(expected_stdout, actual_stdout);
    assert_eq!(expected_stderr, actual_stderr);
}
