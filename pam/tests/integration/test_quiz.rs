use crate::harness::pamtester;

#[test]
fn test_quiz_example_module() {
    let output = pamtester("quiz", &["auth required"], None, "authenticate", b"5\n");

    let expected_stdout = "pamtester: successfully authenticated\n";
    let expected_stderr = "2 + 3 = ";
    let actual_stdout = String::from_utf8_lossy(&output.stdout);
    let actual_stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "stdout: {actual_stdout} stderr: {actual_stderr}"
    );
    assert_eq!(expected_stdout, actual_stdout);
    assert_eq!(expected_stderr, actual_stderr);
}
