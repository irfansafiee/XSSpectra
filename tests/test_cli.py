
from unittest.mock import patch
import main


def test_emergency_stop(capsys):
    with patch(
        "sys.argv",
        ["main.py", "--target", "http://127.0.0.1:5000/vulnerable"]
    ), patch(
        "builtins.input", return_value="yes"
    ), patch(
        "main.scan_target", side_effect=KeyboardInterrupt
    ), patch(
        "main.generate_reports"
    ) as mock_reports:

        exit_code = main.main()

    output = capsys.readouterr().out

    assert exit_code == 130
    assert "Emergency stop" in output
    mock_reports.assert_not_called()
