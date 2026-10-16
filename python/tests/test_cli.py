"""Tests for the ``taylor`` command installed by the Python package."""

import pathlib
import shutil
import subprocess
import sys
import sysconfig

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = REPO / "examples" / "input" / "manifests" / "test.json"
GOLDEN = REPO / "tests" / "golden" / "test.hex"


def run_taylor(*args):
    return subprocess.run(
        [sys.executable, "-m", "taylor", *map(str, args)], capture_output=True, text=True
    )


def test_cli_writes_the_golden_envelope(tmp_path):
    """`python -m taylor <json> -o <dir>` writes a CBOR file byte-identical to the Rust golden fixture."""
    result = run_taylor(MANIFEST, "-o", tmp_path)
    assert result.returncode == 0, result.stderr
    expected = bytes.fromhex(GOLDEN.read_text().strip())
    assert (tmp_path / "test.cbor").read_bytes() == expected


def test_cli_usage_error_exits_with_code_2():
    """A usage error, --render-only without --template, exits with code 2 and explains why."""
    result = run_taylor("--render-only")
    assert result.returncode == 2
    assert "--render-only requires --template" in result.stderr


def test_cli_runtime_failure_exits_with_code_1():
    """A runtime failure, a missing input file, exits with code 1 and an error message, never a panic."""
    result = run_taylor("does-not-exist.json")
    assert result.returncode == 1
    assert "error:" in result.stderr
    assert "panicked" not in result.stderr


def test_cli_version_reports_the_package_version():
    """`--version` prints the same version as taylor.__version__."""
    import taylor

    result = run_taylor("--version")
    assert result.returncode == 0
    assert result.stdout.strip() == f"taylor {taylor.__version__}"


def test_run_cli_accepts_path_objects(tmp_path):
    """The in-process CLI accepts ``pathlib.Path`` arguments as well as strings."""
    import taylor

    assert taylor._taylor.run_cli(["taylor", MANIFEST, "-o", tmp_path]) == 0
    assert (tmp_path / "test.cbor").read_bytes() == bytes.fromhex(GOLDEN.read_text().strip())


def test_in_process_usage_error_returns_code_2(capfd):
    """A usage error in the in-process CLI returns code 2 instead of exiting the interpreter."""
    import taylor

    assert taylor._taylor.run_cli(["taylor", "--render-only"]) == 2
    assert "--render-only requires --template" in capfd.readouterr().err


def test_installed_console_script_runs(tmp_path):
    """The installed `taylor` console script runs and writes the golden envelope."""
    script = shutil.which("taylor", path=sysconfig.get_path("scripts"))
    assert script, "the taylor console script is not installed next to this interpreter"
    result = subprocess.run([script, MANIFEST, "-o", tmp_path], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "test.cbor").read_bytes() == bytes.fromhex(GOLDEN.read_text().strip())
