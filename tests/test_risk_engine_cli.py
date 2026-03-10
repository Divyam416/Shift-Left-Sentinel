import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
RISK_ENGINE_PATH = REPO_ROOT / "scripts" / "risk_engine.py"

spec = importlib.util.spec_from_file_location("risk_engine", RISK_ENGINE_PATH)
risk_engine = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(risk_engine)


def test_cli_requires_single_target_argument(capsys: pytest.CaptureFixture[str]) -> None:
    result = risk_engine.main(["risk_engine.py"])
    out = capsys.readouterr().out

    assert result == 2
    assert "Usage: python scripts/risk_engine.py <target_file_or_directory>" in out


def test_cli_validates_target_exists(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    missing_target = tmp_path / "missing.py"

    result = risk_engine.main(["risk_engine.py", str(missing_target)])
    out = capsys.readouterr().out

    assert result == 2
    assert f"Error: target '{missing_target}' does not exist." in out


def test_cli_runs_internal_semgrep_trivy_then_scores(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("print('hello')\n", encoding="utf-8")

    def fake_semgrep_scan(target_path: Path, output_file: Path) -> bool:
        output_file.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "demo.rule",
                            "path": str(target_path),
                            "extra": {"severity": "ERROR", "message": "demo"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return True

    def fake_trivy_scan(target_path: Path, output_file: Path) -> bool:
        output_file.write_text(
            json.dumps(
                {
                    "Results": [
                        {
                            "Target": str(target_path),
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-0000-0000",
                                    "Severity": "LOW",
                                    "Description": "demo",
                                }
                            ],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return True

    monkeypatch.setattr(risk_engine, "run_semgrep_scan", fake_semgrep_scan)
    monkeypatch.setattr(risk_engine, "run_trivy_scan", fake_trivy_scan)

    result = risk_engine.main(["risk_engine.py", str(target_file)])
    out = capsys.readouterr().out

    assert result == 0
    assert f"Running Semgrep on: {target_file}" in out
    assert f"Running Trivy on: {target_file}" in out
    assert "Successfully loaded 2 issues." in out
    assert "TOTAL RISK SCORE:" in out


def test_cli_gracefully_handles_missing_outputs(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("print('hello')\n", encoding="utf-8")

    monkeypatch.setattr(risk_engine, "run_semgrep_scan", lambda *_: False)
    monkeypatch.setattr(risk_engine, "run_trivy_scan", lambda *_: False)

    result = risk_engine.main(["risk_engine.py", str(target_file)])
    out = capsys.readouterr().out

    assert result == 0
    assert "Skipping Semgrep scan." in out
    assert "Skipping Trivy scan." in out
    assert "Successfully loaded 0 issues." in out
