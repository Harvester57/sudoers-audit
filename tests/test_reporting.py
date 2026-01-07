import pytest
import os
import json
from sudoers_audit.auditor import FileAuditResult, Finding
from sudoers_audit.reporting import ReportGenerator

@pytest.fixture
def sample_results():
    return [
        FileAuditResult(
            file_path="/etc/sudoers",
            findings=[
                Finding(
                    line_number=10,
                    line_content="root ALL=(ALL:ALL) ALL",
                    issues=["CRITICAL: 'ALL' command granted."]
                )
            ]
        ),
        FileAuditResult(
            file_path="/etc/sudoers.d/test",
            error="Permission denied."
        )
    ]

def test_generate_csv(tmp_path, sample_results):
    output_file = tmp_path / "report.csv"
    ReportGenerator.generate_csv(sample_results, str(output_file))
    
    assert output_file.exists()
    content = output_file.read_text(encoding='utf-8')
    assert "File,Line Number,Line Content,Issue" in content
    assert "/etc/sudoers,10,root ALL=(ALL:ALL) ALL,CRITICAL: 'ALL' command granted." in content
    assert "/etc/sudoers.d/test,N/A,N/A,ERROR: Permission denied." in content

def test_generate_html(tmp_path, sample_results):
    output_file = tmp_path / "report.html"
    ReportGenerator.generate_html(sample_results, str(output_file))
    
    assert output_file.exists()
    content = output_file.read_text(encoding='utf-8')
    assert "Sudoers Audit Report" in content
    assert "/etc/sudoers" in content
    assert "root ALL=(ALL:ALL) ALL" in content
    assert "CRITICAL" in content
    assert "Permission denied." in content

def test_generate_sarif(tmp_path, sample_results):
    output_file = tmp_path / "report.sarif"
    ReportGenerator.generate_sarif(sample_results, str(output_file))
    
    assert output_file.exists()
    with open(output_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    results = data["runs"][0]["results"]
    assert len(results) >= 1
    
    found_issue = False
    for res in results:
        if res["message"]["text"] == "CRITICAL: 'ALL' command granted.":
            found_issue = True
            assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "/etc/sudoers"
            assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
            
    assert found_issue
