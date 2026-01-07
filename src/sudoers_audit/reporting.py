import csv
import json
import html
from datetime import datetime
from .auditor import FileAuditResult

class ReportGenerator:
    @staticmethod
    def generate_csv(results: list[FileAuditResult], output_file: str):
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["File", "Line Number", "Line Content", "Issue"])
            
            for result in results:
                if result.error:
                    writer.writerow([result.file_path, "N/A", "N/A", f"ERROR: {result.error}"])
                    continue
                    
                for finding in result.findings:
                    for issue in finding.issues:
                        writer.writerow([
                            result.file_path,
                            finding.line_number,
                            finding.line_content,
                            issue
                        ])

    @staticmethod
    def generate_html(results: list[FileAuditResult], output_file: str):
        date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Sudoers Audit Report</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 2rem; background: #f4f4f9; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                h1 {{ border-bottom: 2px solid #eee; padding-bottom: 0.5rem; }}
                .file-section {{ margin-top: 2rem; border: 1px solid #ddd; border-radius: 4px; overflow: hidden; }}
                .file-header {{ background: #f8f8f8; padding: 0.5rem 1rem; font-weight: bold; border-bottom: 1px solid #ddd; }}
                .finding {{ padding: 1rem; border-bottom: 1px solid #eee; }}
                .finding:last-child {{ border-bottom: none; }}
                .line-info {{ font-family: monospace; background: #f0f0f0; padding: 0.2rem 0.4rem; border-radius: 3px; }}
                .critical {{ color: #d32f2f; font-weight: bold; }}
                .high {{ color: #f57c00; font-weight: bold; }}
                .medium {{ color: #fbc02d; font-weight: bold; }}
                .warning {{ color: #ffa000; font-weight: bold; }}
                .error {{ color: #c62828; padding: 1rem; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Sudoers Audit Report</h1>
                <p>Generated on: {date_str}</p>
        """

        for result in results:
            html_content += f'<div class="file-section"><div class="file-header">{html.escape(result.file_path)}</div>'
            
            if result.error:
                html_content += f'<div class="error">Error: {html.escape(result.error)}</div>'
            elif not result.findings:
                html_content += '<div class="finding" style="color: green;">No issues found.</div>'
            else:
                for finding in result.findings:
                    html_content += '<div class="finding">'
                    html_content += f'<div>Line <span class="line-info">{finding.line_number}</span>: <code>{html.escape(finding.line_content)}</code></div>'
                    html_content += '<ul>'
                    for issue in finding.issues:
                        severity_class = ""
                        if "CRITICAL" in issue:
                            severity_class = "critical"
                        elif "HIGH" in issue:
                            severity_class = "high"
                        elif "MEDIUM" in issue:
                            severity_class = "medium"
                        elif "WARNING" in issue:
                            severity_class = "warning"
                        
                        html_content += f'<li class="{severity_class}">{html.escape(issue)}</li>'
                    html_content += '</ul></div>'
            
            html_content += '</div>'

        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

    @staticmethod
    def generate_sarif(results: list[FileAuditResult], output_file: str):
        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SudoersAudit",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/example/sudoers-audit"
                        }
                    },
                    "results": []
                }
            ]
        }

        for result in results:
            if result.error:
                # SARIF results usually map to rules, but here we just report a tool execution error or similar
                # For simplicity, we skip tool errors in results or add a generic notification
                continue

            for finding in result.findings:
                for issue in finding.issues:
                    level = "warning"
                    if "CRITICAL" in issue or "HIGH" in issue:
                        level = "error"
                    elif "NOTE" in issue:
                        level = "note"
                    
                    # Extract rule ID if possible or make generic
                    rule_id = "SUDO001" 
                    if "ALL" in issue:
                        rule_id = "SUDO001"
                    elif "NOPASSWD" in issue:
                        rule_id = "SUDO002"
                    elif "Wildcard" in issue:
                        rule_id = "SUDO003"
                    elif "GTFOBins" in issue:
                        rule_id = "SUDO004"
                    elif "!requiretty" in issue:
                        rule_id = "SUDO005"
                    elif "Recursive" in issue:
                        rule_id = "SUDO006"

                    sarif_result = {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {
                            "text": issue
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": result.file_path.replace("\\", "/") # SARIF prefers forward slashes
                                    },
                                    "region": {
                                        "startLine": finding.line_number
                                    }
                                }
                            }
                        ]
                    }
                    sarif_log["runs"][0]["results"].append(sarif_result)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif_log, f, indent=2)
