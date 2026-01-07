import argparse
import sys
import os
from .auditor import SudoersAuditor, FileAuditResult
from .reporting import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description="Audit sudoers files for security risks."
    )
    parser.add_argument("path", help="Path to the sudoers file or directory to audit")
    parser.add_argument(
        "-f",
        "--format",
        choices=["csv", "html", "sarif"],
        help="Output format for the report",
    )
    parser.add_argument("-o", "--output", help="Output file path for the report")
    args = parser.parse_args()

    auditor = SudoersAuditor()
    target = args.path
    results: list[FileAuditResult] = []

    if not os.path.exists(target):
        print("ERROR: Target path does not exist.")
        sys.exit(1)

    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for file in files:
                results.append(auditor.audit_file(os.path.join(root, file)))
    else:
        results.append(auditor.audit_file(target))

    # Generate Report if requested
    if args.format and args.output:
        try:
            if args.format == "csv":
                ReportGenerator.generate_csv(results, args.output)
            elif args.format == "html":
                ReportGenerator.generate_html(results, args.output)
            elif args.format == "sarif":
                ReportGenerator.generate_sarif(results, args.output)
            print(f"Report generated successfully: {args.output}")
        except Exception as e:
            print(f"ERROR: Failed to generate report: {e}")
            sys.exit(1)

    # Default behavior: Print to stdout if no report requested OR if user wants to see output anyway (maybe? let's stick to simple logic: if report, don't print? Or always print? The original behavior was always print.)
    # The plan said: "If no report format is specified, print to console".
    # Let's enforce: If NO format is specified, print to console.
    elif not args.format:
        for result in results:
            print(f"--- Auditing {result.file_path} ---")
            if result.error:
                print(f"ERROR: {result.error}")
            elif result.findings:
                for finding in result.findings:
                    print(f"Line {finding.line_number}: {finding.line_content}")
                    for issue in finding.issues:
                        print(f"  [!] {issue}")
                    print("")
    else:
        # Format specified but no output file? defaults? Or error? argparse handles required args if I set them, but here they are optional.
        # If format is specified but no output file, maybe print to stdout in that format?
        # For now, let's just warn or require output. The plan impl said "args.format and args.output".
        if args.format and not args.output:
            print("ERROR: --output required when --format is specified.")
            sys.exit(1)


if __name__ == "__main__":
    main()
