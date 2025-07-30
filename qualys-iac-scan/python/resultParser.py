"""
Parses a JSON scan result file to identify and report failed security controls
and parsing errors in a format suitable for CI/CD systems.
"""
import argparse
import json
import sys
from typing import Any, Dict, Generator, Iterable, Optional

# --- Constants ---

# Prefix for error messages, suitable for systems like GitHub Actions.
ERROR_PREFIX = "::error::"

# Preamble text that precedes the JSON data in the input file.
# This makes the script's assumption clear and easy to modify.
JSON_PREAMBLE = "The scan result is successfully retrieved. JSON output is as follows:"

# Mapping from JSON field names to human-readable names for reporting.
FIELD_MAPPING = {
    "filePath": "File Name",
    "checkId": "Qualys CID",
    "checkName": "Control Name",
    "criticality": "Criticality",
    "remediation": "Remediation",
}

# --- Core Logic ---

def load_scan_data(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Reads a file, strips a known preamble, and parses the remaining content as JSON.

    Args:
        file_path: The path to the input file.

    Returns:
        A dictionary containing the parsed JSON data, or None if an error occurs.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: The file at path '{file_path}' was not found.", file=sys.stderr)
        return None
    except IOError as e:
        print(f"Error: Could not read the file at path '{file_path}': {e}", file=sys.stderr)
        return None

    # Find the position where the JSON data starts. This is brittle but
    # retained from the original script's logic.
    json_start_pos = content.find(JSON_PREAMBLE)
    if json_start_pos != -1:
        json_data_str = content[json_start_pos + len(JSON_PREAMBLE):]
    else:
        # Assume the whole file is JSON if preamble is not found.
        json_data_str = content

    try:
        return json.loads(json_data_str)
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON. The file content may be malformed.", file=sys.stderr)
        # For debugging, you might want to print the problematic string:
        # print(f"--- Data attempted to be parsed ---\n{json_data_str[:500]}...", file=sys.stderr)
        return None


def extract_failures(scan_results: Dict[str, Any]) -> Generator[Dict[str, Any], None, None]:
    """
    Extracts parsing errors and failed checks from the scan results.

    This function acts as a generator, yielding each failure one by one,
    which is memory-efficient for large result sets.

    Args:
        scan_results: The parsed JSON data from the scan.

    Yields:
        A dictionary representing a single failure (either a parsing error or a failed check).
    """
    for result in scan_results.get("result", []):
        if not isinstance(result, dict):
            continue

        if parsing_errors := result.get("results", {}).get("parsingErrors"):
            yield {"type": "parsing_error", "data": parsing_errors}

        if failed_checks := result.get("results", {}).get("failedChecks"):
            for check in failed_checks:
                yield {"type": "failed_check", "data": check}


def report_failures(failures: Iterable[Dict[str, Any]]) -> bool:
    """
    Formats and prints failures to stdout and returns whether any failures were found.

    Args:
        failures: An iterable of failure dictionaries from extract_failures.

    Returns:
        True if at least one failure was reported, False otherwise.
    """
    has_failures = False
    for failure in failures:
        has_failures = True
        if failure["type"] == "parsing_error":
            # Format: ::error::Parsing error file paths=['path1', 'path2']
            print(f"{ERROR_PREFIX}Parsing error file paths={failure['data']}")
        elif failure["type"] == "failed_check":
            check_details = failure["data"]
            # Build the details string using a generator expression and str.join()
            # This is more efficient and readable than string concatenation.
            details_str = ", ".join(
                f"{FIELD_MAPPING.get(key, key)}={check_details.get(key) or 'None'}"
                for key in FIELD_MAPPING
            )
            print(f"{ERROR_PREFIX}{details_str}")

    return has_failures


def main() -> int:
    """
    Main function to orchestrate the script execution.

    1. Parses command-line arguments.
    2. Loads and parses the scan data.
    3. Extracts and reports failures.
    4. Returns an appropriate exit code.

    Returns:
        0 on success (no failures found), 1 on failure (failures found or error).
    """
    parser = argparse.ArgumentParser(description="Parse a scan result file for failures.")
    parser.add_argument("file_path", help="The path to the JSON scan result file.")
    args = parser.parse_args()

    scan_data = load_scan_data(args.file_path)
    if not scan_data:
        return 1

    if scan_data.get("status") != "FINISHED":
        print(f"Error: Scan status was '{scan_data.get('status')}', not 'FINISHED'.", file=sys.stderr)
        return 1

    failure_generator = extract_failures(scan_data)
    any_failures_found = report_failures(failure_generator)

    if any_failures_found:
        print("\nFailures were detected.", file=sys.stderr)
        return 1
    else:
        print("Success: No failed checks or parsing errors found.")
        return 0


if __name__ == '__main__':
    # The main function returns the exit code, which is passed to sys.exit().
    # This is a clean pattern for command-line applications.
    sys.exit(main())

