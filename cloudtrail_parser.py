import json
import argparse
from detections import detect_security_events

def main():
    parser = argparse.ArgumentParser(
        description="Parse AWS CloudTrail logs and extract relevant information."
    )

    parser.add_argument(
        '--file',
        type=str,
        required=True,
        help="Path to the CloudTrail log file (JSON format)."
    )

    parser.add_argument(
        '--event-name',
        type=str,
        help="Filter events by a specific event name."
    )

    args = parser.parse_args()
    print(f"Reading CloudTrail log file: {args.file}")

    cloudtrail_data = load_validate_file(args.file)
    if cloudtrail_data is None:
        return

    matched_events = 0
    filtered_records = []

    print("Parsing CloudTrail log file...")
    print("-" * 40 + "\n")

    for record in cloudtrail_data['Records']:
        if args.event_name is None or record.get('eventName') == args.event_name:
            matched_events += 1
            filtered_records.append(record)

    if matched_events == 0:
        print("No events matched the specified criteria.")
        return

    findings = detect_security_events(filtered_records)
    print(f"Scanned {matched_events} records.\n")
    print_findings(findings)

def load_validate_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            if not isinstance(data, dict):
                raise ValueError("CloudTrail log file must contain a JSON object.")
            if 'Records' not in data:
                raise ValueError("CloudTrail log file must contain a 'Records' key.")
            if not isinstance(data['Records'], list):
                raise ValueError("The 'Records' key must contain a list of records.")
            if not data['Records']:
                print("The 'Records' list in the CloudTrail log file is empty.")
                return
            return data

    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return None

    except ValueError as e:
        print(f"Value error: {e}")
        return None

def print_findings(findings):
    if not findings:
        print("No security findings detected.")
        return

    print(f"Detected {len(findings)} security finding(s).")
    print("\nDetected Security Findings:")
    print("-" * 40)

    for i, finding in enumerate(findings):
        print(f"Finding {i + 1}:")
        print(f"Event ID: {finding.get('eventID')}")
        print(f"Event Name: {finding.get('eventName')}")
        print(f"Event Time: {finding.get('eventTime')}")
        print(f"Event Source: {finding.get('eventSource')}")
        print(f"Source IP Address: {finding.get('sourceIPAddress')}")
        print(f"User Identity: {finding.get('userIdentity')}")
        print(f"User Type: {finding.get('userType')}")
        print(f"AWS Region: {finding.get('awsRegion')}")
        print(f"Affected Resources: {finding.get('affectedResources')}")
        print(f"Result: {finding.get('result')}")
        print(f"Error Message: {finding.get('errorMessage')}")
        print(f"Rule Name: {finding.get('ruleName')}")
        print(f"Description: {finding.get('description')}")
        print("-" * 40)

if __name__ == "__main__":
    main()