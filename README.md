# Cloudtrail_Parser

## Overview

This project was built to ingest CloudTrail logs and generate findings when selected security-relevant events are detected. Two detection rules were implemented and validated.  The structure of the detection algorithm allowed new detectors to be built without modifying the parser logic directly.

## Why I built it

CloudTrail produces a lot of logs for the multitude of events which occur on a regular basis. Due to the volume and density of CloudTrail data, manually reviewing logs can be time-consuming and inefficient for analysts. The parser clears the clutter and allows easy-to-read output for only the events the analyst has chosen to treat as security-relevant.

## Architecture

`cloudtrail_parser.py` contains the logical flow for ingesting and displaying a JSON input file. It handles file validation, parsing, optional event filtering, invocation of the detection engine, and terminal output.

`detections.py` contains the security detection logic. Individual detector functions inspect CloudTrail records and return standardized findings when their conditions match. `detect_security_events` maintains the detector list and evaluates each record against every registered detector.

## CloudTrail data flow

```
cloudtrail_parser.py
        ↓
load + validate JSON
        ↓
apply optional CLI filter
        ↓
filtered_records
        ↓
detect_security_events()
        ↓
detection_functions
    ├── delete_vpc()
    ├── terminate_instances()
    └── future detectors
        ↓
list of standardized findings
        ↓
print_findings()
```

## Detection architecture

Handling in place for empty and malformed data. One detection engine `detect_security_events` runs in the parser. The detection engine maintains a list of registered detector functions and evaluates each record against each detector. As detectors are added, their functions can be registered to the list without modifying the parser logic.

## Current detection rules

### DeleteVpc

Accepts a single CloudTrail record. If the `eventName` does not equal `DeleteVpc` the function returns `None`. If it matches, the detector extracts the affected VPC ID and passes the record to `create_finding`, which returns a standardized security finding.

### TerminateInstances

Accepts a single CloudTrail record. If the `eventName` does not equal `TerminateInstances` the function returns `None`. If it matches, the detector extracts the affected EC2 instance ID or IDs and passes the record to `create_finding`, which returns a standardized security finding.

## Finding structure

All detected events are passed to `create_finding` which standardizes their format. `print_findings` prints the relevant data fields. The finding structure supports multiple affected resources when a single API call impacts more than one resource.  This allows all detection rules to use the same output path while preserving relevant context and supporting multiple affected resources.

## Usage

`python3 cloudtrail_parser.py --file <json-file>`

Optionally an `event-name` can be passed for direct filtering:

`python3 cloudtrail_parser.py --file <json-file> --event-name <event-name>`

## Example command

`python3 cloudtrail_parser.py --file ./samples/delete-vpc.json`

## Example finding output

```bash
Reading CloudTrail log file: ./samples/delete-vpc.json
Parsing CloudTrail log file...
----------------------------------------

Scanned 1 records.

Detected 1 security finding(s).

Detected Security Findings:
----------------------------------------
Finding 1:
Event ID: 33333333-3333-3333-3333-333333333333
Event Name: DeleteVpc
Event Time: 2026-09-23T16:29:41Z
Event Source: ec2.amazonaws.com
Source IP Address: 203.0.113.10
User Identity: arn:aws:sts::111122223333:assumed-role/TerraformExecutionRole/terraform
User Type: AssumedRole
AWS Region: us-west-2
Affected Resources: ['vpc-0123456789abcdef0']
Result: Success
Error Message: None
Rule Name: DeleteVpc
Description: A VPC deletion event was detected. Please verify if this action was intentional and authorized.
```

## Detection validation methodology

To validate design ground truth concepts were applied using my existing Terraform lab documented in my terraform-security-lab repository. I ran a `terraform apply` and noted the time. I then ran a `terraform destroy` and noted the time. Terraform was configured to operate through a known `TerraformExecutionRole`. Because I initiated both the apply and destroy operations, I knew the expected identity, approximate timeframe, affected resources, and reason for the resulting CloudTrail activity. I retrieved the corresponding logs from the S3 bucket configured for the CloudTrail trail and validated the parser's findings matched the known ground truth.

## Security considerations

Real CloudTrail logs are excluded from source control because they can contain account identifiers, ARNs, source IPs, access-key identifiers, session data, and other operational information. Only sanitized sample logs are committed. Local logs, environment files, virtual environments, editor metadata, and generated Python cache files are excluded through `.gitignore`. The repository contains no AWS credentials, session tokens, `tfvars` files, or real CloudTrail telemetry.

## Limitations

- Requires the user to manually download the log files, store them and pass them as an argument.
- Has detector functions developed for only two events.
- Rules detect specific API activity but do not determine whether the activity is malicious, authorized, or expected. That interpretation requires additional context and correlation.

## Future improvements

- Implement additional detection rules.
- Add event correlation and contextual analysis using surrounding CloudTrail activity.
- Introduce severity to each event based on action type and context.
- Add native `.json.gz` decompression support.
- Add direct S3 ingestion using Boto3.