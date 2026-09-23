def create_finding(record, rule_name, description, affected_resources):
    """
    Create a standardised format finding dictionary based on the provided record and rule information.
    """
    finding = {}
    user_identity = record.get('userIdentity') or {}
    identity = user_identity.get('userName')
    if identity is None:
        identity = user_identity.get('arn')

    finding['eventID'] = record.get('eventID')
    finding['eventName'] = record.get('eventName')
    finding['eventTime'] = record.get('eventTime')
    finding['eventSource'] = record.get('eventSource')
    finding['sourceIPAddress'] = record.get('sourceIPAddress')
    finding['userIdentity'] = identity
    finding['userType'] = user_identity.get('type')
    finding['awsRegion'] = record.get('awsRegion')
    finding['affectedResources'] = affected_resources
    finding['result'] = record.get('errorCode') or 'Success'
    finding['errorMessage'] = record.get('errorMessage')
    finding['ruleName'] = rule_name
    finding['description'] = description
    return finding

def delete_vpc(record):
    """
    Handle the DeleteVpc event detection.
    """

    if record.get('eventName') != 'DeleteVpc':
        return

    affected_resources = []
    request_parameters = record.get('requestParameters') or {}
    vpc_id = request_parameters.get('vpcId')

    if vpc_id is not None:
        affected_resources.append(vpc_id)

    return create_finding(
        record,
        "DeleteVpc",
        "A VPC deletion event was detected. Please verify if this action was intentional and authorized.",
        affected_resources
    )

def terminate_instances(record):
    """
    Handle the TerminateInstances event detection.
    """

    if record.get('eventName') != 'TerminateInstances':
        return

    affected_resources = []
    request_parameters = record.get('requestParameters') or {}
    instances_set = request_parameters.get('instancesSet') or {}
    items = instances_set.get('items') or []

    for resource in items:
        if isinstance(resource, dict) and resource.get('instanceId') is not None:
            affected_resources.append(resource['instanceId'])

    return create_finding(
        record,
        "TerminateInstances",
        "An EC2 instance termination event was detected. Please verify if this action was intentional and authorized.",
         affected_resources
    )

def detect_security_events(records):
    """
    Detect security events from the provided CloudTrail records. Future detection functions can be added to the detection_functions list.
    """
    findings = []
    detection_functions = [
        delete_vpc,
        terminate_instances
    ]

    for record in records:
        for detect_func in detection_functions:
            finding = detect_func(record)
            if finding is not None:
                findings.append(finding)

    return findings