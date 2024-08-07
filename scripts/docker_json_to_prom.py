import json
import uuid
import sys
from collections import defaultdict

def sanitize_label_value(value):
    return str(value).replace('"', '').replace(' ', '_').replace(':', '').replace('/', '_').replace('\n', ' ')[:256]

def docker_to_prometheus_format(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)

    metrics = defaultdict(int)
    metric_lines = []

    # Top-level metadata
    schema_version = data.get('SchemaVersion', '')
    created_at = data.get('CreatedAt', '')
    artifact_name = sanitize_label_value(data.get('ArtifactName', ''))
    artifact_type = data.get('ArtifactType', '')

    metric_lines.append(f'trivy_docker_scan_info{{schema_version="{schema_version}",created_at="{created_at}",artifact_name="{artifact_name}",artifact_type="{artifact_type}"}} 1')

    results = data.get('Results', [])
    for res in results:
        target_sanitized = sanitize_label_value(res.get('Target', 'unknown'))
        class_type = res.get('Class', '')
        type_value = res.get('Type', '')
        
        # Initialize counters and sets for tracking unique metrics
        reference_counter = defaultdict(int)
        primary_url_counter = defaultdict(int)
        cause_counter = defaultdict(int)
        info_counter = defaultdict(int)

        # Overall summary
        summary = res.get('MisconfSummary', {})
        metrics[f'trivy_docker_checks_total{{result="success",target="{target_sanitized}"}}'] += summary.get('Successes', 0)
        metrics[f'trivy_docker_checks_total{{result="failure",target="{target_sanitized}"}}'] += summary.get('Failures', 0)
        metrics[f'trivy_docker_checks_total{{result="exception",target="{target_sanitized}"}}'] += summary.get('Exceptions', 0)

        misconfigurations = res.get('Misconfigurations', [])
        for misconf in misconfigurations:
            unique_id = str(uuid.uuid4())
            
            # Main misconfiguration metric
            labels = {
                'target': target_sanitized,
                'class': class_type,
                'type': type_value,
                'misconfig_type': sanitize_label_value(misconf.get('Type', '')),
                'id': sanitize_label_value(misconf.get('ID', '')),
                'avdid': sanitize_label_value(misconf.get('AVDID', '')),
                'title': sanitize_label_value(misconf.get('Title', '')),
                'severity': sanitize_label_value(misconf.get('Severity', '')),
                'status': sanitize_label_value(misconf.get('Status', '')),
                'namespace': sanitize_label_value(misconf.get('Namespace', '')),
                'uuid': unique_id
            }
            label_str = ','.join(f'{k}="{v}"' for k, v in labels.items() if v)
            metric_lines.append(f'trivy_docker_misconfiguration{{{label_str}}} 1')

            # Additional metrics
            metrics[f'trivy_docker_misconfig_severity_total{{severity="{labels["severity"]}",target="{target_sanitized}"}}'] += 1

            # Detailed information metrics
            description = sanitize_label_value(misconf.get('Description', ''))
            message = sanitize_label_value(misconf.get('Message', ''))
            query = sanitize_label_value(misconf.get('Query', ''))
            resolution = sanitize_label_value(misconf.get('Resolution', ''))
            
            info_key = (labels['id'], description, message, query, resolution)
            info_counter[info_key] += 1
            info_label_str = f'id="{labels["id"]}",description="{description}",message="{message}",query="{query}",resolution="{resolution}",instance="{info_counter[info_key]}",uuid="{unique_id}"'
            metric_lines.append(f'trivy_docker_misconfig_info{{{info_label_str}}} 1')

            # Reference URLs
            for ref in misconf.get('References', []):
                ref_sanitized = sanitize_label_value(ref)
                reference_counter[(labels['id'], ref_sanitized)] += 1
                ref_metric = f'trivy_docker_misconfig_reference{{id="{labels["id"]}",url="{ref_sanitized}",instance="{reference_counter[(labels["id"], ref_sanitized)]}",uuid="{unique_id}"}} 1'
                metric_lines.append(ref_metric)

            # Primary URL metric
            primary_url = sanitize_label_value(misconf.get('PrimaryURL', ''))
            if primary_url:
                primary_url_counter[(labels['id'], primary_url)] += 1
                primary_url_metric = f'trivy_docker_misconfig_primary_url{{id="{labels["id"]}",url="{primary_url}",instance="{primary_url_counter[(labels["id"], primary_url)]}",uuid="{unique_id}"}} 1'
                metric_lines.append(primary_url_metric)

            # CauseMetadata metrics
            cause_metadata = misconf.get('CauseMetadata', {})
            provider = sanitize_label_value(cause_metadata.get('Provider', ''))
            service = sanitize_label_value(cause_metadata.get('Service', ''))
            cause_key = (labels['id'], provider, service, target_sanitized)
            cause_counter[cause_key] += 1
            cause_label_str = f'id="{labels["id"]}",provider="{provider}",service="{service}",target="{target_sanitized}",instance="{cause_counter[cause_key]}",uuid="{unique_id}"'
            metric_lines.append(f'trivy_docker_misconfig_cause{{{cause_label_str}}} 1')

    # Write metrics to .prom file
    with open(output_file, 'w') as f:
        f.write("# HELP trivy_docker_scan_info Information about the Docker Trivy scan\n")
        f.write("# TYPE trivy_docker_scan_info gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_docker_scan_info'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_docker_checks_total Total number of Docker checks\n")
        f.write("# TYPE trivy_docker_checks_total gauge\n")
        for metric, value in metrics.items():
            if metric.startswith('trivy_docker_checks_total'):
                f.write(f"{metric} {value}\n")

        f.write("\n# HELP trivy_docker_misconfiguration Details of Docker misconfigurations\n")
        f.write("# TYPE trivy_docker_misconfiguration gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_docker_misconfiguration'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_docker_misconfig_severity_total Total number of Docker misconfigurations by severity\n")
        f.write("# TYPE trivy_docker_misconfig_severity_total gauge\n")
        for metric, value in metrics.items():
            if metric.startswith('trivy_docker_misconfig_severity_total'):
                f.write(f"{metric} {value}\n")

        f.write("\n# HELP trivy_docker_misconfig_info Detailed information about Docker misconfigurations\n")
        f.write("# TYPE trivy_docker_misconfig_info gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_docker_misconfig_info'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_docker_misconfig_reference Reference URLs for Docker misconfigurations\n")
        f.write("# TYPE trivy_docker_misconfig_reference gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_docker_misconfig_reference'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_docker_misconfig_primary_url Primary URLs for Docker misconfigurations\n")
        f.write("# TYPE trivy_docker_misconfig_primary_url gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_docker_misconfig_primary_url'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_docker_misconfig_cause Cause metadata for Docker misconfigurations\n")
        f.write("# TYPE trivy_docker_misconfig_cause gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_docker_misconfig_cause'):
                f.write(f"{line}\n")

    print(f"Metrics successfully written to {output_file}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_json_file> <output_prom_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    docker_to_prometheus_format(input_file, output_file)

if __name__ == "__main__":
    main()