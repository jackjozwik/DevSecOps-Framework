import json
import uuid
import sys
from collections import defaultdict

def sanitize_label_value(value):
    return str(value).replace('"', '').replace(' ', '_').replace(':', '').replace('/', '_').replace('\n', ' ')[:256]

def kubernetes_to_prometheus_format(input_file, output_file):
    with open(input_file, 'r') as f:
        data = json.load(f)

    metrics = defaultdict(int)
    metric_lines = set()  # Use a set to avoid duplicates

    # Top-level metadata
    schema_version = data.get('SchemaVersion', '')
    created_at = data.get('CreatedAt', '')
    artifact_name = sanitize_label_value(data.get('ArtifactName', ''))
    artifact_type = data.get('ArtifactType', '')

    metric_lines.add(f'trivy_kubernetes_scan_info{{schema_version="{schema_version}",created_at="{created_at}",artifact_name="{artifact_name}",artifact_type="{artifact_type}"}} 1')

    results = data.get('Results', [])
    for res in results:
        target_sanitized = sanitize_label_value(res.get('Target', 'unknown'))
        class_type = res.get('Class', '')
        type_value = res.get('Type', '')
        
        # Overall summary
        summary = res.get('MisconfSummary', {})
        metrics[f'trivy_kubernetes_checks_total{{result="success",target="{target_sanitized}"}}'] += summary.get('Successes', 0)
        metrics[f'trivy_kubernetes_checks_total{{result="failure",target="{target_sanitized}"}}'] += summary.get('Failures', 0)
        metrics[f'trivy_kubernetes_checks_total{{result="exception",target="{target_sanitized}"}}'] += summary.get('Exceptions', 0)

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
            metric_lines.add(f'trivy_kubernetes_misconfiguration{{{label_str}}} 1')

            # Additional metrics
            metrics[f'trivy_kubernetes_misconfig_severity_total{{severity="{labels["severity"]}",target="{target_sanitized}"}}'] += 1

            # Detailed information metrics
            description = sanitize_label_value(misconf.get('Description', ''))
            message = sanitize_label_value(misconf.get('Message', ''))
            query = sanitize_label_value(misconf.get('Query', ''))
            resolution = sanitize_label_value(misconf.get('Resolution', ''))
            
            info_label_str = f'id="{labels["id"]}",description="{description}",message="{message}",query="{query}",resolution="{resolution}"'
            metric_lines.add(f'trivy_kubernetes_misconfig_info{{{info_label_str}}} 1')

            # Reference URLs
            for ref in misconf.get('References', []):
                ref_sanitized = sanitize_label_value(ref)
                ref_metric = f'trivy_kubernetes_misconfig_reference{{id="{labels["id"]}",url="{ref_sanitized}"}}'
                metric_lines.add(f"{ref_metric} 1")

            # Primary URL metric
            primary_url = sanitize_label_value(misconf.get('PrimaryURL', ''))
            if primary_url:
                primary_url_metric = f'trivy_kubernetes_misconfig_primary_url{{id="{labels["id"]}",url="{primary_url}"}}'
                metric_lines.add(f"{primary_url_metric} 1")

            # CauseMetadata metrics
            cause_metadata = misconf.get('CauseMetadata', {})
            provider = sanitize_label_value(cause_metadata.get('Provider', ''))
            service = sanitize_label_value(cause_metadata.get('Service', ''))
            start_line = cause_metadata.get('StartLine', 0)
            end_line = cause_metadata.get('EndLine', 0)

            cause_label_str = f'id="{labels["id"]}",provider="{provider}",service="{service}",start_line="{start_line}",end_line="{end_line}"'
            metric_lines.add(f'trivy_kubernetes_misconfig_cause{{{cause_label_str}}} 1')

            # Code snippet metric (first line only for brevity)
            code_lines = cause_metadata.get('Code', {}).get('Lines', [])
            if code_lines:
                first_line = code_lines[0]
                line_number = first_line.get('Number', 0)
                content = sanitize_label_value(first_line.get('Content', ''))
                is_cause = 'true' if first_line.get('IsCause', False) else 'false'
                code_label_str = f'id="{labels["id"]}",line_number="{line_number}",content="{content}",is_cause="{is_cause}"'
                metric_lines.add(f'trivy_kubernetes_misconfig_code{{{code_label_str}}} 1')

    # Write metrics to .prom file
    with open(output_file, 'w') as f:
        f.write("# HELP trivy_kubernetes_scan_info Information about the Kubernetes Trivy scan\n")
        f.write("# TYPE trivy_kubernetes_scan_info gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_scan_info'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_kubernetes_checks_total Total number of Kubernetes checks\n")
        f.write("# TYPE trivy_kubernetes_checks_total gauge\n")
        for metric, value in metrics.items():
            if metric.startswith('trivy_kubernetes_checks_total'):
                f.write(f"{metric} {value}\n")

        f.write("\n# HELP trivy_kubernetes_misconfiguration Details of Kubernetes misconfigurations\n")
        f.write("# TYPE trivy_kubernetes_misconfiguration gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_misconfiguration'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_kubernetes_misconfig_severity_total Total number of Kubernetes misconfigurations by severity\n")
        f.write("# TYPE trivy_kubernetes_misconfig_severity_total gauge\n")
        for metric, value in metrics.items():
            if metric.startswith('trivy_kubernetes_misconfig_severity_total'):
                f.write(f"{metric} {value}\n")

        f.write("\n# HELP trivy_kubernetes_misconfig_info Detailed information about Kubernetes misconfigurations\n")
        f.write("# TYPE trivy_kubernetes_misconfig_info gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_misconfig_info'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_kubernetes_misconfig_reference Reference URLs for Kubernetes misconfigurations\n")
        f.write("# TYPE trivy_kubernetes_misconfig_reference gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_misconfig_reference'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_kubernetes_misconfig_primary_url Primary URLs for Kubernetes misconfigurations\n")
        f.write("# TYPE trivy_kubernetes_misconfig_primary_url gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_misconfig_primary_url'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_kubernetes_misconfig_cause Cause metadata for Kubernetes misconfigurations\n")
        f.write("# TYPE trivy_kubernetes_misconfig_cause gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_misconfig_cause'):
                f.write(f"{line}\n")

        f.write("\n# HELP trivy_kubernetes_misconfig_code Code snippets for Kubernetes misconfigurations\n")
        f.write("# TYPE trivy_kubernetes_misconfig_code gauge\n")
        for line in metric_lines:
            if line.startswith('trivy_kubernetes_misconfig_code'):
                f.write(f"{line}\n")

    print(f"Metrics successfully written to {output_file}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_json_file> <output_prom_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    kubernetes_to_prometheus_format(input_file, output_file)

if __name__ == "__main__":
    main()