from typing import Dict, Any
from datetime import datetime

def get_severity_color(severity: str) -> str:
    colors = {
        'critical': '\033[91m',  # Red
        'high': '\033[93m',      # Yellow
        'medium': '\033[94m',    # Blue
        'low': '\033[92m',       # Green
        'info': '\033[0m'        # Default
    }
    return colors.get(severity.lower(), colors['info'])

def determine_severity(port_data: Dict) -> str:
    """Determine severity based on service and version information"""
    if port_data.get('state') != 'open':
        return 'info'

    critical_services = ['telnet', 'ftp', 'rsh', 'rlogin']
    high_risk_services = ['mysql', 'mssql', 'oracle', 'postgresql']

    service = port_data.get('service', '').lower()
    version = port_data.get('version', '')

    if service in critical_services:
        return 'critical'
    elif service in high_risk_services:
        return 'high'
    elif not version and port_data.get('state') == 'open':
        return 'medium'
    return 'low'

def generate_report(scan_results: Dict[str, Any]) -> str:
    report = []
    report.append("=" * 60)
    report.append("Security Scan Report")
    report.append("=" * 60)
    report.append(f"Target: {scan_results['target']}")
    report.append(f"Scan Date: {scan_results['timestamp']}")
    report.append(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("\n")

    # Add Executive Summary
    total_vulnerabilities = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }

    if scan_results.get('dns_results'):
        report.append("-" * 30)
        report.append("DNS Analysis Results")
        report.append("-" * 30)
        dns_data = scan_results['dns_results'].get('records', {})

        for record_type, records in dns_data.items():
            if records:
                report.append(f"\n{record_type} Records:")
                for record in records:
                    report.append(f"  - {record}")

    if scan_results.get('network_results'):
        report.append("\n" + "=" * 30)
        report.append("Network Security Analysis")
        report.append("=" * 30)

        for host, host_data in scan_results['network_results'].items():
            report.append(f"\nHost: {host}")
            report.append(f"State: {host_data['state']}")

            # Add summary statistics
            if 'summary' in host_data:
                summary = host_data['summary']
                report.append("\nPort Summary:")
                report.append(f"  Total Ports Scanned: {summary['total_ports']}")
                report.append(f"  Open Ports: {summary['open_ports']}")
                report.append(f"  Filtered Ports: {summary['filtered_ports']}")
                report.append(f"  Closed Ports: {summary['closed_ports']}")

            # Enhanced service and vulnerability reporting
            if 'protocols' in host_data:
                report.append("\nDetailed Port Analysis:")
                for proto in host_data['protocols']:
                    for port, port_data in host_data['protocols'][proto].items():
                        severity = determine_severity(port_data)
                        total_vulnerabilities[severity] += 1

                        color = get_severity_color(severity)
                        report.append(f"\n{color}[{severity.upper()}] Port {port}/{proto}:")
                        report.append(f"  Service: {port_data['service']}")
                        if port_data.get('version'):
                            report.append(f"  Version: {port_data['version']}")
                        if port_data.get('product'):
                            report.append(f"  Product: {port_data['product']}")
                        if port_data.get('extrainfo'):
                            report.append(f"  Additional Info: {port_data['extrainfo']}")

                        # Add security recommendations
                        if severity in ['critical', 'high']:
                            report.append("  Recommendations:")
                            if port_data['service'] in ['telnet', 'ftp']:
                                report.append("   - Consider replacing with secure alternatives (SSH/SFTP)")
                            report.append("   - Implement strict access controls")
                            report.append("   - Enable encryption if possible")

            # Port forwarding analysis
            if 'port_forwarding' in host_data:
                report.append("\nPort Forwarding Analysis:")
                for port_info in host_data['port_forwarding']:
                    report.append(f"  {port_info[2]}")  # port_info[2] contains the status message

    # Add Executive Summary at the end
    report.append("\n" + "=" * 30)
    report.append("Executive Summary")
    report.append("=" * 30)
    report.append("\nVulnerability Overview:")
    for severity, count in total_vulnerabilities.items():
        if count > 0:
            color = get_severity_color(severity)
            report.append(f"{color}{severity.upper()}: {count} finding(s)")

    return "\n".join(report)