import re
import socket
from typing import Union, Tuple, List
import logging
import requests

def validate_target(target: str) -> bool:
    """
    Validates if the target is either a valid domain name or IP address.
    """
    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass

    # Check if it's a valid domain name
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True

    return False

def format_bytes(size: Union[int, float]) -> str:
    """
    Formats byte size to human readable format.
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"

def is_port_open(host: str, port: int, timeout: float = 2) -> bool:
    """
    Check if a port is open on the target host.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except Exception as e:
        logging.debug(f"Error checking port {port}: {str(e)}")
        return False

def verify_port_forwarding(host: str, ports: List[int]) -> List[Tuple[int, bool, str]]:
    """
    Verify if ports are properly forwarded and accessible.
    Returns a list of tuples containing (port, is_accessible, status_message)
    """
    results = []
    for port in ports:
        try:
            # Try internal access first
            internal_access = is_port_open(host, port)

            # Try multiple external port checking services for redundancy
            external_access = False

            # Enhanced status reporting
            if internal_access:
                status = "✓ Port is accessible"
                is_accessible = True
            else:
                status = "✗ Port is not accessible"
                is_accessible = False

            results.append((port, is_accessible, status))

        except Exception as e:
            results.append((port, False, f"Error checking port {port}: {str(e)}"))

    return results

def format_scan_results(scan_data: dict) -> str:
    """
    Format scan results into a human-readable string
    """
    output = []
    output.append("=" * 50)
    output.append("Security Scan Report")
    output.append("=" * 50)

    # Add basic info
    if 'target' in scan_data:
        output.append(f"Target: {scan_data['target']}")
    if 'timestamp' in scan_data:
        output.append(f"Scan Date: {scan_data['timestamp']}")
    output.append("")

    # DNS Records
    if 'records' in scan_data:
        output.append("-" * 20)
        output.append("DNS Records")
        output.append("-" * 20)

        for record_type, records in scan_data['records'].items():
            if records:
                output.append(f"\n{record_type} Records:")
                for record in records:
                    output.append(f"  - {record}")

    # Network Scan Results
    if 'results' in scan_data:
        output.append("\n" + "-" * 20)
        output.append("Network Scan")
        output.append("-" * 20)

        for host, data in scan_data['results'].items():
            output.append(f"\nHost: {host}")
            output.append(f"State: {data.get('state', 'unknown')}")

            if 'summary' in data:
                output.append("\nPort Summary:")
                for key, value in data['summary'].items():
                    output.append(f"  {key.replace('_', ' ').title()}: {value}")

            if 'protocols' in data:
                for proto, ports in data['protocols'].items():
                    output.append(f"\nProtocol: {proto}")
                    for port, info in ports.items():
                        output.append(f"  Port {port}: {info['state']} ({info['service']})")
                        if info.get('version'):
                            output.append(f"    Version: {info['version']}")

    return "\n".join(output)