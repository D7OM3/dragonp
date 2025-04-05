#!/usr/bin/env python3
import argparse
import sys
from datetime import datetime
from dns_tools import DNSScanner
from network_tools import NetworkScanner
from report_generator import generate_report
from email_sender import EmailSender
from utils import validate_target
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Security Scanner Tool')
    parser.add_argument('target', help='Target domain or IP address')
    parser.add_argument('--email', help='Email address to send the report to')
    parser.add_argument('--dns-only', action='store_true', help='Perform only DNS scanning')
    parser.add_argument('--network-only', action='store_true', help='Perform only network scanning')
    return parser.parse_args()

def main():
    args = parse_arguments()

    if not validate_target(args.target):
        logging.error("Invalid target specified")
        sys.exit(1)

    scan_results = {
        'target': args.target,
        'timestamp': datetime.now().isoformat(),
        'dns_results': None,
        'network_results': None,
        'status': 'starting'
    }

    try:
        if not args.network_only:
            logging.info("Starting DNS scan...")
            scan_results['status'] = 'dns_scanning'
            dns_scanner = DNSScanner(args.target)
            dns_results = dns_scanner.scan()
            if isinstance(dns_results, dict) and 'error' not in dns_results:
                scan_results['dns_results'] = dns_results
            else:
                logging.error(f"DNS scan failed: {dns_results.get('error', 'Unknown error')}")
            logging.info("DNS scan completed")

        if not args.dns_only:
            logging.info("Starting network scan...")
            scan_results['status'] = 'network_scanning'
            network_scanner = NetworkScanner(args.target)
            network_results = network_scanner.scan()
            if isinstance(network_results, dict) and 'error' not in network_results:
                scan_results['network_results'] = network_results
            else:
                logging.error(f"Network scan failed: {network_results.get('error', 'Unknown error')}")
            logging.info("Network scan completed")

        scan_results['status'] = 'completed'
        report = generate_report(scan_results)

        if args.email:
            logging.info("Sending email report...")
            email_sender = EmailSender()
            email_sender.send_report(args.email, report)
            logging.info(f"Report sent to {args.email}")

        print("\nScan Results:")
        print(report)

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        scan_results['status'] = 'failed'
        scan_results['error'] = str(e)
        sys.exit(1)

if __name__ == "__main__":
    main()