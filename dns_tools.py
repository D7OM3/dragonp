import dns.resolver
import dns.reversename
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

class DNSScanner:
    """DNS Scanner for comprehensive DNS enumeration"""
    def __init__(self, target: str):
        self.target = target
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def _query_record(self, record_type: str) -> List[str]:
        """Query specific DNS record type with error handling"""
        try:
            answers = self.resolver.resolve(self.target, record_type)
            results = [str(rdata) for rdata in answers]
            logging.info(f"Found {len(results)} {record_type} records for {self.target}")
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            logging.info(f"No {record_type} records found for {self.target}")
            return []
        except dns.resolver.Timeout:
            logging.warning(f"Timeout querying {record_type} records for {self.target}")
            return []
        except Exception as e:
            logging.error(f"Error querying {record_type} records: {str(e)}")
            return []

    def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            rev_name = dns.reversename.from_address(ip)
            answer = self.resolver.resolve(rev_name, "PTR")
            return str(answer[0])
        except Exception as e:
            logging.error(f"Reverse DNS lookup failed for {ip}: {str(e)}")
            return None

    def scan(self, options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Perform comprehensive DNS scan with configurable options
        """
        logging.info(f"Starting DNS scan for {self.target}")

        if options is None:
            options = {
                'A': True, 'AAAA': True, 'MX': True, 'NS': True,
                'TXT': True, 'SOA': True, 'CNAME': True, 'PTR': True
            }

        results = {'records': {}}
        vulnerabilities = []

        # Perform forward lookups for enabled record types
        for record_type, enabled in options.items():
            if enabled and record_type != 'PTR':
                records = self._query_record(record_type)
                results['records'][record_type] = records

                # Check for potential security issues
                if record_type == 'TXT':
                    for record in records:
                        if 'v=spf1' in record.lower():
                            vulnerabilities.append({
                                'type': 'dns-spf',
                                'severity': 'info',
                                'description': f'SPF record found: {record}'
                            })
                elif record_type == 'MX':
                    for record in records:
                        vulnerabilities.append({
                            'type': 'dns-mx',
                            'severity': 'info',
                            'description': f'Mail server found: {record}'
                        })

        # Special handling for PTR records if A records exist
        if options.get('PTR', True) and 'A' in results['records']:
            ptr_results = []
            for ip in results['records']['A']:
                ptr = self._reverse_dns_lookup(ip)
                if ptr:
                    ptr_results.append(ptr)
            results['records']['PTR'] = ptr_results

        # Add metadata
        results.update({
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': vulnerabilities,
            'total_records': sum(len(records) for records in results['records'].values())
        })

        return results