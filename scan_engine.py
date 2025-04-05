import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from dns_tools import DNSScanner
from nmap_scanner import NmapScanner
from whois_tools import WhoisScanner
from models import db, ScanResult, Vulnerability, ScanDetail
import uuid

class ScanEngine:
    """Manages scanning operations and tracks progress"""

    def __init__(self):
        self.active_scans = {}
        self.scan_progress = {}
        logging.info("ScanEngine initialized")

    def start_scan(self, scan_id: str, target: str, scan_type: str, selected_tools: List[str]) -> Dict[str, Any]:
        """Start a new scan with progress tracking"""
        try:
            if scan_id in self.active_scans:
                raise ValueError(f"Scan with ID {scan_id} is already running")

            # Initialize scan data
            self.active_scans[scan_id] = {
                'target': target,
                'type': scan_type,
                'tools': selected_tools,
                'start_time': datetime.now(),
                'status': 'running',
                'progress': 0,
                'results': {},  # Initialize empty results dictionary
                'current_tool': selected_tools[0] if selected_tools else None
            }

            # Initialize progress tracking
            total_steps = len(selected_tools)
            self.scan_progress[scan_id] = {
                'current_step': 0,
                'total_steps': total_steps,
                'current_tool': selected_tools[0] if selected_tools else None
            }

            return {'status': 'started', 'scan_id': scan_id}

        except Exception as e:
            logging.error(f"Failed to start scan: {str(e)}")
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            if scan_id in self.scan_progress:
                del self.scan_progress[scan_id]
            return {'status': 'error', 'message': str(e)}

    def get_scan_progress(self, scan_id: str) -> Dict[str, Any]:
        """Get current scan progress"""
        if scan_id not in self.active_scans:
            return {'status': 'not_found', 'progress': 0}

        scan = self.active_scans[scan_id]
        progress = self.scan_progress[scan_id]

        response = {
            'status': scan['status'],
            'progress': (progress['current_step'] / progress['total_steps'] * 100) if progress['total_steps'] > 0 else 0,
            'current_tool': progress['current_tool'],
            'target': scan['target'],
            'tools': scan['tools']
        }

        # Include results if they exist
        if 'results' in scan:
            response['results'] = scan['results']

        return response

    def execute_scan(self, scan_id: str) -> Dict[str, Any]:
        """Execute scan with selected tools"""
        if scan_id not in self.active_scans:
            logging.error(f"Scan ID {scan_id} not found in active scans")
            return {'status': 'not_found'}

        scan = self.active_scans[scan_id]
        
        try:
            # Handle DNS lookup if selected
            if 'dns-lookup' in scan['tools']:
                logging.info(f"Starting DNS lookup for {scan['target']}")
                try:
                    dns_scanner = DNSScanner(scan['target'])
                    dns_options = {
                        'A': True,
                        'AAAA': True,
                        'MX': True,
                        'NS': True,
                        'TXT': True,
                        'SOA': True,
                        'CNAME': True,
                        'PTR': True
                    }
                    dns_results = dns_scanner.scan(dns_options)
                    
                    # Update scan results with DNS data
                    scan['results']['dns-lookup'] = dns_results
                    scan['current_tool'] = 'dns-lookup'
                    
                    # Log success
                    logging.info(f"DNS lookup completed for {scan['target']}")
                    
                    # Save to database if possible
                    try:
                        scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
                        if scan_result:
                            scan_detail = ScanDetail(
                                scan_id=scan_result.id,
                                tool_name='dns-lookup',
                                raw_output=str(dns_results)
                            )
                            db.session.add(scan_detail)
                            db.session.commit()
                    except Exception as db_error:
                        logging.error(f"Database error: {str(db_error)}")
                        # Continue even if database save fails
                
                except Exception as dns_error:
                    error_msg = f"DNS lookup error: {str(dns_error)}"
                    logging.error(error_msg)
                    scan['results']['dns-lookup'] = {'error': error_msg}

            # Handle port scanning if selected
            if 'port-scan' in scan['tools']:
                logging.info(f"Starting port scan for {scan['target']}")
                try:
                    nmap_scanner = NmapScanner(scan['target'])
                    scan_options = {
                        'version': True,  # Enable version detection
                        'default_scripts': True,  # Run default scripts
                        'timing': True,  # Use aggressive timing
                    }
                    port_results = nmap_scanner.scan(scan_options)
                    
                    # Debug log the results
                    logging.info(f"Port scan results: {port_results}")
                    
                    # Save to database
                    try:
                        scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
                        if scan_result:
                            # Store both raw and structured results
                            raw_output = str(port_results)
                            scan_detail = ScanDetail(
                                scan_id=scan_result.id,
                                tool_name='port-scan',
                                raw_output=raw_output
                            )
                            db.session.add(scan_detail)
                            db.session.commit()
                            logging.info(f"Saved port scan results to database for scan_id: {scan_id}")
                            
                            # Update scan results with both raw and structured data
                            scan['results']['port-scan'] = {
                                'raw_output': raw_output,
                                'structured_data': {
                                    'hosts': port_results.get('hosts', []),
                                    'scan_info': port_results.get('scan_info', {})
                                }
                            }
                    except Exception as db_error:
                        logging.error(f"Database error: {str(db_error)}")
                        # If database fails, still update the results
                        scan['results']['port-scan'] = {
                            'raw_output': str(port_results),
                            'structured_data': {
                                'hosts': port_results.get('hosts', []),
                                'scan_info': port_results.get('scan_info', {})
                            }
                        }
                    
                    scan['current_tool'] = 'port-scan'
                    
                    # Update progress
                    progress = self.scan_progress[scan_id]
                    progress['current_step'] += 1
                    
                    # Log success
                    logging.info(f"Port scan completed for {scan['target']}")
                
                except Exception as port_error:
                    error_msg = f"Port scan error: {str(port_error)}"
                    logging.error(error_msg)
                    scan['results']['port-scan'] = {'error': error_msg}

            # Handle WHOIS lookup if selected
            if 'whois-lookup' in scan['tools']:
                logging.info(f"Starting WHOIS lookup for {scan['target']}")
                try:
                    whois_scanner = WhoisScanner(scan['target'])
                    whois_results = whois_scanner.scan()
                    
                    # Debug log the results
                    logging.info(f"WHOIS lookup results: {whois_results}")
                    
                    if 'error' in whois_results:
                        scan['results']['whois-lookup'] = whois_results
                    else:
                        # Save to database
                        try:
                            scan_result = ScanResult.query.filter_by(scan_id=scan_id).first()
                            if scan_result:
                                scan_detail = ScanDetail(
                                    scan_id=scan_result.id,
                                    tool_name='whois-lookup',
                                    raw_output=whois_results.get('raw_data', str(whois_results))
                                )
                                db.session.add(scan_detail)
                                db.session.commit()
                                logging.info(f"Saved WHOIS results to database for scan_id: {scan_id}")
                        except Exception as db_error:
                            logging.error(f"Database error: {str(db_error)}")
                        
                        # Update scan results
                        scan['results']['whois-lookup'] = {
                            'records': whois_results['records'],
                            'vulnerabilities': whois_results['vulnerabilities']
                        }
                    
                    scan['current_tool'] = 'whois-lookup'
                    
                    # Update progress
                    progress = self.scan_progress[scan_id]
                    progress['current_step'] += 1
                    
                    # Log success
                    logging.info(f"WHOIS lookup completed for {scan['target']}")
                    
                except Exception as whois_error:
                    error_msg = f"WHOIS lookup error: {str(whois_error)}"
                    logging.error(error_msg)
                    scan['results']['whois-lookup'] = {'error': error_msg}

            # Update final status
            scan['status'] = 'completed'
            logging.info(f"Scan completed. Final results: {scan['results']}")
            
            # Return results
            return {
                'status': 'completed',
                'target': scan['target'],
                'current_tool': scan['current_tool'],
                'results': scan['results']
            }

        except Exception as e:
            error_msg = f"Scan execution failed: {str(e)}"
            logging.error(error_msg)
            scan['status'] = 'failed'
            return {'status': 'error', 'message': error_msg}