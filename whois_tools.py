import whois
import logging
import subprocess
import os
from typing import Dict, Any, Optional
from datetime import datetime

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log')
    ]
)
logger = logging.getLogger(__name__)

class WhoisScanner:
    """WHOIS Scanner for domain information lookup"""
    
    def __init__(self, target: str):
        self.target = target
        
    def scan(self) -> Dict[str, Any]:
        """
        Perform WHOIS lookup and return structured results
        """
        try:
            logger.info(f"Starting WHOIS lookup for {self.target}")
            
            # First try using python-whois
            try:
                w = whois.whois(self.target)
                if w and w.domain_name:  # Valid response
                    return self._process_whois_data(w)
            except Exception as e:
                logger.warning(f"python-whois failed, falling back to command line: {str(e)}")
            
            # Fallback to command line whois
            try:
                # Check if we're on Windows and use the correct path
                whois_cmd = 'whois.exe' if os.name == 'nt' else 'whois'
                whois_path = None
                
                # Try to find whois in common Windows locations
                if os.name == 'nt':
                    possible_paths = [
                        'C:\\whois\\whois.exe',
                        'C:\\Windows\\System32\\whois.exe',
                        os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'whois\\whois.exe'),
                        os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'whois\\whois.exe')
                    ]
                    for path in possible_paths:
                        if os.path.exists(path):
                            whois_path = path
                            break
                    
                    if not whois_path:
                        raise FileNotFoundError("Could not find whois.exe in any standard location")
                
                # Run the WHOIS command
                cmd = [whois_path if whois_path else whois_cmd, self.target]
                result = subprocess.run(cmd, 
                                     capture_output=True, 
                                     text=True, 
                                     timeout=30)
                if result.returncode == 0:
                    return self._process_raw_whois(result.stdout)
                else:
                    raise Exception(f"whois command failed: {result.stderr}")
            except Exception as e:
                logger.error(f"Command line whois failed: {str(e)}")
                raise
            
        except Exception as e:
            error_msg = f"Error during WHOIS lookup: {str(e)}"
            logger.error(error_msg)
            return {'error': error_msg}
    
    def _process_whois_data(self, w) -> Dict[str, Any]:
        """Process python-whois data"""
        # Group related information together
        results = {
            'records': {
                'registration': [
                    f"Domain Name: {w.domain_name[0] if isinstance(w.domain_name, list) else w.domain_name}",
                    f"Registrar: {w.registrar}" if w.registrar else None,
                    f"Organization: {w.org}" if hasattr(w, 'org') and w.org else None,
                    f"Created: {self._format_date(w.creation_date)}" if w.creation_date else None,
                    f"Expires: {self._format_date(w.expiration_date)}" if w.expiration_date else None,
                    f"Updated: {self._format_date(w.updated_date)}" if w.updated_date else None
                ],
                'name_servers': self._format_list(w.name_servers),
                'status': self._format_list(w.status),
                'dnssec': [w.dnssec if hasattr(w, 'dnssec') else 'Not available'],
                'contacts': self._format_list(w.emails) if hasattr(w, 'emails') and w.emails else []
            },
            'raw_data': str(w),
            'vulnerabilities': []
        }
        
        # Clean up None values and empty lists
        results['records']['registration'] = [r for r in results['records']['registration'] if r]
        results['records'] = {k: v for k, v in results['records'].items() if v and (not isinstance(v, list) or len(v) > 0)}
        
        # Check for potential security issues
        self._check_vulnerabilities(results)
        return results
    
    def _process_raw_whois(self, raw_output: str) -> Dict[str, Any]:
        """Process raw whois command output"""
        lines = raw_output.split('\n')
        results = {
            'records': {
                'registration': [],
                'name_servers': [],
                'status': [],
                'dnssec': ['Not available'],
                'contacts': []
            },
            'raw_data': raw_output,
            'vulnerabilities': []
        }
        
        domain_name = None
        registrar = None
        organization = None
        creation_date = None
        expiration_date = None
        updated_date = None
        
        for line in lines:
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if value:  # Only process non-empty values
                    if 'domain name' in key:
                        domain_name = f"Domain Name: {value}"
                    elif 'registrar' in key:
                        registrar = f"Registrar: {value}"
                    elif 'organization' in key or 'org' in key:
                        organization = f"Organization: {value}"
                    elif 'creation date' in key or 'created' in key:
                        creation_date = f"Created: {value}"
                    elif 'expiration date' in key or 'expires' in key:
                        expiration_date = f"Expires: {value}"
                    elif 'updated date' in key or 'last update' in key:
                        updated_date = f"Updated: {value}"
                    elif 'name server' in key:
                        if value not in results['records']['name_servers']:
                            results['records']['name_servers'].append(value)
                    elif 'status' in key:
                        if value not in results['records']['status']:
                            results['records']['status'].append(value)
                    elif 'dnssec' in key:
                        results['records']['dnssec'] = [value]
                    elif '@' in value:
                        if value not in results['records']['contacts']:
                            results['records']['contacts'].append(value)
        
        # Add registration information
        registration_info = [
            domain_name,
            registrar,
            organization,
            creation_date,
            expiration_date,
            updated_date
        ]
        results['records']['registration'] = [info for info in registration_info if info]
        
        # Clean up empty lists and None values
        results['records'] = {k: v for k, v in results['records'].items() if v and (not isinstance(v, list) or len(v) > 0)}
        
        # Check for potential security issues
        self._check_vulnerabilities(results)
        return results
    
    def _format_date(self, date) -> Optional[str]:
        """Format date objects to string"""
        if not date:
            return None
        if isinstance(date, list):
            date = date[0]
        if isinstance(date, datetime):
            return date.strftime('%Y-%m-%d %H:%M:%S')
        return str(date)
    
    def _format_list(self, value) -> list:
        """Format a value into a list, handling various input types"""
        if not value:
            return []
        if isinstance(value, list):
            return [str(v).strip() for v in value if v]
        return [str(value).strip()]
    
    def _check_vulnerabilities(self, results: Dict) -> None:
        """Check for potential security issues in WHOIS data"""
        records = results['records']
        vulnerabilities = results['vulnerabilities']
        
        # Check domain expiration
        expiry_date = None
        for info in records.get('registration', []):
            if info and info.startswith('Expires:'):
                expiry_date = info.split(':', 1)[1].strip()
                break
        
        if expiry_date:
            try:
                expiry = datetime.strptime(expiry_date, '%Y-%m-%d %H:%M:%S')
                days_until_expiry = (expiry - datetime.now()).days
                if days_until_expiry < 30:
                    vulnerabilities.append({
                        'type': 'domain-expiry',
                        'severity': 'high',
                        'description': f'Domain will expire in {days_until_expiry} days'
                    })
            except:
                pass
        
        # Check DNSSEC
        if records.get('dnssec', ['Not available'])[0] in ['unsigned', 'None', 'Not available']:
            vulnerabilities.append({
                'type': 'dnssec-missing',
                'severity': 'medium',
                'description': 'DNSSEC is not enabled for this domain'
            })
        
        # Check for privacy protection
        if records.get('contacts') and any('@' in email for email in records['contacts']):
            vulnerabilities.append({
                'type': 'email-exposure',
                'severity': 'medium',
                'description': 'Email addresses are publicly visible in WHOIS data'
            }) 