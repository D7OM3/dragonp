import nmap
import logging
import os
import sys
from typing import Dict, Any, Optional

class NmapScanner:
    """Nmap-based port scanner implementation"""
    
    def __init__(self, target: str):
        self.target = target
        
        # Set default Nmap path for Windows
        if os.name == 'nt':  # Windows
            default_paths = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Program Files (x86)\nmap\nmap.exe",  # Additional common paths
                r"C:\Program Files\nmap\nmap.exe",
                os.path.join(os.environ.get('ProgramFiles(x86)', ''), 'Nmap', 'nmap.exe'),
                os.path.join(os.environ.get('ProgramFiles', ''), 'Nmap', 'nmap.exe')
            ]
            
            nmap_path = None
            for path in default_paths:
                logging.info(f"Checking Nmap path: {path}")
                if os.path.exists(path):
                    nmap_path = path
                    logging.info(f"Found Nmap at: {path}")
                    break
            
            if nmap_path:
                # Add Nmap directory to system PATH
                nmap_dir = os.path.dirname(nmap_path)
                if nmap_dir not in os.environ['PATH']:
                    os.environ['PATH'] = nmap_dir + os.pathsep + os.environ['PATH']
                    logging.info(f"Added Nmap directory to PATH: {nmap_dir}")
                
                # Set nmap path for python-nmap
                nmap.PortScanner.nmap_path = lambda _: nmap_path
            else:
                logging.error("Nmap executable not found in standard locations")
                raise FileNotFoundError("Nmap executable not found. Please ensure Nmap is installed correctly.")
        
        try:
            self.nm = nmap.PortScanner()
            logging.info("Successfully initialized Nmap scanner")
        except Exception as e:
            logging.error(f"Failed to initialize Nmap scanner: {str(e)}")
            raise
        
    def scan(self, options: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
        """
        Perform Nmap scan with specified options
        
        Args:
            options: Dictionary of scan options (all_ports, syn_scan, timing, version, default_scripts, vuln)
        """
        if options is None:
            options = {}
            
        args = []
        
        # Map flags to user selections
        if options.get('all_ports'):
            args.append("-p-")
        if options.get('syn_scan'):
            args.append("-sS")
        if options.get('timing'):
            args.append("-T4")
        if options.get('version'):
            args.append("-sV")
        if options.get('default_scripts'):
            args.append("-sC")
        if options.get('vuln'):
            args.append("--script vuln")
            
        # Always add version detection if no specific options are set
        if not args:
            args.append("-sV")

        scan_args = " ".join(args)
        
        try:
            logging.info(f"Starting Nmap scan of {self.target} with args: {scan_args}")
            logging.info(f"Using Nmap path: {self.nm.nmap_path()}")
            self.nm.scan(hosts=self.target, arguments=scan_args)
            
            results = {
                'hosts': [],
                'scan_info': {
                    'arguments': scan_args,
                    'timestamp': self.nm.scanstats().get('timestr', ''),
                    'elapsed': self.nm.scanstats().get('elapsed', ''),
                }
            }
            
            for host in self.nm.all_hosts():
                host_data = {
                    'address': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports_data = []
                    ports = sorted(self.nm[host][proto].keys())
                    
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        ports_data.append({
                            'port': port,
                            'state': port_info.get('state', 'unknown'),
                            'service': port_info.get('name', ''),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'cpe': port_info.get('cpe', ''),
                            'scripts': port_info.get('script', {})
                        })
                    
                    host_data['protocols'][proto] = ports_data
                
                results['hosts'].append(host_data)
            
            return results
            
        except Exception as e:
            error_msg = f"Nmap scan error: {str(e)}"
            logging.error(error_msg)
            return {'error': error_msg} 