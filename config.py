import os

# Scanning configuration
SCAN_CONFIG = {
    'timeout': 30,
    'max_retries': 3,
    'common_ports': [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
}