import customtkinter as ctk
import threading
from scanner import parse_arguments, validate_target
from dns_tools import DNSScanner
from network_tools import NetworkScanner
from report_generator import generate_report
from email_sender import EmailSender
import logging
import sys
from datetime import datetime

class SecurityScannerGUI:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("Security Scanner")
        self.window.geometry("800x600")
        
        # Set color scheme
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")
        
        # Configure colors
        self.colors = {
            'blue': "#39b3cf",
            'red': "#fb0134",
            'white': "#f0f5f6"
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = ctk.CTkFrame(self.window, fg_color=self.colors['white'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Header
        header = ctk.CTkLabel(
            main_frame,
            text="Security Scanner",
            font=("Helvetica", 24, "bold"),
            text_color=self.colors['blue']
        )
        header.pack(pady=20)
        
        # Target input
        target_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        target_frame.pack(fill='x', padx=20, pady=10)
        
        target_label = ctk.CTkLabel(target_frame, text="Target Domain/IP:")
        target_label.pack(side='left', padx=5)
        
        self.target_entry = ctk.CTkEntry(target_frame, width=300)
        self.target_entry.pack(side='left', padx=5)
        
        # Email input
        email_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        email_frame.pack(fill='x', padx=20, pady=10)
        
        email_label = ctk.CTkLabel(email_frame, text="Email (optional):")
        email_label.pack(side='left', padx=5)
        
        self.email_entry = ctk.CTkEntry(email_frame, width=300)
        self.email_entry.pack(side='left', padx=5)
        
        # Scan options
        options_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        options_frame.pack(fill='x', padx=20, pady=10)
        
        self.dns_var = ctk.BooleanVar(value=True)
        self.network_var = ctk.BooleanVar(value=True)
        
        dns_check = ctk.CTkCheckBox(
            options_frame,
            text="DNS Scan",
            variable=self.dns_var,
            text_color=self.colors['blue']
        )
        dns_check.pack(side='left', padx=20)
        
        network_check = ctk.CTkCheckBox(
            options_frame,
            text="Network Scan",
            variable=self.network_var,
            text_color=self.colors['blue']
        )
        network_check.pack(side='left', padx=20)
        
        # Start button
        self.scan_button = ctk.CTkButton(
            main_frame,
            text="Start Scan",
            command=self.start_scan,
            fg_color=self.colors['blue'],
            hover_color="#2d8fa3"
        )
        self.scan_button.pack(pady=20)
        
        # Results text area
        self.results_text = ctk.CTkTextbox(
            main_frame,
            width=700,
            height=300,
            font=("Courier", 12)
        )
        self.results_text.pack(padx=20, pady=10)
        
    def update_results(self, text):
        self.results_text.insert('end', text + '\n')
        self.results_text.see('end')
        
    def start_scan(self):
        target = self.target_entry.get().strip()
        email = self.email_entry.get().strip()
        
        if not target:
            self.update_results("Error: Please enter a target domain or IP address")
            return
            
        if not validate_target(target):
            self.update_results("Error: Invalid target specified")
            return
            
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.results_text.delete('1.0', 'end')
        
        # Start scan in separate thread
        thread = threading.Thread(target=self.perform_scan, args=(target, email))
        thread.daemon = True
        thread.start()
        
    def perform_scan(self, target, email):
        try:
            scan_results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'dns_results': None,
                'network_results': None
            }
            
            if self.dns_var.get():
                self.update_results("Starting DNS scan...")
                dns_scanner = DNSScanner(target)
                scan_results['dns_results'] = dns_scanner.scan()
                self.update_results("DNS scan completed")
                
            if self.network_var.get():
                self.update_results("Starting network scan...")
                network_scanner = NetworkScanner(target)
                scan_results['network_results'] = network_scanner.scan()
                self.update_results("Network scan completed")
                
            report = generate_report(scan_results)
            
            if email:
                self.update_results("Sending email report...")
                email_sender = EmailSender()
                email_sender.send_report(email, report)
                self.update_results(f"Report sent to {email}")
                
            self.update_results("\nScan Results:")
            self.update_results(report)
            
        except Exception as e:
            self.update_results(f"Error: {str(e)}")
            
        finally:
            self.scan_button.configure(state="normal", text="Start Scan")
            
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = SecurityScannerGUI()
    app.run()
