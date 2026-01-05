"""
Main GUI Application
AI Security Assistant with chat interface and security scanning capabilities
"""
import customtkinter as ctk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import os
import sys

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scanners.log_scanner import LogScanner
from scanners.network_analyzer import NetworkAnalyzer
from scanners.file_scanner import FileScanner
from scanners.registry_scanner import RegistryScanner
from ai.ollama_client import OllamaClient, SecurityAI
from utils.config_manager import ConfigManager


class SecurityAssistantGUI:
    """Main GUI application for AI Security Assistant"""
    
    def __init__(self):
        # Initialize configuration
        self.config = ConfigManager()
        
        # Initialize scanners
        self.log_scanner = LogScanner()
        self.network_analyzer = NetworkAnalyzer()
        self.file_scanner = FileScanner()
        self.registry_scanner = RegistryScanner()
        
        # Initialize AI
        self.ollama_client = OllamaClient(self.config.get_ollama_url())
        self.security_ai = SecurityAI(self.ollama_client, self.config.get_ai_model())
        
        # Setup UI
        self.setup_ui()
        
        # Check Ollama status
        self.check_ollama_status()
    
    def setup_ui(self):
        """Setup the main UI"""
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Create main window
        self.root = ctk.CTk()
        self.root.title("AI Security Assistant")
        self.root.geometry(f"{self.config.get('ui', 'window_width', 1200)}x{self.config.get('ui', 'window_height', 800)}")
        
        # Create main container with tabs
        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.chat_tab = self.tabview.add("Chat")
        self.scan_tab = self.tabview.add("Security Scans")
        self.settings_tab = self.tabview.add("Settings")
        
        # Setup each tab
        self.setup_chat_tab()
        self.setup_scan_tab()
        self.setup_settings_tab()
    
    def setup_chat_tab(self):
        """Setup the chat interface tab"""
        # Chat display area
        self.chat_display = ctk.CTkTextbox(self.chat_tab, width=1100, height=600)
        self.chat_display.pack(padx=10, pady=10)
        self.chat_display.configure(state="disabled")
        
        # Input frame
        input_frame = ctk.CTkFrame(self.chat_tab)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        self.chat_input = ctk.CTkEntry(input_frame, placeholder_text="Ask a security question...")
        self.chat_input.pack(side="left", fill="x", expand=True, padx=5)
        self.chat_input.bind("<Return>", lambda e: self.send_chat_message())
        
        self.send_button = ctk.CTkButton(input_frame, text="Send", command=self.send_chat_message)
        self.send_button.pack(side="right", padx=5)
        
        # Clear button
        self.clear_button = ctk.CTkButton(input_frame, text="Clear Chat", 
                                         command=self.clear_chat, width=100)
        self.clear_button.pack(side="right", padx=5)
        
        # Welcome message
        self.add_chat_message("System", "AI Security Assistant initialized. Ask me about security threats, scan results, or general security questions.")
    
    def setup_scan_tab(self):
        """Setup the security scanning tab"""
        # Left panel - Scan options
        left_panel = ctk.CTkFrame(self.scan_tab, width=300)
        left_panel.pack(side="left", fill="y", padx=10, pady=10)
        
        ctk.CTkLabel(left_panel, text="Security Scans", font=("Arial", 18, "bold")).pack(pady=10)
        
        # Log scan section
        ctk.CTkLabel(left_panel, text="Log File Scan", font=("Arial", 14)).pack(pady=5)
        ctk.CTkButton(left_panel, text="Scan Log Files", 
                     command=self.scan_logs).pack(pady=5, padx=10, fill="x")
        
        # Network scan section
        ctk.CTkLabel(left_panel, text="Network Analysis", font=("Arial", 14)).pack(pady=5)
        ctk.CTkButton(left_panel, text="Analyze Network", 
                     command=self.scan_network).pack(pady=5, padx=10, fill="x")
        
        # File scan section
        ctk.CTkLabel(left_panel, text="File Scan", font=("Arial", 14)).pack(pady=5)
        ctk.CTkButton(left_panel, text="Scan File", 
                     command=self.scan_file).pack(pady=5, padx=10, fill="x")
        ctk.CTkButton(left_panel, text="Scan Directory", 
                     command=self.scan_directory).pack(pady=5, padx=10, fill="x")
        
        # Registry scan section (Windows only)
        ctk.CTkLabel(left_panel, text="Registry Scan", font=("Arial", 14)).pack(pady=5)
        self.registry_button = ctk.CTkButton(left_panel, text="Scan Registry", 
                                            command=self.scan_registry)
        self.registry_button.pack(pady=5, padx=10, fill="x")
        
        if not self.registry_scanner.available:
            self.registry_button.configure(state="disabled")
        
        # AI Analysis button
        ctk.CTkLabel(left_panel, text="AI Analysis", font=("Arial", 14)).pack(pady=10)
        self.analyze_button = ctk.CTkButton(left_panel, text="Analyze Results with AI", 
                                           command=self.analyze_with_ai,
                                           fg_color="green")
        self.analyze_button.pack(pady=5, padx=10, fill="x")
        
        # Right panel - Results display
        right_panel = ctk.CTkFrame(self.scan_tab)
        right_panel.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(right_panel, text="Scan Results", font=("Arial", 18, "bold")).pack(pady=10)
        
        self.results_display = ctk.CTkTextbox(right_panel, width=700, height=650)
        self.results_display.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Store last scan results for AI analysis
        self.last_scan_type = None
        self.last_scan_results = None
    
    def setup_settings_tab(self):
        """Setup the settings tab"""
        settings_frame = ctk.CTkFrame(self.settings_tab)
        settings_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # AI Settings
        ctk.CTkLabel(settings_frame, text="AI Settings", font=("Arial", 18, "bold")).pack(pady=10)
        
        # Ollama URL
        url_frame = ctk.CTkFrame(settings_frame)
        url_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(url_frame, text="Ollama URL:", width=150).pack(side="left", padx=5)
        self.ollama_url_entry = ctk.CTkEntry(url_frame, width=300)
        self.ollama_url_entry.pack(side="left", padx=5)
        self.ollama_url_entry.insert(0, self.config.get_ollama_url())
        ctk.CTkButton(url_frame, text="Save", width=100,
                     command=self.save_ollama_url).pack(side="left", padx=5)
        
        # Model selection
        model_frame = ctk.CTkFrame(settings_frame)
        model_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(model_frame, text="AI Model:", width=150).pack(side="left", padx=5)
        self.model_var = ctk.StringVar(value=self.config.get_ai_model())
        self.model_dropdown = ctk.CTkOptionMenu(model_frame, variable=self.model_var,
                                                values=["llama2", "mistral", "codellama", "phi"],
                                                command=self.change_model)
        self.model_dropdown.pack(side="left", padx=5)
        ctk.CTkButton(model_frame, text="Refresh Models", width=120,
                     command=self.refresh_models).pack(side="left", padx=5)
        
        # Ollama status
        status_frame = ctk.CTkFrame(settings_frame)
        status_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(status_frame, text="Ollama Status:", width=150).pack(side="left", padx=5)
        self.ollama_status_label = ctk.CTkLabel(status_frame, text="Checking...", width=200)
        self.ollama_status_label.pack(side="left", padx=5)
        
        # Log Paths Settings
        ctk.CTkLabel(settings_frame, text="Log File Paths", font=("Arial", 18, "bold")).pack(pady=20)
        
        # Log paths list
        self.log_paths_frame = ctk.CTkScrollableFrame(settings_frame, height=150)
        self.log_paths_frame.pack(fill="x", pady=5)
        self.refresh_log_paths()
        
        # Add log path button
        log_button_frame = ctk.CTkFrame(settings_frame)
        log_button_frame.pack(fill="x", pady=5)
        ctk.CTkButton(log_button_frame, text="Add Log Path", 
                     command=self.add_log_path).pack(side="left", padx=5)
        ctk.CTkButton(log_button_frame, text="Add Log Directory", 
                     command=self.add_log_directory).pack(side="left", padx=5)
    
    def check_ollama_status(self):
        """Check if Ollama is available"""
        if self.ollama_client.is_available():
            self.ollama_status_label.configure(text="✓ Connected", text_color="green")
        else:
            self.ollama_status_label.configure(text="✗ Not Available", text_color="red")
            self.add_chat_message("System", "Warning: Ollama is not available. Please ensure Ollama is running.")
    
    def add_chat_message(self, sender: str, message: str):
        """Add a message to the chat display"""
        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", f"\n[{sender}]\n{message}\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")
    
    def send_chat_message(self):
        """Send a chat message to the AI"""
        message = self.chat_input.get().strip()
        if not message:
            return
        
        self.chat_input.delete(0, "end")
        self.add_chat_message("You", message)
        
        # Disable send button while processing
        self.send_button.configure(state="disabled", text="Thinking...")
        
        # Process in thread to avoid UI freeze
        def process():
            response = self.security_ai.chat_conversation(message)
            self.root.after(0, lambda: self.add_chat_message("AI Assistant", response))
            self.root.after(0, lambda: self.send_button.configure(state="normal", text="Send"))
        
        threading.Thread(target=process, daemon=True).start()
    
    def clear_chat(self):
        """Clear chat history"""
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", "end")
        self.chat_display.configure(state="disabled")
        self.security_ai.clear_conversation()
        self.add_chat_message("System", "Chat cleared.")
    
    def scan_logs(self):
        """Scan configured log files"""
        self.results_display.delete("1.0", "end")
        self.results_display.insert("1.0", "Scanning log files...\n\n")
        
        def scan():
            log_paths = self.config.get_log_paths()
            if not log_paths:
                result = "No log paths configured. Please add log paths in Settings."
            else:
                results = {}
                for path in log_paths:
                    if os.path.isfile(path):
                        findings = self.log_scanner.scan_file(path)
                        if findings:
                            results[path] = findings
                    elif os.path.isdir(path):
                        dir_results = self.log_scanner.scan_directory(path)
                        results.update(dir_results)
                
                result = self.log_scanner.generate_report(results)
            
            self.last_scan_type = "log"
            self.last_scan_results = result
            self.root.after(0, lambda: self.results_display.delete("1.0", "end"))
            self.root.after(0, lambda: self.results_display.insert("1.0", result))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def scan_network(self):
        """Scan network connections"""
        self.results_display.delete("1.0", "end")
        self.results_display.insert("1.0", "Analyzing network connections...\n\n")
        
        def scan():
            result = self.network_analyzer.generate_report()
            self.last_scan_type = "network"
            self.last_scan_results = result
            self.root.after(0, lambda: self.results_display.delete("1.0", "end"))
            self.root.after(0, lambda: self.results_display.insert("1.0", result))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def scan_file(self):
        """Scan a single file"""
        filepath = filedialog.askopenfilename(title="Select file to scan")
        if not filepath:
            return
        
        self.results_display.delete("1.0", "end")
        self.results_display.insert("1.0", f"Scanning file: {filepath}\n\n")
        
        def scan():
            results = self.file_scanner.scan_file_content(filepath)
            report = self.file_scanner.generate_report(results)
            self.last_scan_type = "file"
            self.last_scan_results = report
            self.root.after(0, lambda: self.results_display.delete("1.0", "end"))
            self.root.after(0, lambda: self.results_display.insert("1.0", report))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def scan_directory(self):
        """Scan a directory"""
        dirpath = filedialog.askdirectory(title="Select directory to scan")
        if not dirpath:
            return
        
        self.results_display.delete("1.0", "end")
        self.results_display.insert("1.0", f"Scanning directory: {dirpath}\n\n")
        
        def scan():
            results = self.file_scanner.scan_directory(dirpath, recursive=False)
            report = self.file_scanner.generate_report(results)
            self.last_scan_type = "file"
            self.last_scan_results = report
            self.root.after(0, lambda: self.results_display.delete("1.0", "end"))
            self.root.after(0, lambda: self.results_display.insert("1.0", report))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def scan_registry(self):
        """Scan Windows registry"""
        if not self.registry_scanner.available:
            messagebox.showwarning("Not Available", "Registry scanning is only available on Windows.")
            return
        
        self.results_display.delete("1.0", "end")
        self.results_display.insert("1.0", "Scanning Windows registry...\n\n")
        
        def scan():
            result = self.registry_scanner.generate_report()
            self.last_scan_type = "registry"
            self.last_scan_results = result
            self.root.after(0, lambda: self.results_display.delete("1.0", "end"))
            self.root.after(0, lambda: self.results_display.insert("1.0", result))
        
        threading.Thread(target=scan, daemon=True).start()
    
    def analyze_with_ai(self):
        """Analyze scan results with AI"""
        if not self.last_scan_results:
            messagebox.showinfo("No Results", "Please run a scan first.")
            return
        
        if not self.ollama_client.is_available():
            messagebox.showerror("Ollama Not Available", 
                               "Ollama is not running. Please start Ollama first.")
            return
        
        self.analyze_button.configure(state="disabled", text="Analyzing...")
        
        def analyze():
            analysis = self.security_ai.analyze_scan_results(
                self.last_scan_type, self.last_scan_results
            )
            
            # Add to chat
            self.root.after(0, lambda: self.add_chat_message(
                "System", 
                f"AI Analysis of {self.last_scan_type} scan completed. Check results below."
            ))
            self.root.after(0, lambda: self.add_chat_message("AI Assistant", analysis))
            
            # Also show in results
            full_results = f"{self.last_scan_results}\n\n{'='*60}\nAI ANALYSIS\n{'='*60}\n\n{analysis}"
            self.root.after(0, lambda: self.results_display.delete("1.0", "end"))
            self.root.after(0, lambda: self.results_display.insert("1.0", full_results))
            
            self.root.after(0, lambda: self.analyze_button.configure(state="normal", text="Analyze Results with AI"))
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def save_ollama_url(self):
        """Save Ollama URL"""
        url = self.ollama_url_entry.get().strip()
        self.config.set_ollama_url(url)
        self.ollama_client = OllamaClient(url)
        self.security_ai.client = self.ollama_client
        self.check_ollama_status()
        messagebox.showinfo("Saved", "Ollama URL saved successfully.")
    
    def change_model(self, model: str):
        """Change AI model"""
        self.config.set_ai_model(model)
        self.security_ai.model = model
        self.add_chat_message("System", f"AI model changed to: {model}")
    
    def refresh_models(self):
        """Refresh available models from Ollama"""
        if not self.ollama_client.is_available():
            messagebox.showerror("Error", "Ollama is not available.")
            return
        
        models = self.ollama_client.list_models()
        if models:
            model_names = [m.get('name', '').split(':')[0] for m in models]
            self.model_dropdown.configure(values=model_names)
            messagebox.showinfo("Success", f"Found {len(models)} models.")
        else:
            messagebox.showwarning("No Models", "No models found. Please pull a model first.")
    
    def refresh_log_paths(self):
        """Refresh the log paths display"""
        # Clear existing widgets
        for widget in self.log_paths_frame.winfo_children():
            widget.destroy()
        
        # Add each path
        paths = self.config.get_log_paths()
        if not paths:
            ctk.CTkLabel(self.log_paths_frame, text="No log paths configured").pack(pady=5)
        else:
            for path in paths:
                frame = ctk.CTkFrame(self.log_paths_frame)
                frame.pack(fill="x", pady=2)
                
                ctk.CTkLabel(frame, text=path, anchor="w").pack(side="left", fill="x", expand=True, padx=5)
                ctk.CTkButton(frame, text="Remove", width=70,
                            command=lambda p=path: self.remove_log_path(p)).pack(side="right", padx=5)
    
    def add_log_path(self):
        """Add a log file path"""
        filepath = filedialog.askopenfilename(title="Select log file")
        if filepath:
            self.config.add_log_path(filepath)
            self.refresh_log_paths()
    
    def add_log_directory(self):
        """Add a log directory path"""
        dirpath = filedialog.askdirectory(title="Select log directory")
        if dirpath:
            self.config.add_log_path(dirpath)
            self.refresh_log_paths()
    
    def remove_log_path(self, path: str):
        """Remove a log path"""
        self.config.remove_log_path(path)
        self.refresh_log_paths()
    
    def run(self):
        """Run the application"""
        self.root.mainloop()


def main():
    """Main entry point"""
    app = SecurityAssistantGUI()
    app.run()


if __name__ == "__main__":
    main()
