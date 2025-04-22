import tempfile
import os
import yara
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog, ttk
from datetime import datetime
import shutil

# Default YARA rule - expanded with more patterns
DEFAULT_YARA_RULE = '''
rule DetectSuspiciousPatterns{
    meta:
        description = "Detects common suspicious commands and indicators"
        author = "Louis Kraimer"
        severity = "high"
        date = "2025-04-22"

    strings:
        $a = "powershell" nocase
        $b = "curl" nocase
        $c = "cmd.exe" nocase
        $d = "wget" nocase
        $e = "base64" nocase
        $f = "net user" nocase
        $g = "/wp-admin" nocase
        $h = "/phpmyadmin" nocase
        $i = ".env" nocase
        $j = "' OR '1'='1" nocase
        $k = "--" 
        $l = "&&"
        $m = "||"
        $n = "$("
        $o = "exec(" nocase
        $p = "system(" nocase
        $q = "eval(" nocase
        $r = "<script>" nocase
        $s = "document.cookie" nocase
        $t = "fetch(" nocase

    condition:
        any of them
}
'''

# Expanded identifier lookup for new patterns
IDENTIFIER_LOOKUP = {
    "$a": "powershell (command shell)",
    "$b": "curl (data transfer)",
    "$c": "cmd.exe (command shell)",
    "$d": "wget (download utility)",
    "$e": "base64 (encoding)",
    "$f": "net user (user management)",
    "$g": "/wp-admin (WordPress admin)",
    "$h": "/phpmyadmin (database admin)",
    "$i": ".env (environment file)",
    "$j": "SQL Injection attempt",
    "$k": "-- (SQL comment)",
    "$l": "command injection: &&",
    "$m": "command injection: ||",
    "$n": "command injection: $(",
    "$o": "exec() (code execution)",
    "$p": "system() (command execution)",
    "$q": "eval() (code execution)",
    "$r": "<script> (JavaScript tag)",
    "$s": "document.cookie (cookie access)",
    "$t": "fetch() (web request)"
}


class YaraRuleEditor:
    def __init__(self, parent, current_rule, on_save_callback):
        self.parent = parent
        self.editor_window = tk.Toplevel(parent)
        self.editor_window.title("YARA Rule Editor")
        self.editor_window.geometry("800x600")
        self.on_save_callback = on_save_callback

        # Add editor components
        tk.Label(self.editor_window, text="Edit YARA Rule", font=("Arial", 14, "bold")).pack(pady=10)

        # Rule editor textbox
        self.rule_editor = scrolledtext.ScrolledText(self.editor_window, height=25, width=90,
                                                     font=("Consolas", 11),
                                                     bg="#1E1E1E", fg="#DCDCDC")
        self.rule_editor.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.rule_editor.insert(tk.END, current_rule)

        # Buttons frame
        btn_frame = tk.Frame(self.editor_window)
        btn_frame.pack(pady=10)

        # Test rule button
        self.test_btn = tk.Button(btn_frame, text="Test Rule", command=self.test_rule,
                                  bg="#333333", fg="#FFFFFF",
                                  font=("Arial", 11))
        self.test_btn.pack(side=tk.LEFT, padx=5)

        # Save button
        self.save_btn = tk.Button(btn_frame, text="Save Rule", command=self.save_rule,
                                  bg="#228B22", fg="#FFFFFF",
                                  font=("Arial", 11))
        self.save_btn.pack(side=tk.LEFT, padx=5)

        # Cancel button
        self.cancel_btn = tk.Button(btn_frame, text="Cancel", command=self.editor_window.destroy,
                                    bg="#8B0000", fg="#FFFFFF",
                                    font=("Arial", 11))
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = tk.Label(self.editor_window, text="", font=("Arial", 10))
        self.status_label.pack(pady=5)

    def test_rule(self):
        """Test if the YARA rule syntax is valid"""
        rule_content = self.rule_editor.get("1.0", tk.END)
        try:
            with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
                f.write(rule_content)
                test_rule_path = f.name

            # Try to compile the rule
            yara.compile(filepath=test_rule_path)
            self.status_label.config(text="Rule syntax is valid!", fg="green")

            # Clean up temp file
            os.unlink(test_rule_path)
        except Exception as e:
            self.status_label.config(text=f"Error in rule syntax: {str(e)}", fg="red")

    def save_rule(self):
        """Save the edited rule and close the editor"""
        rule_content = self.rule_editor.get("1.0", tk.END)
        try:
            # Validate rule before saving
            with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
                f.write(rule_content)
                test_rule_path = f.name

            yara.compile(filepath=test_rule_path)
            os.unlink(test_rule_path)

            # Call the callback with the new rule
            self.on_save_callback(rule_content)
            self.editor_window.destroy()
        except Exception as e:
            messagebox.showerror("Rule Syntax Error",
                                 f"Cannot save rule - syntax error: {str(e)}")


class EnhancedYaraScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced YARA Security Scanner")
        self.root.geometry("950x700")

        # Set the theme colors
        self.bg_color = "#2b2b2b"  # Dark background
        self.fg_color = "#e0e0e0"  # Light text
        self.accent_color = "#39FF14"  # Neon green accent
        self.accent_color2 = "#00FFCC"  # Cyan accent
        self.highlight_color = "#404040"  # Lighter dark for contrast

        self.root.configure(bg=self.bg_color)

        # Variables
        self.folder_path = ""
        self.quarantine_path = ""
        self.yara_rule_content = DEFAULT_YARA_RULE
        self.yara_rule_path = ""
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.scan_count = 0
        self.match_count = 0

        # Compile initial YARA rule
        self._compile_yara_rule()

        # Create UI structure
        self._create_header()
        self._create_notebook()
        self._create_footer()

    def _create_header(self):
        """Create the app header with title and main controls"""
        header_frame = tk.Frame(self.root, bg=self.bg_color, pady=10)
        header_frame.pack(fill=tk.X)

        # App title
        title_label = tk.Label(header_frame, text="Advanced YARA Security Scanner",
                               font=("Arial", 16, "bold"),
                               bg=self.bg_color, fg=self.accent_color)
        title_label.pack()

        # Subtitle
        subtitle_label = tk.Label(header_frame,
                                  text="Detect malicious patterns in text files",
                                  font=("Arial", 10),
                                  bg=self.bg_color, fg=self.fg_color)
        subtitle_label.pack(pady=5)

    def _create_notebook(self):
        """Create tabbed interface for the app"""
        # Create notebook (tabs container)
        self.notebook = ttk.Notebook(self.root)

        # Configure notebook style
        self.style = ttk.Style()
        self.style.theme_use('default')
        self.style.configure("TNotebook", background=self.bg_color, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=self.highlight_color,
                             foreground=self.fg_color, padding=[10, 2])
        self.style.map("TNotebook.Tab", background=[("selected", self.bg_color)])

        # Configure Results notebook style
        self.style.configure("Results.TNotebook", background=self.bg_color)

        # Create tabs
        self.scan_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.settings_tab = tk.Frame(self.notebook, bg=self.bg_color)
        self.about_tab = tk.Frame(self.notebook, bg=self.bg_color)

        # Add tabs to notebook
        self.notebook.add(self.scan_tab, text="Scanner")
        self.notebook.add(self.settings_tab, text="Settings")
        self.notebook.add(self.about_tab, text="About")
        self.notebook.pack(expand=1, fill="both", padx=10, pady=5)

        # Build tab contents
        self._build_scan_tab()
        self._build_settings_tab()
        self._build_about_tab()

    def _build_scan_tab(self):
        """Build the main scanner tab contents"""
        # Control panel frame
        control_frame = tk.Frame(self.scan_tab, bg=self.bg_color, pady=10)
        control_frame.pack(fill=tk.X)

        # Create button styles
        button_style = {
            "bg": self.highlight_color,
            "fg": self.accent_color,
            "activebackground": "#111111",
            "activeforeground": self.accent_color2,
            "font": ("Arial", 11),
            "relief": "ridge",
            "bd": 2,
            "padx": 10,
            "pady": 5
        }

        # Folder selection
        folder_frame = tk.Frame(control_frame, bg=self.bg_color)
        folder_frame.pack(pady=5, fill=tk.X)

        tk.Label(folder_frame, text="Scan Folder:", bg=self.bg_color, fg=self.fg_color).pack(side=tk.LEFT, padx=5)

        self.folder_path_var = tk.StringVar()
        folder_entry = tk.Entry(folder_frame, textvariable=self.folder_path_var, width=50,
                                bg=self.highlight_color, fg=self.fg_color, insertbackground=self.accent_color)
        folder_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        select_btn = tk.Button(folder_frame, text="Select Folder", command=self.select_folder, **button_style)
        select_btn.pack(side=tk.LEFT, padx=5)

        # Action buttons
        action_frame = tk.Frame(control_frame, bg=self.bg_color)
        action_frame.pack(pady=10, fill=tk.X)

        # Status display
        self.status_var = tk.StringVar(value="Ready to scan")
        status_label = tk.Label(action_frame, textvariable=self.status_var,
                                bg=self.bg_color, fg=self.accent_color2,
                                font=("Arial", 10))
        status_label.pack(side=tk.LEFT, padx=10)

        # Scan button
        self.scan_btn = tk.Button(action_frame, text="Start Scan", command=self.start_scan,
                                  **button_style, width=12)
        self.scan_btn.pack(side=tk.RIGHT, padx=5)

        # Export button (initially disabled)
        self.export_btn = tk.Button(action_frame, text="Export Report", command=self.export_report,
                                    **button_style, width=12, state=tk.DISABLED)
        self.export_btn.pack(side=tk.RIGHT, padx=5)

        # Quarantine button (initially disabled)
        self.quarantine_btn = tk.Button(action_frame, text="Quarantine Files", command=self.quarantine_files,
                                        **button_style, width=12, state=tk.DISABLED)
        self.quarantine_btn.pack(side=tk.RIGHT, padx=5)

        # Results notebook
        results_notebook = ttk.Notebook(self.scan_tab)
        self.style.configure("Results.TNotebook", background=self.bg_color)

        # Results tabs
        self.output_tab = tk.Frame(results_notebook, bg=self.bg_color)
        self.summary_tab = tk.Frame(results_notebook, bg=self.bg_color)

        results_notebook.add(self.output_tab, text="Scan Results")
        results_notebook.add(self.summary_tab, text="Scan Summary")
        results_notebook.pack(expand=1, fill="both", padx=5, pady=5)

        # Results output
        self.output = scrolledtext.ScrolledText(self.output_tab, height=25, width=110,
                                                font=("Consolas", 10), state='disabled',
                                                bg="#111111", fg=self.accent_color2,
                                                insertbackground=self.accent_color)
        self.output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Summary output
        self.summary_output = scrolledtext.ScrolledText(self.summary_tab, height=25, width=110,
                                                        font=("Arial", 10), state='disabled',
                                                        bg="#111111", fg=self.accent_color2,
                                                        insertbackground=self.accent_color)
        self.summary_output.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

    def _build_settings_tab(self):
        """Build the settings tab contents"""
        settings_frame = tk.Frame(self.settings_tab, bg=self.bg_color, padx=20, pady=20)
        settings_frame.pack(fill=tk.BOTH, expand=True)

        # YARA Rule Settings
        rule_frame = tk.LabelFrame(settings_frame, text="YARA Rule Settings",
                                   font=("Arial", 11, "bold"),
                                   bg=self.bg_color, fg=self.accent_color, pady=10, padx=10)
        rule_frame.pack(fill=tk.X, pady=10)

        edit_rule_btn = tk.Button(rule_frame, text="Edit YARA Rule", command=self.open_rule_editor,
                                  bg=self.highlight_color, fg=self.fg_color,
                                  activebackground="#111111", activeforeground=self.accent_color2,
                                  font=("Arial", 11))
        edit_rule_btn.pack(pady=5)

        reset_rule_btn = tk.Button(rule_frame, text="Reset to Default Rule", command=self.reset_yara_rule,
                                   bg=self.highlight_color, fg=self.fg_color,
                                   activebackground="#111111", activeforeground=self.accent_color2,
                                   font=("Arial", 11))
        reset_rule_btn.pack(pady=5)

        # Quarantine Settings
        quarantine_frame = tk.LabelFrame(settings_frame, text="Quarantine Settings",
                                         font=("Arial", 11, "bold"),
                                         bg=self.bg_color, fg=self.accent_color, pady=10, padx=10)
        quarantine_frame.pack(fill=tk.X, pady=10)

        quarantine_path_frame = tk.Frame(quarantine_frame, bg=self.bg_color)
        quarantine_path_frame.pack(fill=tk.X, pady=5)

        tk.Label(quarantine_path_frame, text="Quarantine Folder:",
                 bg=self.bg_color, fg=self.fg_color).pack(side=tk.LEFT, padx=5)

        self.quarantine_path_var = tk.StringVar()
        quarantine_entry = tk.Entry(quarantine_path_frame, textvariable=self.quarantine_path_var,
                                    width=40, bg=self.highlight_color, fg=self.fg_color,
                                    insertbackground=self.accent_color)
        quarantine_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        select_quarantine_btn = tk.Button(quarantine_path_frame, text="Select Folder",
                                          command=self.select_quarantine_folder,
                                          bg=self.highlight_color, fg=self.fg_color,
                                          activebackground="#111111", activeforeground=self.accent_color2,
                                          font=("Arial", 11))
        select_quarantine_btn.pack(side=tk.LEFT, padx=5)

    def _build_about_tab(self):
        """Build the about tab contents"""
        about_frame = tk.Frame(self.about_tab, bg=self.bg_color, padx=20, pady=20)
        about_frame.pack(fill=tk.BOTH, expand=True)

        # App information
        app_info = """
        Advanced YARA Security Scanner v1.0

        This application scans text files for potentially malicious patterns using YARA rules.

        Features:
        • Scan folders for suspicious text files
        • Customizable YARA rules for pattern matching
        • Quarantine suspicious files
        • Export scan reports

        Technologies:
        • Python
        • Tkinter GUI Framework
        • YARA Pattern Matching (yara-python)

        Created: April 2025
        """

        about_label = tk.Label(about_frame, text=app_info, justify=tk.LEFT,
                               bg=self.bg_color, fg=self.fg_color,
                               font=("Arial", 11))
        about_label.pack(pady=20)

    def _create_footer(self):
        """Create the app footer"""
        footer_frame = tk.Frame(self.root, bg=self.bg_color, pady=5)
        footer_frame.pack(fill=tk.X)

        footer_label = tk.Label(footer_frame, text="© 2025 Louis Kraimer",
                                bg=self.bg_color, fg=self.fg_color,
                                font=("Arial", 8))
        footer_label.pack(side=tk.RIGHT, padx=10)

    def _compile_yara_rule(self):
        """Compile the current YARA rule and save to a temporary file"""
        try:
            # Delete previous rule file if exists
            if self.yara_rule_path and os.path.exists(self.yara_rule_path):
                os.unlink(self.yara_rule_path)

            # Write new rule to temporary file
            with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
                f.write(self.yara_rule_content)
                self.yara_rule_path = f.name

            # Compile the rule
            self.rule = yara.compile(filepath=self.yara_rule_path)

            # Update status
            if hasattr(self, 'status_var'):
                self.status_var.set("YARA rule compiled successfully")

            return True
        except Exception as e:
            if hasattr(self, 'status_var'):
                self.status_var.set(f"Error compiling YARA rule: {str(e)}")
            messagebox.showerror("YARA Rule Error", f"Error compiling YARA rule: {str(e)}")
            return False

    def select_folder(self):
        """Select a folder to scan"""
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path = folder
            self.folder_path_var.set(folder)
            self.status_var.set(f"Selected folder: {folder}")

    def select_quarantine_folder(self):
        """Select a folder for quarantined files"""
        folder = filedialog.askdirectory()
        if folder:
            self.quarantine_path = folder
            self.quarantine_path_var.set(folder)
            self.status_var.set(f"Quarantine folder: {folder}")

    def open_rule_editor(self):
        """Open the YARA rule editor"""
        YaraRuleEditor(self.root, self.yara_rule_content, self.update_yara_rule)

    def update_yara_rule(self, new_rule_content):
        """Update the YARA rule with new content"""
        self.yara_rule_content = new_rule_content
        success = self._compile_yara_rule()
        if success:
            messagebox.showinfo("YARA Rule Updated", "YARA rule has been updated successfully.")

    def reset_yara_rule(self):
        """Reset the YARA rule to default"""
        if messagebox.askyesno("Reset Rule", "Reset YARA rule to default?"):
            self.yara_rule_content = DEFAULT_YARA_RULE
            self._compile_yara_rule()
            messagebox.showinfo("YARA Rule Reset", "YARA rule has been reset to default.")

    def start_scan(self):
        """Start scanning the selected folder"""
        if not self.folder_path:
            messagebox.showwarning("No Folder Selected", "Please select a folder to scan.")
            return

        # Reset counters and results
        self.results = []
        self.scan_count = 0
        self.match_count = 0

        # Disable buttons during scan
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Scanning in progress...")
        self.root.update()

        # Clear output
        self.output.config(state="normal")
        self.output.delete('1.0', tk.END)
        self.output.insert(tk.END, f"Scanning folder: {self.folder_path}\n\n")
        self.output.config(state="disabled")

        # Clear summary
        self.summary_output.config(state="normal")
        self.summary_output.delete('1.0', tk.END)
        self.summary_output.config(state="disabled")

        # Record start time
        self.scan_start_time = datetime.now()

        # Perform the scan
        self.results = self.scan_folder(self.folder_path)

        # Record end time
        self.scan_end_time = datetime.now()

        # Update output with results
        self.output.config(state="normal")
        if not self.results:
            self.output.insert(tk.END, "No matches found.\n")
        else:
            matched_files = set()
            for path, details in self.results:
                matched_files.add(path)
                self.output.insert(tk.END, f"File: {path}\n")
                for d in details:
                    self.output.insert(tk.END, f"  -> {d}\n")
                self.output.insert(tk.END, "-" * 80 + "\n")

            self.match_count = len(matched_files)

        self.output.config(state="disabled")

        # Update scan summary
        self.update_scan_summary()

        # Re-enable buttons
        self.scan_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.NORMAL)

        # Enable quarantine button if quarantine path is set
        if self.quarantine_path and self.results:
            self.quarantine_btn.config(state=tk.NORMAL)

        self.status_var.set(f"Scan completed. Found {self.match_count} suspicious files.")

        # Show notification
        messagebox.showinfo("Scan Complete",
                            f"Scan completed successfully.\nFound {self.match_count} suspicious files.")

    def scan_folder(self, folder_path):
        """Scan a folder for suspicious .txt files"""
        findings = []

        for root, _, files in os.walk(folder_path):
            for f in files:
                if f.lower().endswith(".txt"):
                    file_path = os.path.join(root, f)
                    try:
                        self.scan_count += 1
                        self.status_var.set(f"Scanning: {file_path}")
                        self.root.update()

                        matches = self.rule.match(filepath=file_path)
                        if matches:
                            match_details = []
                            for m in matches:
                                for s in m.strings:
                                    try:
                                        identifier = s.identifier
                                        pattern_name = IDENTIFIER_LOOKUP.get(identifier, 'unknown')
                                        if not any(pattern_name in detail for detail in match_details):
                                            match_details.append(f"Detection: {pattern_name}")
                                    except Exception as inner_e:
                                        match_details.append(f"Error reading match: {str(inner_e)}")

                            if match_details:
                                findings.append((file_path, match_details))
                    except Exception as e:
                        findings.append((file_path, [f"Error scanning file: {str(e)}"]))

        return findings

    def update_scan_summary(self):
        """Update the scan summary tab with results"""
        if not hasattr(self, 'scan_start_time') or not self.scan_start_time:
            return

        self.summary_output.config(state="normal")
        self.summary_output.delete('1.0', tk.END)

        # Calculate scan duration
        duration = self.scan_end_time - self.scan_start_time
        duration_str = str(duration).split('.')[0]  # Remove microseconds

        # Build summary
        summary = f"""
        SCAN SUMMARY
        {'-' * 50}

        Scan Start Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}
        Scan End Time: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}
        Duration: {duration_str}

        Files Scanned: {self.scan_count}
        Suspicious Files Detected: {self.match_count}

        Scan Location: {self.folder_path}
        """

        if self.match_count > 0:
            # Count all unique patterns found
            pattern_counts = {}
            for _, details in self.results:
                for detail in details:
                    if detail.startswith("Detection:"):
                        pattern = detail.split(":", 1)[1].strip()
                        pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

            summary += f"\n{'DETECTED PATTERNS COUNT':^50}\n"
            summary += f"{'-' * 50}\n"

            for pattern, count in sorted(pattern_counts.items(), key=lambda x: x[1], reverse=True):
                summary += f"{pattern}: {count}\n"

        self.summary_output.insert(tk.END, summary)
        self.summary_output.config(state="disabled")

    def export_report(self):
        """Export the scan results to a text file"""
        if not self.results and not hasattr(self, 'scan_start_time'):
            messagebox.showwarning("No Results", "No scan results to export.")
            return

        # Ask for save location
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )

        if not file_path:
            return

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                # Write header
                f.write("===================================================\n")
                f.write("           YARA SECURITY SCANNER REPORT             \n")
                f.write("===================================================\n\n")

                # Write summary
                if hasattr(self, 'scan_start_time') and self.scan_start_time:
                    duration = self.scan_end_time - self.scan_start_time
                    duration_str = str(duration).split('.')[0]

                    f.write(f"Scan Start Time: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Scan End Time: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Duration: {duration_str}\n")
                    f.write(f"Files Scanned: {self.scan_count}\n")
                    f.write(f"Suspicious Files Detected: {self.match_count}\n")
                    f.write(f"Scan Location: {self.folder_path}\n\n")

                # Write YARA rule used
                f.write("YARA Rule Used:\n")
                f.write("---------------------------------------------------\n")
                f.write(f"{self.yara_rule_content}\n\n")

                # Write detailed results
                f.write("SCAN RESULTS:\n")
                f.write("---------------------------------------------------\n")

                if not self.results:
                    f.write("No suspicious patterns detected.\n")
                else:
                    for path, details in self.results:
                        f.write(f"File: {path}\n")
                        for d in details:
                            # Replace arrow symbol with plain text to avoid encoding issues
                            detail_text = d.replace("→", "->")
                            f.write(f"  {detail_text}\n")
                        f.write("-" * 50 + "\n")

            messagebox.showinfo("Export Complete", f"Report saved to:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting report: {str(e)}")

            messagebox.showinfo("Export Complete", f"Report saved to:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting report: {str(e)}")

    def quarantine_files(self):
        """Move suspicious files to quarantine folder"""
        if not self.quarantine_path:
            # Ask for quarantine folder if not set
            self.select_quarantine_folder()
            if not self.quarantine_path:
                return

        if not self.results:
            messagebox.showinfo("Quarantine", "No suspicious files to quarantine.")
            return

        # Confirm before quarantining
        if not messagebox.askyesno("Confirm Quarantine",
                                   "Are you sure you want to move all suspicious files to quarantine?"):
            return

        # Create quarantine folder if it doesn't exist
        os.makedirs(self.quarantine_path, exist_ok=True)

        # Create a subfolder with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_subfolder = os.path.join(self.quarantine_path, f"quarantine_{timestamp}")
        os.makedirs(quarantine_subfolder, exist_ok=True)

        # Move files to quarantine
        moved_count = 0
        failed_count = 0

        for path, _ in self.results:
            try:
                # Create file metadata
                file_name = os.path.basename(path)
                quarantine_path = os.path.join(quarantine_subfolder, file_name)

                # If file with same name exists, add a number
                if os.path.exists(quarantine_path):
                    base, ext = os.path.splitext(file_name)
                    counter = 1
                    while os.path.exists(quarantine_path):
                        quarantine_path = os.path.join(
                            quarantine_subfolder, f"{base}_{counter}{ext}")
                        counter += 1

                # Copy file to quarantine
                shutil.copy2(path, quarantine_path)

                # Create metadata file
                with open(f"{quarantine_path}.meta", "w") as meta_file:
                    meta_file.write(f"Original path: {path}\n")
                    meta_file.write(f"Quarantined: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    meta_file.write(f"Detected patterns:\n")

                    # Find details for this file
                    for p, details in self.results:
                        if p == path:
                            for d in details:
                                meta_file.write(f"  - {d}\n")

                # Move original file
                shutil.move(path, quarantine_path)
                moved_count += 1

            except Exception as e:
                failed_count += 1
                self.output.config(state="normal")
                self.output.insert(tk.END, f"Error quarantining {path}: {str(e)}\n")
                self.output.config(state="disabled")

        # Update status
        self.status_var.set(f"Quarantined {moved_count} files. {failed_count} failed.")

        # Show notification
        if failed_count == 0:
            messagebox.showinfo("Quarantine Complete",
                                f"Successfully quarantined {moved_count} files to:\n{quarantine_subfolder}")
        else:
            messagebox.showwarning("Quarantine Partial",
                                   f"Quarantined {moved_count} files, but {failed_count} failed. See log for details.")

        # Disable quarantine button
        self.quarantine_btn.config(state=tk.DISABLED)


# Main application
if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedYaraScannerApp(root)
    # Center window on screen
    window_width = 950
    window_height = 700
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_coordinate = int((screen_width / 2) - (window_width / 2))
    y_coordinate = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")
    root.mainloop()