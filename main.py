import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import time
from datetime import datetime, timedelta
import hashlib
import base64

class RansomwareDemoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Educational Demonstration")
        self.root.geometry("600x1000")
        self.root.configure(bg="#000000")
        
        # Initialize variables
        self.start_time = datetime.now()
        self.total_seconds = 47 * 3600 + 59 * 60 + 54  # 47h 59m 54s
        self.encrypted_files = {}
        self.btc_address = "16KQjht4ePZxxGPr3es24VQyMYgR9UEkFy"
        self.btc_amount = "0.00092"
        self.decryption_key = "DEMO_KEY_12345"
        
        # Create main frame with scrollbar
        self.main_frame = tk.Frame(root, bg="#000000")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create canvas for scrolling
        self.canvas = tk.Canvas(self.main_frame, bg="#000000", highlightthickness=0)
        self.scrollbar = tk.Scrollbar(self.main_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#000000")
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Build UI
        self.build_ui()
        
        # Start timer
        self.update_timer()
    
    def build_ui(self):
        """Build the user interface"""
        
        # Warning banner
        warning_frame = tk.Frame(self.scrollable_frame, bg="#1a1a1a", relief=tk.SOLID, bd=2)
        warning_frame.pack(pady=15, padx=15, fill=tk.X)
        
        warning_label = tk.Label(
            warning_frame,
            text="⚠ EDUCATIONAL DEMONSTRATION ONLY - This is a security awareness\ninterface showing how ransomware screens work. No files are\nencrypted.",
            bg="#1a1a1a",
            fg="#FFD700",
            font=("Courier", 10, "bold"),
            justify=tk.CENTER,
            wraplength=500,
            padx=10,
            pady=10
        )
        warning_label.pack()
        
        # Bitcoin icon and initial message
        bitcoin_label = tk.Label(
            self.scrollable_frame,
            text="₿",
            bg="#000000",
            fg="#FFD700",
            font=("Arial", 60, "bold")
        )
        bitcoin_label.pack(pady=20)
        
        message_label = tk.Label(
            self.scrollable_frame,
            text="Data will be lost after",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 12)
        )
        message_label.pack()
        
        # Main countdown timer
        self.timer_label = tk.Label(
            self.scrollable_frame,
            text="48h",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 48, "bold")
        )
        self.timer_label.pack(pady=10)
        
        # Clock icon and detailed timer
        clock_label = tk.Label(
            self.scrollable_frame,
            text="🕐",
            bg="#000000",
            fg="#FFD700",
            font=("Arial", 40, "bold")
        )
        clock_label.pack(pady=15)
        
        message_label2 = tk.Label(
            self.scrollable_frame,
            text="Data will be lost after",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 12)
        )
        message_label2.pack()
        
        # Detailed countdown
        self.detailed_timer_label = tk.Label(
            self.scrollable_frame,
            text="47h 59m 54s",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 36, "bold")
        )
        self.detailed_timer_label.pack(pady=10)
        
        # Encrypted files count
        files_label = tk.Label(
            self.scrollable_frame,
            text="Numbers of encrypted files",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 11)
        )
        files_label.pack()
        
        self.files_count_label = tk.Label(
            self.scrollable_frame,
            text="N/A",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 28, "bold")
        )
        self.files_count_label.pack(pady=10)
        
        # Bitcoin cost
        cost_label = tk.Label(
            self.scrollable_frame,
            text="The cost of the key for encryption",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 11)
        )
        cost_label.pack()
        
        bitcoin_cost_label = tk.Label(
            self.scrollable_frame,
            text="₿",
            bg="#000000",
            fg="#FFD700",
            font=("Arial", 40, "bold")
        )
        bitcoin_cost_label.pack(pady=10)
        
        cost_amount_label = tk.Label(
            self.scrollable_frame,
            text=f"{self.btc_amount} BTC",
            bg="#000000",
            fg="#00FF00",
            font=("Courier", 20, "bold")
        )
        cost_amount_label.pack(pady=5)
        
        # Main warning box
        warning_box_frame = tk.Frame(self.scrollable_frame, bg="#1a1a1a", relief=tk.SOLID, bd=2)
        warning_box_frame.pack(pady=20, padx=15, fill=tk.X)
        
        warning_title = tk.Label(
            warning_box_frame,
            text="WARNING,",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 14, "bold"),
            justify=tk.LEFT
        )
        warning_title.pack(anchor="w", padx=15, pady=(10, 5))
        
        warning_text = tk.Label(
            warning_box_frame,
            text="Your data has been encrypted, all your personal videos,\nphotos, documents and files have been LOCKED with\nencryption!",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10),
            justify=tk.LEFT,
            wraplength=500
        )
        warning_text.pack(anchor="w", padx=15, pady=5)
        
        do_not_label = tk.Label(
            warning_box_frame,
            text="DO NOT :",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 11, "bold"),
            justify=tk.LEFT
        )
        do_not_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        do_not_text = tk.Label(
            warning_box_frame,
            text="• Close This Screen\n• Uninstall This Application.\n• Power Off This Device.\n• Disconnect Internet Access.",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10),
            justify=tk.LEFT,
            wraplength=500
        )
        do_not_text.pack(anchor="w", padx=15, pady=5)
        
        warning_consequence = tk.Label(
            warning_box_frame,
            text="The one-time decryption key will be deleted if you do not\nfollow these instructions, your files will be LOST\nFOREVER.",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10),
            justify=tk.LEFT,
            wraplength=500
        )
        warning_consequence.pack(anchor="w", padx=15, pady=5)
        
        do_label = tk.Label(
            warning_box_frame,
            text="DO :",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 11, "bold"),
            justify=tk.LEFT
        )
        do_label.pack(anchor="w", padx=15, pady=(10, 5))
        
        do_text = tk.Label(
            warning_box_frame,
            text="• Plug In Your Charger To Stop Any Accidents\n• Pay As Soon As Possible.",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10),
            justify=tk.LEFT,
            wraplength=500
        )
        do_text.pack(anchor="w", padx=15, pady=(5, 10))
        
        # Useful Information section
        info_frame = tk.Frame(self.scrollable_frame, bg="#1a1a1a", relief=tk.SOLID, bd=2)
        info_frame.pack(pady=15, padx=15, fill=tk.X)
        
        info_title = tk.Label(
            info_frame,
            text="Useful Information",
            bg="#1a1a1a",
            fg="#FFD700",
            font=("Courier", 14, "bold")
        )
        info_title.pack(anchor="w", padx=15, pady=(10, 5))
        
        btc_label = tk.Label(
            info_frame,
            text=f"BTC addr: {self.btc_address}",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10),
            wraplength=500,
            justify=tk.LEFT
        )
        btc_label.pack(anchor="w", padx=15, pady=5)
        
        # Copy button
        copy_button = tk.Button(
            info_frame,
            text="📋 COPY",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10, "bold"),
            relief=tk.SOLID,
            bd=1,
            command=self.copy_btc_address,
            padx=10,
            pady=5
        )
        copy_button.pack(anchor="w", padx=15, pady=5)
        
        # Decrypt section
        decrypt_label = tk.Label(
            info_frame,
            text="Decrypt",
            bg="#1a1a1a",
            fg="#FFD700",
            font=("Courier", 14, "bold")
        )
        decrypt_label.pack(anchor="w", padx=15, pady=(15, 5))
        
        key_label = tk.Label(
            info_frame,
            text="Key: paste your key here...",
            bg="#1a1a1a",
            fg="#00FF00",
            font=("Courier", 10)
        )
        key_label.pack(anchor="w", padx=15, pady=5)
        
        # Key input field
        self.key_input = tk.Entry(
            info_frame,
            bg="#0a0a0a",
            fg="#00FF00",
            font=("Courier", 10),
            relief=tk.SOLID,
            bd=1,
            insertbackground="#00FF00"
        )
        self.key_input.pack(anchor="w", padx=15, pady=5, fill=tk.X)
        
        # Decrypt button
        decrypt_button = tk.Button(
            info_frame,
            text="DECRYPT",
            bg="#333333",
            fg="#00FF00",
            font=("Courier", 11, "bold"),
            relief=tk.SOLID,
            bd=1,
            command=self.decrypt_files,
            padx=10,
            pady=8
        )
        decrypt_button.pack(anchor="w", padx=15, pady=(10, 15), fill=tk.X)
        
        # Final warning
        final_warning = tk.Frame(self.scrollable_frame, bg="#330000", relief=tk.SOLID, bd=2)
        final_warning.pack(pady=15, padx=15, fill=tk.X)
        
        final_warning_text = tk.Label(
            final_warning,
            text="Do not delete this APP, or your files will not be\nback forever!!!",
            bg="#330000",
            fg="#FF6666",
            font=("Courier", 11, "bold"),
            justify=tk.CENTER,
            wraplength=500,
            padx=10,
            pady=10
        )
        final_warning_text.pack()
    
    def update_timer(self):
        """Update the countdown timer"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        remaining = max(0, self.total_seconds - elapsed)
        
        hours = int(remaining // 3600)
        minutes = int((remaining % 3600) // 60)
        seconds = int(remaining % 60)
        
        # Update main timer
        if hours > 0:
            self.timer_label.config(text=f"{hours}h")
        else:
            self.timer_label.config(text=f"{minutes}m")
        
        # Update detailed timer
        self.detailed_timer_label.config(text=f"{hours}h {minutes}m {seconds}s")
        
        # Schedule next update
        self.root.after(1000, self.update_timer)
    
    def copy_btc_address(self):
        """Copy BTC address to clipboard"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.btc_address)
            self.root.update()
            messagebox.showinfo("Success", "BTC address copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")
    
    def simulate_encryption(self, data):
        """Simulate file encryption"""
        # Simple base64 encoding as simulation
        return base64.b64encode(data.encode()).decode()
    
    def simulate_decryption(self, encrypted_data, key):
        """Simulate file decryption"""
        try:
            # For demo purposes, check if key matches
            if key == self.decryption_key:
                return base64.b64decode(encrypted_data.encode()).decode()
            else:
                return None
        except:
            return None
    
    def decrypt_files(self):
        """Handle decryption attempt"""
        key = self.key_input.get()
        
        if not key:
            messagebox.showwarning("Warning", "Please enter a decryption key!")
            return
        
        if key == self.decryption_key:
            messagebox.showinfo(
                "Success!",
                f"Decryption key verified!\n\nYour files have been successfully decrypted.\n\nDemo Key Used: {key}"
            )
            self.key_input.delete(0, tk.END)
        else:
            messagebox.showerror(
                "Invalid Key",
                "The decryption key you entered is incorrect.\n\nPlease try again or contact support."
            )

def main():
    root = tk.Tk()
    app = RansomwareDemoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
    
