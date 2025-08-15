import hashlib
import tkinter as tk
from tkinter import ttk, messagebox

def generate_hash():
    password = entry.get()
    hash_type = hash_type_combobox.get().lower()

    if not password:
        messagebox.showerror("Error", "❌ Please enter a password.")
        return
    if hash_type not in ["md5", "sha256"]:
        messagebox.showerror("Error", "❌ Please select a valid hash type (MD5 or SHA256).")
        return

    encoded = password.encode()

    if hash_type == "md5":
        hashed = hashlib.md5(encoded).hexdigest()
    elif hash_type == "sha256":
        hashed = hashlib.sha256(encoded).hexdigest()

    result_label.config(text=f"{hash_type.upper()} Hash:\n{hashed}", foreground="blue")

    # Copy to clipboard
    root.clipboard_clear()
    root.clipboard_append(hashed)
    root.update()
    messagebox.showinfo("Copied", "✅ Hash copied to clipboard!")

# GUI Setup
root = tk.Tk()
root.title("Hash Generator")
root.geometry("500x200")
root.resizable(False, False)

# Title
project_label = ttk.Label(root, text="🔐 Hash Generator", font=("Helvetica", 18, "bold"))
project_label.grid(row=0, column=0, columnspan=2, pady=15)

# Password Label & Entry
label = ttk.Label(root, text="Enter Password:")
label.grid(row=1, column=0, sticky="e", padx=10, pady=5)

entry = ttk.Entry(root, width=40, show="*")
entry.grid(row=1, column=1, sticky="w", pady=5)

# Hash Type Label & Dropdown
hash_type_label = ttk.Label(root, text="Select Hash Type:")
hash_type_label.grid(row=2, column=0, sticky="e", padx=10, pady=5)


hash_type_combobox = ttk.Combobox(root, values=["MD5", "SHA256"], state="readonly", width=37)
hash_type_combobox.current(0)
hash_type_combobox.grid(row=2, column=1, sticky="w", pady=5)

# Generate Button
button = ttk.Button(root, text="Generate Hash", command=generate_hash)
button.grid(row=3, column=0, columnspan=2, pady=15)

# Result Label
result_label = ttk.Label(root, text="Hash will appear here", font=("Courier", 12), foreground="gray", wraplength=750, justify="center")
result_label.grid(row=4, column=0, columnspan=2, pady=15)

root.mainloop()
