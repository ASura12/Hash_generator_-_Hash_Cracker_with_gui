import tkinter as tk
from tkinter import ttk,messagebox
import hashlib

def crack_hash():
    hash = hash_entry.get()
    hash_type = hash_type_combobox.get().lower()
    found = False
    try:
        with open("wordlist.txt","r") as worlist:
            for word in worlist:
                word = word.strip()

                if hash_type == "md5":
                    hashed_word = hashlib.md5(word.encode()).hexdigest()
                elif hash_type == "sha256":
                    hashed_word = hashlib.sha256(word.encode()).hexdigest()
                else:
                    messagebox.showerror("Error","Invalid hash type selected")
                    return
                
                if hashed_word == hash:
                    messagebox.showinfo("Password Found", f"Password is: {word}")
                    found = True
                    break

        if not found:
            messagebox.showwarning("Not Found", "Password not found in wordlist")

    except FileNotFoundError:
        messagebox.showerror("Error", "wordlist.txt file not found!")


# Create GUI window
root= tk.Tk()
root.title("🔓 Hash Cracker")
root.geometry("500x200")

project_label = ttk.Label(root, text="🔓 Hash Cracker", font=("Helvetica", 18, "bold"))
project_label.grid(row=0, column=0, columnspan=3, pady=15)


# Take input
Input_label = ttk.Label(root, text="Enter Hash: ")
Input_label.grid(row=1,column=0,padx=5,pady=5,sticky="w")
hash_entry = ttk.Entry(root,width=50)
hash_entry.grid(row=1,column=1,padx=5,pady=5)

# Hash Type Selection
ttk.Label(root, text="Select Hash Type:").grid(row=2,column=0,padx=5,pady=5,sticky="w")
hash_type_combobox = ttk.Combobox(root,values=["MD5", "SHA256"], state="readonly")
hash_type_combobox.current(0)
hash_type_combobox.grid(row=2,column=1,padx=5,pady=5)

# Crack Button
button = ttk.Button(root,text="Crack",command = crack_hash)
button.grid(row=3,column=1,padx=5,pady=5)


root.mainloop()