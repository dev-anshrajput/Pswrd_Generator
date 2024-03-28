import tkinter as tk
import random
import string
import pyperclip

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Password Generator")

        self.length_label = tk.Label(master, text="Length:")
        self.length_label.grid(row=0, column=0, sticky=tk.W)
        self.length_entry = tk.Entry(master)
        self.length_entry.grid(row=0, column=1)

        self.complexity_label = tk.Label(master, text="Complexity:")
        self.complexity_label.grid(row=1, column=0, sticky=tk.W)
        self.complexity_var = tk.StringVar(value="Medium")
        self.complexity_menu = tk.OptionMenu(master, self.complexity_var, "Low", "Medium", "High")
        self.complexity_menu.grid(row=1, column=1)

        self.rule_label = tk.Label(master, text="Security Rules:")
        self.rule_label.grid(row=2, column=0, sticky=tk.W)
        self.rule_upper = tk.BooleanVar()
        self.rule_upper_check = tk.Checkbutton(master, text="Uppercase", variable=self.rule_upper)
        self.rule_upper_check.grid(row=2, column=1, sticky=tk.W)
        self.rule_lower = tk.BooleanVar()
        self.rule_lower_check = tk.Checkbutton(master, text="Lowercase", variable=self.rule_lower)
        self.rule_lower_check.grid(row=3, column=1, sticky=tk.W)
        self.rule_digits = tk.BooleanVar()
        self.rule_digits_check = tk.Checkbutton(master, text="Digits", variable=self.rule_digits)
        self.rule_digits_check.grid(row=4, column=1, sticky=tk.W)
        self.rule_symbols = tk.BooleanVar()
        self.rule_symbols_check = tk.Checkbutton(master, text="Symbols", variable=self.rule_symbols)
        self.rule_symbols_check.grid(row=5, column=1, sticky=tk.W)

        self.generate_button = tk.Button(master, text="Generate", command=self.generate_password)
        self.generate_button.grid(row=6, columnspan=2)

        self.password_label = tk.Label(master, text="Password:")
        self.password_label.grid(row=7, column=0, sticky=tk.W)
        self.password_entry = tk.Entry(master, state='readonly')
        self.password_entry.grid(row=7, column=1)

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.grid(row=8, columnspan=2)

    def generate_password(self):
        length = int(self.length_entry.get())
        complexity = self.complexity_var.get()
        rules = {'Upper': self.rule_upper.get(), 'Lower': self.rule_lower.get(), 'Digits': self.rule_digits.get(), 'Symbols': self.rule_symbols.get()}
        
        if complexity == "Low":
            chars = string.ascii_lowercase + string.digits
        elif complexity == "Medium":
            chars = string.ascii_letters + string.digits
        else:
            chars = string.ascii_letters + string.digits + string.punctuation
        
        if all(rule == False for rule in rules.values()):
            tk.messagebox.showerror("Error", "Please select at least one security rule.")
            return
        
        if rules['Upper']:
            chars += string.ascii_uppercase
        if rules['Lower']:
            chars += string.ascii_lowercase
        if rules['Digits']:
            chars += string.digits
        if rules['Symbols']:
            chars += string.punctuation

        password = ''.join(random.choice(chars) for _ in range(length))
        self.password_entry.config(state='normal')
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.password_entry.config(state='readonly')

    def copy_to_clipboard(self):
        password = self.password_entry.get()
        pyperclip.copy(password)
        tk.messagebox.showinfo("Info", "Password copied to clipboard.")

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
