import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog

class SimpleUI:
    def __init__(self, root, dghv):
        self.dghv = dghv  # Pass the DGHV encryption object from the main file
        self.encrypted_values = []  # List to store encrypted values

        self.root = root
        self.root.title("Simple DGHV Encryption UI")

        # Create UI components
        self.label = tk.Label(root, text="DGHV Homomorphic Encryption")
        self.label.pack()

        # Display the key 'p' (the secret key) in the UI
        self.key_label = tk.Label(root, text=f"Secret Key (p): {self.dghv.p}")
        self.key_label.pack()

        # Button to encrypt a bit message
        self.encrypt_button = tk.Button(root, text="Encrypt a bit message", command=self.encrypt_message)
        self.encrypt_button.pack()

        # Button to decrypt a ciphertext
        self.decrypt_button = tk.Button(root, text="Decrypt a ciphertext", command=self.decrypt_message)
        self.decrypt_button.pack()

        # Button to perform homomorphic addition
        self.add_button = tk.Button(root, text="Add two ciphertexts", command=self.add_ciphertexts)
        self.add_button.pack()

        # Button to perform homomorphic multiplication
        self.multiply_button = tk.Button(root, text="Multiply two ciphertexts", command=self.multiply_ciphertexts)
        self.multiply_button.pack()

        # Button to perform 2-bit full adder
        self.full_adder_button = tk.Button(root, text="2-bit adder", command=self.perform_full_adder)
        self.full_adder_button.pack()

        # Listbox to display encrypted values
        self.encrypted_listbox_label = tk.Label(root, text="Encrypted values (select for operations):")
        self.encrypted_listbox_label.pack()

        # Enable multiple selection mode in Listbox
        self.encrypted_listbox = tk.Listbox(root, selectmode=tk.MULTIPLE)
        self.encrypted_listbox.pack()

    def encrypt_message(self):
        """Encrypt a bit message (0 or 1) entered by the user."""
        bit_message = simpledialog.askinteger("Input", "Enter bit message (0 or 1):", minvalue=0, maxvalue=1)
        if bit_message is not None:
            ciphertext = self.dghv.encrypt(bit_message)
            self.encrypted_values.append(ciphertext)
            self.encrypted_listbox.insert(tk.END, ciphertext)
            messagebox.showinfo("Encryption", f"Encrypted ciphertext: {ciphertext}")

    def decrypt_message(self):
        """Decrypt the selected ciphertext."""
        selected = self.encrypted_listbox.curselection()
        if selected:
            ciphertext = self.encrypted_values[selected[0]]
            decrypted_message = self.dghv.decrypt(ciphertext)
            messagebox.showinfo("Decryption", f"Decrypted message: {decrypted_message}")
        else:
            messagebox.showinfo("Information", "No ciphertext selected.")

    def add_ciphertexts(self):
        """Perform homomorphic addition on two selected ciphertexts."""
        selected = self.encrypted_listbox.curselection()
        if len(selected) == 2:
            c1 = self.encrypted_values[selected[0]]
            c2 = self.encrypted_values[selected[1]]
            result_ciphertext = c1 + c2
            decrypted_result = self.dghv.decrypt(result_ciphertext)
            messagebox.showinfo("Addition", f"Decrypted result of addition: {decrypted_result}")
        else:
            messagebox.showinfo("Information", "Please select exactly two ciphertexts for addition.")

    def multiply_ciphertexts(self):
        """Perform homomorphic multiplication on two selected ciphertexts."""
        selected = self.encrypted_listbox.curselection()
        if len(selected) == 2:
            c1 = self.encrypted_values[selected[0]]
            c2 = self.encrypted_values[selected[1]]
            result_ciphertext = c1 * c2
            decrypted_result = self.dghv.decrypt(result_ciphertext)
            messagebox.showinfo("Multiplication", f"Decrypted result of multiplication: {decrypted_result}")
        else:
            messagebox.showinfo("Information", "Please select exactly two ciphertexts for multiplication.")

    def perform_full_adder(self):
        """Perform a 2-bit full adder."""
        # Create a dialog to ask the user for two 2-bit binary numbers
        input_values = simpledialog.askstring("Input", "Enter two 2-bit binary numbers (e.g., 01 11):")
        if input_values:
            try:
                a, b = input_values.split()
                bit_a1, bit_a0 = int(a[0]), int(a[1])
                bit_b1, bit_b0 = int(b[0]), int(b[1])
                
                # Perform the full adder operation
                c_bit_a0 = self.dghv.encrypt(bit_a0)
                c_bit_a1 = self.dghv.encrypt(bit_a1)
                c_bit_b0 = self.dghv.encrypt(bit_b0)
                c_bit_b1 = self.dghv.encrypt(bit_b1)

                z0_add = c_bit_a0 + c_bit_b0
                z0_carry = c_bit_a0 * c_bit_b0
                z1_add = c_bit_a1 + c_bit_b1 + z0_carry
                z1_carry = (c_bit_a1 * c_bit_b1) + (c_bit_a1 * z0_carry) + (c_bit_b1 * z0_carry)

                z0 = self.dghv.decrypt(z0_add)
                z1 = self.dghv.decrypt(z1_add)
                z2 = self.dghv.decrypt(z1_carry)

                # Show the intermediate ciphertexts and the final decrypted result
                messagebox.showinfo(
                    "2-bit Adder",
                    f"Encrypted bits:\n"
                    f"a0: {c_bit_a0}, a1: {c_bit_a1}\n"
                    f"b0: {c_bit_b0}, b1: {c_bit_b1}\n"
                    f"Intermediate Results:\n"
                    f"z0_add: {z0_add}, z0_carry: {z0_carry}\n"
                    f"z1_add: {z1_add}, z1_carry: {z1_carry}\n"
                    f"Final decrypted result: {z2} {z1} {z0}"
                )
            except (ValueError, IndexError):
                messagebox.showinfo("Error", "Invalid input. Please enter two valid 2-bit binary numbers (e.g., 01 11).")
        else:
            messagebox.showinfo("Information", "No input provided.")
