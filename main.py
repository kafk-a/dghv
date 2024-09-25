import random
from Cryptodome.Util.number import getPrime
import sys
from tkinter import Tk
from ui import SimpleUI

# Fix for Python's integer size limit (Python 3.11+)
sys.set_int_max_str_digits(10000)

class DGHV:
    def __init__(self):
        """
        Initialize the public key encryption parameters for the DGHV scheme.
        rho: Noise parameter (bit-length of the noise).
        eta: Bit-length of the secret key (prime number p).
        gam: Bit-length of the modulus for encryption (public key size).
        """
        # self.rho = rho
        # self.eta = eta
        # self.gam = gam
        
        # Generate the secret key
        self.p = random.randrange(10000,20000,1)

        print(f"Secret key (p): {self.p}")

    def encrypt(self, m):
        """
        Encrypt the message m (must be 0 or 1) using public parameters.
        m: The message to encrypt (must be 0 or 1).
        """
        if m not in [0, 1]:
            raise ValueError("Message must be 0 or 1.")

        # Noise is a small random integer
        noise = random.randrange(1,10,2)

        # Random large integer q
        q = random.randint(10000, 20000)

        # Ciphertext is generated as c = p * q + 2 * noise + m
        ciphertext = self.p * q + 2 * noise + m
        return ciphertext

    def decrypt(self, c):
        """
        Decrypt the ciphertext c to retrieve the original bit message (0 or 1).
        """
        # Decrypt by reducing modulo p, then taking mod 2 to get the original bit
        return (c % self.p) % 2

    def full_adder(self, bit_a0, bit_a1, bit_b0, bit_b1):
            """
            Perform a 2-bit full adder operation on two binary numbers using homomorphic encryption.
            bit_a0, bit_a1: Bits of the first binary number.
            bit_b0, bit_b1: Bits of the second binary number.
            """
            # Encrypt each bit
            c_bit_a0 = self.encrypt(bit_a0)
            c_bit_a1 = self.encrypt(bit_a1)
            c_bit_b0 = self.encrypt(bit_b0)
            c_bit_b1 = self.encrypt(bit_b1)

            # Perform full adder operations
            # z0_add = a0 + b0 (sum for the least significant bit)
            z0_add = c_bit_a0 + c_bit_b0

            # z0_carry = a0 * b0 (carry for the least significant bit)
            z0_carry = c_bit_a0 * c_bit_b0

            # z1_add = a1 + b1 + z0_carry (sum for the second bit)
            z1_add = c_bit_a1 + c_bit_b1 + z0_carry

            # z1_carry = a1 * b1 + (a1 * z0_carry) + (b1 * z0_carry) (carry out)
            z1_carry = (c_bit_a1 * c_bit_b1) + (c_bit_a1 * z0_carry) + (c_bit_b1 * z0_carry)

            # Decrypt results
            z0 = self.decrypt(z0_add)  # Sum bit 0
            z1 = self.decrypt(z1_add)  # Sum bit 1
            z2 = self.decrypt(z1_carry)  # Carry out

            # Print encrypted values and decrypted results
            print("\nEncrypted bits:")
            print(f"c_bit_a0: {c_bit_a0}")
            print(f"c_bit_a1: {c_bit_a1}")
            print(f"c_bit_b0: {c_bit_b0}")
            print(f"c_bit_b1: {c_bit_b1}")

            print("\nDecrypted results of the addition:")
            print(f"z2 (carry out): {z2}")
            print(f"z1 (sum bit 1): {z1}")
            print(f"z0 (sum bit 0): {z0}")

            # Return the final result as a tuple (z2, z1, z0)
            return z2, z1, z0
    
# Main function for user interaction
def main():
    # Set the encryption parameters for DGHV
    # rho, eta, gam = 2, 16, 64  # Adjust parameters as needed
    dghv = DGHV()

    while True:
        print("\nWhat would you like to do?")
        print("1. Encrypt a bit message (0 or 1)")
        print("2. Decrypt a ciphertext")
        print("3. Add two ciphertexts (homomorphic addition)")
        print("4. Multiply two ciphertexts (homomorphic multiplication)")
        print("5. 2-bit adder")
        print("6. Exit")
        
        choice = input("Enter your choice (1-6): ")

        if choice == '1':
            message = int(input("Enter the bit message (0 or 1) to encrypt: "))
            ciphertext = dghv.encrypt(message)
            print(f"Encrypted ciphertext: {ciphertext}")

        elif choice == '2':
            ciphertext = int(input("Enter the ciphertext to decrypt: "))
            decrypted_message = dghv.decrypt(ciphertext)
            print(f"Decrypted message: {decrypted_message}")

        elif choice == '3':
            c1 = int(input("Enter the first ciphertext: "))
            c2 = int(input("Enter the second ciphertext: "))
            result_ciphertext = c1+c2
            print(f"Resulting ciphertext after addition: {result_ciphertext}")
            decrypted_result = dghv.decrypt(result_ciphertext)
            print(f"Decrypted result of addition: {decrypted_result}")

        elif choice == '4':
            c1 = int(input("Enter the first ciphertext: "))
            c2 = int(input("Enter the second ciphertext: "))
            result_ciphertext = c1*c2
            print(f"Resulting ciphertext after multiplication: {result_ciphertext}")
            decrypted_result = dghv.decrypt(result_ciphertext)
            print(f"Decrypted result of multiplication: {decrypted_result}")
       
        elif choice == '5':
            bit_a1 = int(input("Enter the first bit (a1) of the first 2-bit number: "))
            bit_a0 = int(input("Enter the second bit (a0) of the first 2-bit number: "))
            bit_b1 = int(input("Enter the first bit (b1) of the second 2-bit number: "))
            bit_b0 = int(input("Enter the second bit (b0) of the second 2-bit number: "))
            
            result = dghv.full_adder(bit_a0, bit_a1, bit_b0, bit_b1)
            print(f"Final result (decrypted): {result[0]} {result[1]} {result[2]}")
        elif choice == '6':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

def main():
    """Launch the Tkinter UI."""
    root = Tk()  # Create the Tkinter root window
    dghv = DGHV()  # Create an instance of the DGHV encryption scheme
    app = SimpleUI(root, dghv)  # Launch the UI with the DGHV object
    root.mainloop()  # Start the Tkinter main loop

if __name__ == "__main__":
    main()