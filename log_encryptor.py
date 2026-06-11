from cryptography.fernet import Fernet
import os

KEY_FILE = "logkey.key"
ENC_FILE = "monitor.enc"

# Step 1: Generate & save AES key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    print("🔑 AES key generated and saved!")

# Step 2: Load AES key
def load_key():
    if not os.path.exists(KEY_FILE):
        print("❌ Key file not found. Please generate one.")
        return None
    with open(KEY_FILE, 'rb') as f:
        return f.read()

# Step 3: Encrypt text and write to monitor.enc
def encrypt_log(text):
    key = load_key()
    if key:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode())
        with open(ENC_FILE, 'ab') as f:
            f.write(encrypted + b'\n')

# Step 4: Decrypt and view log
def decrypt_log():
    key = load_key()
    if key:
        fernet = Fernet(key)
        with open(ENC_FILE, 'rb') as f:
            lines = f.readlines()
            for line in lines:
                try:
                    decrypted = fernet.decrypt(line.strip())
                    print(decrypted.decode())
                except Exception as e:
                    print("❌ Failed to decrypt line:", e)

# Step 5: Simple menu system
if __name__ == "__main__":
    print("\n=== Log Encryptor ===")
    print("1. 🔐 Generate New Key")
    print("2. 🔓 Decrypt and Read Logs")
    choice = input("👉 Choose option (1 or 2): ").strip()

    if choice == "1":
        generate_key()
    elif choice == "2":
        decrypt_log()
    else:
        print("❌ Invalid choice.")
