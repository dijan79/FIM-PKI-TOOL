from pki_manager import PKIManager
from signer import Signer
from monitor import FileMonitor
import time

# Initialize components
pki = PKIManager()
signer = Signer(pki)
monitor = FileMonitor(signer)

def main():
    print("=== File Integrity Monitoring System with PKI ===")
    
    while True:
        print("\nOptions:")
        print("1. Register New User")
        print("2. Revoke User Certificate")
        print("3. Register File for Integrity Monitoring")
        print("4. Start Continuous Monitoring")
        print("5. Exit")

        choice = input("Select option: ")

        if choice == '1':
            username = input("Enter username: ")
            pki.register_user(username)
        elif choice == '2':
            username = input("Enter username to revoke: ")
            pki.revoke_certificate(username)
        elif choice == '3':
            username = input("Enter username: ")
            filepath = input("Enter full file path to monitor: ")
            monitor.register_file(username, filepath)
        elif choice == '4':
            monitor.start_monitoring()
        elif choice == '5':
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()