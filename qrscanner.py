import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import json
import serial
import time
import base64
from datetime import datetime
from Crypto.Cipher import AES
import hashlib

class QRDecryptManager:
    def __init__(self, port='/dev/tty.usbmodemAPP_0000000001', secret_key='abcdefghijklmnop'):
        # Initialize Firebase
        cred = credentials.Certificate("credentials.json")
        firebase_admin.initialize_app(cred)
        self.db = firestore.client()
        
        # Initialize serial connection
        self.ser = serial.Serial(
            port=port,
            baudrate=9600,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=1
        )
        
        # Convert the secret key to bytes
        self.key = secret_key.encode('utf-8')
        # Fixed IV (must match the one in React Native)
        self.iv = b'1234567890123456'

    def decrypt_data(self, encrypted_data):
        """
        Decrypt data that was encrypted with CryptoJS.AES.encrypt using CBC mode
        """
        try:
            # Remove any whitespace and newline characters
            encrypted_data = encrypted_data.strip()
            
            # Decode base64
            try:
                encrypted_bytes = base64.b64decode(encrypted_data)
                print(f"Base64 decoded successfully, length: {len(encrypted_bytes)} bytes")
            except Exception as e:
                print(f"Base64 decoding failed: {e}")
                return None

            # Create cipher and decrypt
            cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            padded_data = cipher.decrypt(encrypted_bytes)
            
            # Remove PKCS7 padding
            padding_length = padded_data[-1]
            if padding_length > 16:
                raise ValueError("Invalid padding")
            decrypted_data = padded_data[:-padding_length]
            
            # Convert to string and parse JSON
            decrypted_str = decrypted_data.decode('utf-8')
            print(f"Decrypted string: {decrypted_str[:100]}...")
            
            return json.loads(decrypted_str)

        except Exception as e:
            print(f"Decryption process failed: {e}")
            print(f"Full error details: {str(e)}")
            return None

    def save_to_firebase(self, data):
        """
        Save the decrypted data to Firebase
        """
        for entry in data:
            passport_no = entry["passport_no"]
            try:
                data_to_save = {
                    **entry,
                    'timestamp': datetime.now(),
                    'scan_status': 'success'
                }
            
                doc_ref = self.db.collection("gates").document("sal1").collection("users").document(passport_no)
                doc_ref.set(data_to_save)
                print(f"Data saved to Firebase with ID: {doc_ref.id}")
                
            except Exception as e:
                print(f"Firebase save failed: {e}")
                return False
        return True

    def run(self):
        """
        Main loop to read QR codes, decrypt data, and save to Firebase
        """
        print(f"Starting QR code reading loop...")
        print("Using fixed IV for decryption")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                if self.ser.in_waiting:
                    raw_data = self.ser.readline().decode(errors='ignore').strip()
                    
                    if raw_data:
                        print("\n=== New QR Code Scanned ===")
                        print(f"Raw data length: {len(raw_data)}")
                        print(f"Raw data preview: {raw_data[:100]}...")
                        
                        decrypted_data = self.decrypt_data(raw_data)
                        
                        if decrypted_data:
                            print("Decryption successful!")
                            print(f"Decrypted data: {json.dumps(decrypted_data, indent=2)}")
                            
                            if self.save_to_firebase(decrypted_data):
                                print("Successfully saved to Firebase")
                            else:
                                print("Failed to save to Firebase")
                        else:
                            print("Decryption failed")
                
                time.sleep(0.1)

        except KeyboardInterrupt:
            print("\nProgram interrupted by user")
        finally:
            self.ser.close()
            print("Serial connection closed")

if __name__ == "__main__":
    # Initialize and run
    manager = QRDecryptManager(
        port='/dev/tty.usbmodemAPP_0000000001',  # Update with your port
        secret_key='abcdefghijklmnop'  # Must match the key used in React Native
    )
    manager.run()