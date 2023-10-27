# Secure-File-Sharing

- This project aims to develop a secure file-sharing system using asymmetric key encryption and authentication. The system is built using the Flask framework in Python, with the Crypto libraries utilized for encryption and decryption. The project also involves the use of an SQLite database for storing user credentials and file metadata.
- The system requires users to register and log in to access the shared files. Upon login, a unique private and public key pair is generated for each user, with the private key stored securely in the database. The public key is shared with other users to allow for encrypted file sharing.
- All files uploaded to the system are encrypted using the recipient's public key and stored in the database with the necessary metadata, such as the sender, recipient, and timestamp. The file is decrypted upon download using the recipient's private key, ensuring confidentiality and data integrity.
- Additionally, the system provides authentication measures to prevent unauthorized access to files, such as password protection and two-factor authentication. Overall, the system provides a secure and efficient way for users to share files with confidentiality and integrity while maintaining the integrity of user data using a robust database.

### The stepwise breakdown of working involves:
#### Step 1: Signup
- User signs up to the platform with their email and password
- The platform generates a pair of public and private keys for the user
#### Step 2: Sharing Message or Files
- User selects the message or file they want to share with another user
- User enters the email address of the recipient
#### Step 3: Encryption
- The platform uses the recipient's public key to encrypt the message or file
- The encrypted data is then sent to the recipient
#### Step 4: Decryption
- The recipient uses their private key to decrypt the message or file
- The decrypted data is then displayed to the recipient
#### Step 5: Viewing Chat History
- User can view their chat history with a particular recipient
- All messages and files sent between the two users are displayed
#### Step 6: Downloading
- User can download any files shared between them and the recipient
- The downloaded files are decrypted using the user's private key

## Screenshot
![image](https://github.com/Jenis08/Secure-File-Sharing/assets/84531789/08ee5142-3e60-4f6e-9e9d-3b85226f6009)

