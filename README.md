# Secure Medical Data Transmission Model

A Python/Flask web application designed for the secure transmission of medical reports between authorized doctors.

## Key Features
- **Confidentiality:** Uses AES encryption to protect medical data.
- **Secure Key Exchange:** Uses RSA-2048 to protect the AES session key during exchange.
- **Steganography:** Utilizes DWT-based steganography to embed encrypted payloads inside generated medical-themed cover images.
- **Integrity:** Implements SHA-256 hashing to verify data integrity and detect tampering.
- **Database:** Uses SQLite for data management.

## Technologies Used
* **Backend:** Python, Flask
* **Security:** AES, RSA, SHA-256, DWT (Discrete Wavelet Transform)
* **Frontend:** HTML, CSS, JavaScript
* **Database:** SQLite
