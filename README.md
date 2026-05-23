# 🛡️ CHAKRAVYUH - Secure Military File Transfer System
![Military Grade](https://img.shields.io/badge/Security-Military--Grade-success) ![Encryption](https://img.shields.io/badge/Encryption-AES--256-blue) ![Stack](https://img.shields.io/badge/Stack-MERN-green)

**CHAKRAVYUH** is an advanced, classified cyber-defense web application built to simulate a high-security military file transfer network for the Indian Army. It features a cinematic, glassmorphic UI paired with actual backend cryptographic file encryption to ensure payload secrecy.

## ✨ Core Features
*   **Physical Payload Encryption:** Uploaded files are immediately encrypted on the backend server's hard drive using `crypto` AES-256. They cannot be read locally without the system.
*   **Role-Based Dashboards:** Distinct interfaces for system Operators (Admins) and standard Military Personnel based on specific unit credentials.
*   **Auto-Destruct Protocols:** Files can be flagged for one-time downloads or time-based expiry, automatically scrubbing themselves from the servers when triggered.
*   **Threat Monitoring System:** The system logs all brute-force attempts and suspicious activities, actively locking out IPs after multiple failed access attempts.

## 🛠️ Technology Stack
*   **Frontend:** React.js, Vite, Tailwind CSS, Framer Motion
*   **Backend:** Node.js, Express.js, Custom JSON Persistence DB, bcryptjs, jsonwebtoken
*   **Cryptography:** Native Node `crypto` AES-256-CBC, JWT Session Tokens

## 🚀 How to Run Locally

1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/chakravyuh.git
