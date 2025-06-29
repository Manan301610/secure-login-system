# 🔐 Secure Login System with User Role Management

A secure and modern login system built using **Flask**, **MongoDB**, and **HTML/CSS**, featuring:

- User Registration & Login
- Role-based Access Control (Admin/User)
- OTP Email Verification
- Google reCAPTCHA Integration
- Password Hashing (bcrypt)
- JWT/Session-based Authentication

---

## 🚀 Features

✅ Secure User Registration  
✅ User Login with bcrypt password verification  
✅ Email-based OTP verification  
✅ Admin/User Role Management  
✅ Google reCAPTCHA to prevent bot attacks  
✅ Session/Token-based authentication  
✅ MongoDB for user storage  
✅ Frontend built using HTML & CSS  
✅ Environment variable support via `.env` (secrets are protected)  

---


---

## 🔧 Technologies Used

- 🐍 Python (Flask)
- ☁️ MongoDB Atlas
- 🔐 bcrypt for hashing passwords
- 📩 Flask-Mail for sending OTP
- 🔐 Google reCAPTCHA
- 🌍 HTML/CSS for frontend

---

## 🛡️ Security Highlights

- **Password Hashing:** User passwords are stored using bcrypt.
- **OTP Verification:** One-Time Password sent via email for user verification.
- **reCAPTCHA:** Protects against bots.
- **Environment Variables:** Secrets stored securely using a `.env` file.
- **Session/Token Authentication:** Secures access to protected routes.
- **Role Management:** Admin vs. User privileges.

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/secure-login-system.git
cd secure-login-system

Install all Dependencies
pip install -r requirements.txt

Run the Flask App
python app.py
