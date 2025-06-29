# =========================================
# Flask Secure Login System (Clean Version)
# =========================================

from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from pymongo import MongoClient
from datetime import datetime, timedelta
from bson.objectid import ObjectId
import bcrypt
import requests
import random

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-mail@gmail.com'
app.config['MAIL_PASSWORD'] = '16 digit mail password'
app.config['MAIL_DEFAULT_SENDER'] = 'your-mail@gmail.com'

mail = Mail(app)


# MongoDB Atlas Setup
client = MongoClient("mongodb+srv://username:password@secure-login.apvgkcs.mongodb.net/?retryWrites=true&w=majority&appName=secure-login")
db = client["secure_login"]
users = db["users"]


# Serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# reCAPTCHA Config
RECAPTCHA_SECRET = "SECRET_KEY"

def verify_recaptcha(response_token):
    payload = {'secret': RECAPTCHA_SECRET, 'response': response_token}
    r = requests.post("https://www.google.com/recaptcha/api/siteverify", data=payload)
    return r.json().get('success', False)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            flash("reCAPTCHA failed.", "danger")
            return redirect(url_for('register'))

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        if users.find_one({'email': email}):
            flash("User already exists.", "danger")
            return redirect(url_for('register'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        users.insert_one({
            'username': username,
            'email': email,
            'password': hashed_pw,
            'role': role,
            'verified': False,
            'security_question': security_question,
            'security_answer': security_answer.lower()
        })

        token = serializer.dumps(email, salt='email-confirm')
        confirm_url = url_for('verify_email', token=token, _external=True)

        msg = Message('Confirm your account', recipients=[email])
        msg.body = f'Click the link to verify your account: {confirm_url}'
        mail.send(msg)

        flash("Check your email to verify your account.", "info")
        return redirect(url_for('login'))

    return render_template("register.html")

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
        user = users.find_one({'email': email})
        if user:
            users.update_one({'email': email}, {'$set': {'verified': True}})
            flash("Email verified successfully!", "success")
    except:
        flash("Verification link is invalid or expired.", "danger")
    return redirect(url_for('login'))
from datetime import datetime, timedelta

@app.route('/login', methods=['GET', 'POST'])
def login():
    lockout_remaining = 0

    if request.method == 'POST':
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            flash("reCAPTCHA failed.", "danger")
            return redirect(url_for('login'))

        email = request.form['email']
        password = request.form['password']
        user = users.find_one({'email': email})

        if not user:
            flash("Invalid email or password.", "danger")
            return redirect(url_for('login'))

        # Check if account is locked
        lockout_time = user.get('lockout_time')
        if lockout_time and datetime.utcnow() < lockout_time:
            lockout_remaining = int((lockout_time - datetime.utcnow()).total_seconds())
            remaining_minutes = lockout_remaining // 60
            flash(f"Account is locked. Try again in {remaining_minutes} minute(s).", "danger")
            return render_template("login.html", lockout_remaining=lockout_remaining)

        # Reset lockout if expired
        if lockout_time and datetime.utcnow() >= lockout_time:
            users.update_one({'email': email}, {'$set': {'failed_attempts': 0, 'lockout_time': None}})

        # Check password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            attempts = user.get('failed_attempts', 0) + 1
            update_fields = {'failed_attempts': attempts}

            if attempts >= 3:
                update_fields['lockout_time'] = datetime.utcnow() + timedelta(minutes=5)
                flash("Too many failed attempts. Account locked for 5 minutes.", "danger")
            else:
                flash("Incorrect password.", "danger")

            users.update_one({'email': email}, {'$set': update_fields})
            return render_template("login.html", lockout_remaining=lockout_remaining)

        # Successful login
        if not user.get('verified'):
            flash("Please verify your email before logging in.", "warning")
            return redirect(url_for('login'))

        users.update_one({'email': email}, {'$set': {'failed_attempts': 0, 'lockout_time': None}})
        otp = str(random.randint(100000, 999999))
        session['otp'] = otp
        session['temp_user'] = user['email']

        msg = Message("Your OTP", recipients=[email])
        msg.body = f"Your OTP is: {otp}"
        mail.send(msg)

        flash("Enter the OTP sent to your email.", "info")
        return redirect(url_for('verify_otp'))

    return render_template("login.html", lockout_remaining=lockout_remaining)


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_entered = request.form['otp']
        if otp_entered == session.get('otp'):
            user = users.find_one({'email': session['temp_user']})
            session.clear()
            session['user'] = {
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
            flash("Logged in successfully!", "success")
            return redirect(url_for('admin_dashboard' if user['role'] == 'Admin' else 'user_dashboard'))
        else:
            flash("Incorrect OTP.", "danger")
            return redirect(url_for('verify_otp'))

    return render_template("verify_otp.html")
@app.route('/resend_otp')
def resend_otp():
    if 'temp_user' not in session:
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for('login'))

    email = session['temp_user']
    otp = str(random.randint(100000, 999999))
    session['otp'] = otp

    msg = Message("Your OTP (Resent)", recipients=[email])
    msg.body = f"Your new OTP is: {otp}"
    mail.send(msg)

    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for('verify_otp'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users.find_one({'email': email})
        if user:
            session['reset_email'] = email
            return redirect(url_for('security_question'))
        else:
            flash("Email not found.", "danger")
            return redirect(url_for('forgot_password'))
    return render_template("forgot_password.html")

@app.route('/security_question', methods=['GET', 'POST'])
def security_question():
    email = session.get('reset_email')
    if not email:
        flash("Session expired. Try again.", "danger")
        return redirect(url_for('forgot_password'))

    user = users.find_one({'email': email})
    question = user['security_question']

    if request.method == 'POST':
        answer = request.form['security_answer'].lower()
        if answer == user['security_answer']:
            return redirect(url_for('reset_password'))
        else:
            flash("Incorrect answer.", "danger")
            return redirect(url_for('security_question'))

    return render_template("security_question.html", question=question)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        flash("Session expired. Try again.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        users.update_one({'email': email}, {'$set': {'password': hashed_pw}})
        flash("Password reset successfully.", "success")
        session.pop('reset_email', None)
        return redirect(url_for('login'))

    return render_template("reset_password.html")


@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user' not  in session or session['user']['role'] == 'Admin':
        all_users = list(users.find())
        return render_template('admin_dashboard.html', user=session['user'], users=all_users)
    flash("Access Denied", "danger")
    return redirect(url_for('login'))

@app.route('/admin/update_role/<user_id>', methods=['POST'])
def update_role(user_id):
    if 'user' in session and session['user']['role'] == 'Admin':
        new_role = request.form['role']
        users.update_one({'_id': ObjectId(user_id)}, {'$set': {'role': new_role}})
        flash("User role updated.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    if 'user' in session and session['user']['role'] == 'Admin':
        users.delete_one({'_id': ObjectId(user_id)})
        flash("User deleted successfully.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_lock/<user_id>')
def reset_lock(user_id):
    if 'user' in session and session['user']['role'] == 'Admin':
        users.update_one({'_id': ObjectId(user_id)}, {'$set': {'failed_attempts': 0, 'lockout_time': None}})
        flash("User lockout reset.", "success")
    return redirect(url_for('admin_dashboard'))


@app.route('/user_dashboard')
def user_dashboard():
    if 'user' in session and session['user']['role'] == 'User':
        return render_template('user_dashboard.html', user=session['user'])
    flash("Access Denied", "danger")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
