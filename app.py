from datetime import datetime, timedelta
import os
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from flask_login import LoginManager, login_required, login_user, logout_user
import secrets
from flask_migrate import Migrate



from db import db
from form import LoginForm
from forms import Logins
from model import ResetPasswordToken, User, OTPToken, db
from werkzeug.security import check_password_hash, generate_password_hash
from utils import generate_random_otp
from flask_mail import Mail, Message




from dotenv import load_dotenv

load_dotenv() 




MAX_ATTEMPTS = 5
LOCK_MINUTES = 5





app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = 'warning'
migrate = Migrate(app, db)



app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DB_URL")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("DEFAULT_EMAIL")
app.config['MAIL_PASSWORD'] = os.getenv("GMAIL_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("DEFAULT_EMAIL")

mail = Mail(app)


OTP_LIFESPAN_MINUTES = 10







db.init_app(app=app)


@app.route('/')
def index():
    return render_template("index.html")



@app.route('/register' ,methods=['GET', 'POST'])
def register():
    form = Logins()

    
    if form.validate_on_submit():
        email = form.email.data.lower()
        name = form.full_name.data
        password = form.password.data

        user = User(email=email, username=name, password=generate_password_hash(password))
        _new_otp = generate_random_otp(5)
        token = OTPToken(
            token = _new_otp,
            expires_at = datetime.now() + timedelta(minutes=OTP_LIFESPAN_MINUTES),
            user = user
        )

        db.session.add_all([user, token])
        db.session.commit()
        msg = Message(
            subject=f"Verifiy Account: Your OTP is {_new_otp}",
            body=f"Welcome\nYour OTP is {token.token} ",
            recipients=[user.email]
        )
        
        html_text = render_template("email/verify-email.html", username=user.username, otp=token.token)

        msg.html = html_text
        mail.send(msg)

    
        session['user_being_verified'] = user.id

        flash ("Sign up success.", category="success")

        return redirect(url_for('verify_otp'))

    return render_template("register.html", form=form)








MAX_ATTEMPTS = 5
LOCK_MINUTES = 5


@app.route("/login", methods=['GET', 'POST'])
def login():

    form = LoginForm()

    if form.validate_on_submit():

        email = form.email.data.lower()
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        
        if user is None:

            flash("Invalid email", category="danger")

            return redirect(url_for('login'))

        # CHECK IF ACCOUNT IS LOCKED
        if user.locked_until:

            if datetime.utcnow() < user.locked_until:

                flash(
                    "Too many failed attempts. Try again in 5 minutes.",
                    category="danger"
                )

                return redirect(url_for('login'))

            else:
                # UNLOCK ACCOUNT
                user.failed_attempts = 0
                user.locked_until = None

                db.session.commit()

        # CHECK PASSWORD
        if check_password_hash(user.password, password):

            # RESET FAILED ATTEMPTS
            user.failed_attempts = 0
            user.locked_until = None

            db.session.commit()

            login_user(user)

            flash("Login successful", category="success")

            return redirect(url_for('dashboard'))

        else:

            # FIX NONE ERROR
            if user.failed_attempts is None:
                user.failed_attempts = 0

            # INCREASE FAILED ATTEMPTS
            user.failed_attempts += 1

            # LOCK ACCOUNT
            if user.failed_attempts >= MAX_ATTEMPTS:

                user.locked_until = (
                    datetime.utcnow() + timedelta(minutes=LOCK_MINUTES)
                )

                flash(
                    "Account locked for 5 minutes",
                    category="danger"
                )

            else:

                remaining = MAX_ATTEMPTS - user.failed_attempts

                flash(
                    f"Invalid password. {remaining} attempts left.",
                    category="warning"
                )

            db.session.commit()

            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.get('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout out successful" ,category="success")
    return redirect(url_for('login'))




@app.route("/verify-otp", methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        token =request.form.get('token')
        user_id = session.get('user_being_verified')
        if user_id is None:
            flash("Invalid request", category="danger")
            return abort(400)
        user = User.query.get(user_id)
        otp_token = OTPToken.query.filter_by(token=token, user_id=user_id).first()
        if otp_token:
            # IF TOKEN HAS NOT EXPIRED
            if not otp_token.is_used and otp_token.expires_at > datetime.now():
                otp_token.user.is_verified = True
                otp_token.is_used = True

                db.session.add(otp_token)
                db.session.commit()
                
                session.pop("user_being_verified")
                flash("OTP is verified", category="session")
                login_user(user)
                return redirect(url_for("login"))
            
            
            flash("Token has been used or expired", category="danger")
            return render_template("verify-otp.html")
        flash("Invalid OTP token", category="danger")

    return render_template("verify-otp.html")



@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/forget-password" , methods=['POST', 'GET'])
def forget_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            _new_otp = generate_random_otp(5)
            token = ResetPasswordToken(
                token = _new_otp,
                expires_at = datetime.now() + timedelta(minutes=OTP_LIFESPAN_MINUTES),
                user = user
            )
            db.session.add_all([ token])
            db.session.commit()
            msg = Message(
                subject=f"Verify  reset password : Your OTP is {_new_otp}",
                body=f"Welcome\nYour password reset OTP is {token.token} ",
                recipients=[user.email]
            )
            html_text = render_template("email/reset-password.html", username=user.username, otp=token.token)

            msg.html = html_text
            mail.send(msg)
            session['user_being_verified'] = user.id

            flash("OTP has been sent to your email. Please check your inbox.", "success")
            return redirect(url_for('forget_password_verify_otp'))    
            
        else:
            flash("Email not found","danger")

    return render_template("forget-password-otp.html")


@app.route("/forget-password-otp-verification", methods=['POST', 'GET'])
def forget_password_verify_otp():
    if request.method == 'POST':
        token = request.form.get('token')
        user_id = session.get('user_being_verified')
        print("DEBUG USER ID:", user_id)
        print("DEBUG TOKEN:", token)
        if user_id is None:
            flash("Invalid request", category="danger")
            abort(400)
        user = User.query.get(user_id)
        reset_password_token = ResetPasswordToken.query.filter_by(token=token, user_id=user_id).first()
        print("ALL TOKENS FOR USER:", reset_password_token)
        if reset_password_token:
            # IF TOKEN HAS NOT EXPIRED
            if not reset_password_token.is_used and reset_password_token.expires_at > datetime.now():
                
                reset_password_token.is_used = True

                db.session.add(reset_password_token)
                db.session.commit()
                
                session.pop("user_being_verified")
                session['reset_email'] = reset_password_token.user.email
                flash("Reset Password OTP verify", category="success")
                
                return redirect(url_for("new_reset_password"))
            
            
            flash("Reset password Token has been used or expired", category="danger")
            return render_template("forget-password-verify-otp.html")
        flash("Invalid OTP token", category="danger")
       

    return render_template("forget-password-verify-otp.html")



@app.route("/new-reset-password", methods=['POST', 'GET'])
def new_reset_password():
    if request.method == "POST":
        new_password = request.form.get("password")

        user = User.query.filter_by(email=session.get("reset_email")).first()

        if user:
            user.password = generate_password_hash(new_password)

            db.session.commit()

            flash("Password successfully changed. You can now login.", "success")
            return redirect(url_for("login"))

    return render_template("new-reset-password.html")





            

        
    

@login_manager.user_loader
def get_user(pk):
    return User.query.filter_by(id=int(pk)).first()


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)