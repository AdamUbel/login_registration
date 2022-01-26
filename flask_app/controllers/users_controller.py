from flask_app.models import user
from flask_app import app
from flask import render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)


@app.route('/')
def home():
    if "uuid" in session:
        return redirect("/homepage")

    return render_template("index.html")


@app.route("/homepage")
def homepage():

    if "uuid" not in session:
        return redirect("/")

    return render_template("home.html", current_user=user.Users.user_by_id({"id": session["uuid"]}), users=user.Users.get_all_users())


@app.route('/verify-register', methods=["POST"])
def verify_register():

    if not user.Users.validate_register(request.form):
        return redirect('/')

    hashed_pw = bcrypt.generate_password_hash(request.form["password"])

    user_data = {
        **request.form,
        "password": hashed_pw,
        "email": request.form["email"].lower()
    }

    session["uuid"] = user.Users.insert_user(user_data)
    return redirect("/")


@app.route("/verify-login", methods=["POST"])
def verify_login():
    user_check = user.Users.user_by_email({"email": request.form["email"]})

    if not user.Users.validate_login(user_check, {"input_pw": request.form["password"]}):
        return redirect("/")

    session["uuid"] = user_check.id
    flash("Logged In Successfully", "logged-in")
    return redirect("/homepage")


@app.route('/logout')
def logout():
    session.clear()
    return redirect("/")
