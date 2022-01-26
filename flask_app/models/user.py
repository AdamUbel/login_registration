from flask_app.configs.mysqlconnection import connectToMySQL
from flask import flash
from flask_app import app
from flask_bcrypt import Bcrypt
import re

bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$!&*?])[\w\d@#$]{8,16}$')


class Users():

    def __init__(self, data):
        self.id = data['id']
        self.first_name = data["first_name"]
        self.last_name = data["last_name"]
        self.email = data["email"]
        self.password = data["password"]
        self.created_at = data["created_at"]
        self.updated_at = data["updated_at"]

    @classmethod
    def insert_user(cls, data):
        query = """
      INSERT INTO users (first_name, last_name, email, password, created_at, updated_at)
      VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());
      """
        return connectToMySQL("login_schema").query_db(query, data)

    @classmethod
    def user_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s;"
        user_with_email = connectToMySQL("login_schema").query_db(query, data)

        if len(user_with_email) < 1:
            return False
        return cls(user_with_email[0])

    @classmethod
    def user_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        user_by_id = connectToMySQL("login_schema").query_db(query, data)
        print(user_by_id)
        return cls(user_by_id[0])

    @classmethod
    def get_all_users(cls):
        query = "SELECT * FROM users"

        results = connectToMySQL("login_schema").query_db(query)

        users = []
        for row in results:
            users.append(cls(row))

        return users

    @staticmethod
    def validate_register(post_data):
        is_valid = True
        print(post_data)

        if len(post_data["first_name"]) < 3:
            flash("First Name Must Be Longer Then Two Characters", "register")
            is_valid = False

        if len(post_data["last_name"]) < 3:
            flash("Last Name Must Be Longer Then Two Characters", "register")
            is_valid = False

        if not EMAIL_REGEX.match(post_data['email']):
            flash('Please Enter Valid Email', "register")
            is_valid = False

        if not PASSWORD_REGEX.match(post_data['password']):
            flash("Please Enter Valid Password", "register")
            is_valid = False

        if Users.user_by_email({"email": post_data["email"].lower()}):
            flash("Email Already In Use, Please Sign In", "register")
            is_valid = False

        if post_data['password'] != post_data['confirm_password']:
            flash("Passwords Dont Match", "register")
            is_valid = False

        return is_valid

    @staticmethod
    def validate_login(user, input_pw):
        is_valid = True

        print(user, input_pw)
        if not user:
            flash("Invalid Email or Password", "login")
            is_valid = False
            return is_valid

        if not bcrypt.check_password_hash(user.password, input_pw["input_pw"]):
            flash("Invalid Password", "login")
            is_valid = False

        return is_valid
