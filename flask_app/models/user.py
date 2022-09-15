from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
from flask_app import app
import re

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


class User:
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']
    
    @classmethod
    def save_user(cls, data):
        query = "INSERT INTO users(first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
        new_user = connectToMySQL('login_base').query_db(query, data)
        return new_user

    ##Recupera info de user para nombre en la main
    @classmethod
    def get_user(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        result = connectToMySQL('login_base').query_db(query, data)
        return cls(result[0])
    
    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results = connectToMySQL("login_base").query_db(query)
        users = []
        for user in results:
            users.append( cls(user))
        return users

    ##revisa si correo coincide para iniciar sesión
    @classmethod
    def get_login(cls, data):
        query = "SELECT * FROM users WHERE email =%(email)s;"
        result = connectToMySQL("login_base").query_db(query,data)
        if len(result) < 1:
            return False
        return cls(result[0])

    
    @staticmethod
    def validate_user(user):
        is_valid = True
        if len(user["first_name"]) < 2:   ##pendiente que solo sea letras
            flash("Name must be at least 2 characters long.", "register")
            is_valid = False
        if len(user["last_name"]) < 2:   ##pendiente que solo sea letras
            flash("Name must be at least 2 characters long.", "register")
            is_valid = False
        ##Valida que el correo no este registrado ya
        query = "SELECT * FROM users WHERE email = %(email)s;"
        coincidence = connectToMySQL('login_base').query_db(query, user)
        if len(coincidence) >= 1:
            flash ("Invalid email, already registered...", "register")
            is_valid = False
            return is_valid
        if not EMAIL_REGEX.match(user['email']):
            flash("Email is not valid!", "register")
            is_valid = False
        if len(user["password"]) < 8: 
            flash("Password must be at least 8 characters long.", "register")
            is_valid = False
        if user["password"] != user['confirm_password']:
            flash("Password doesn't match", "register")
            is_valid = False
        else:        ##este podria ir en controllers pero para dejar la logica en un solo lado lo pongo acá
            flash("User created, thank you! :)", "register")
            is_valid = True
        return is_valid