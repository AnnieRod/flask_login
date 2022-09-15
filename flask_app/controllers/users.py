from flask import request, redirect, render_template,session, flash

from flask_app import app

from flask_app.models.user import User

from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

##Home
@app.route("/")
def start_form():
    if 'user_id' not in session:
        flash("please log to enter", "login")
        return redirect("/")

    return render_template("index.html")


## Crea usuario con las validaciones necesarias
@app.route("/process", methods = ['POST'])
def create_user():
    if not User.validate_user(request.form):
        return redirect("/")

    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'email': request.form['email'],
        'password': pw_hash
    }

    user_id = User.save_user(data)
    session['user_id'] = user_id 
    return redirect("/success")

#Ruta para login, comapra correo y pass
@app.route ("/login", methods = ['POST'])
def login_user():
    data = {
        "email" : request.form["email"]
    }
    user_db = User.get_login(data)
    if not user_db:
        flash("Invalid mail/password", "login")
        return redirect("/")

    if not bcrypt.check_password_hash(user_db[0]["password"], request.form['password']):
        flash("Invalid mail/password", "login")
        return redirect("/")
    
    session['user_id'] = user_db[0]["first_name"]
    return redirect("/success")

@app.route("/success")
def main_page():
    if 'user_id' not in session:
        return redirect("/logout")
    
    data = {
        "id" : session['user_id']
    }
    return render_template("main.html", user = User.get_user(data))

##logout
@app.route('/logout') ##fallo con logout, redirige muchas veces y se cae sistema
def logout():
    session.clear()
    return redirect('/')