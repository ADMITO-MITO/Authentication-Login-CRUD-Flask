from flask import Flask, render_template, jsonify, request
from models.user import User
from flask_login import LoginManager, login_user, current_user
app = Flask(__name__)
app.config['SECRET_KEY'] = "Your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'


from database import db
login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
#view login
login_manager.login_view = 'login'
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)


@app.route('/login', methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #login
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
                login_user(user)
                print(current_user.is_authenticated)
                return jsonify({"message": "Autenticação realizada com sucesso"})


    return jsonify({"message": "Credenciais invalidas"}), 400

if __name__ == "__main__":
    app.run(debug=True)
