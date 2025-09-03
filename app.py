from flask import Flask, render_template, jsonify, request
from models.user import User
from flask_login import LoginManager
app = Flask(__name__)
app.config['SECRET_KEY'] = "Your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'


from database import db
Login_manager=LoginManager()
db.init_app(app)
Login_manager.init_app(app)
#view login

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        #login
        return jsonify({"message": "Autenticação realizada com sucesso"})
    
    return jsonify({"message": "Credenciais invalidas"}), 400

if __name__ == "__main__":
    app.run(debug=True)