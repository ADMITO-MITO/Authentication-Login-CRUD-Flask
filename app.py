from flask import Flask, render_template, jsonify, request
from flask_login import LoginManager, login_required, login_user, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = "Your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Inicializar o banco de dados
from database import db
db.init_app(app)

# IMPORTANTE: Importar os modelos DEPOIS de inicializar o db
from models.user import User

# Configurar o login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = "Você precisa estar logado para acessar essa página."
login_manager.login_message_category = "warning"

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Login obrigatório"}), 401

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

# Criar as tabelas do banco de dados
@app.before_request
def create_tables():
    db.create_all()

# Rota de login
@app.route('/login', methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # Login
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            # Autenticação de login
            login_user(user)
            print(f"Usuário autenticado: {current_user.is_authenticated}")
            return jsonify({"message": "Autenticação realizada com sucesso"})

    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

# Rota para cadastrar usuário (para testes)
@app.route('/register', methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username e password são obrigatórios"}), 400

    # Verificar se o usuário já existe
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Usuário já existe"}), 400

    # Criar novo usuário
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuário cadastrado com sucesso"}), 201

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Criar tabelas caso ainda não tenha
    app.run(debug=True)
