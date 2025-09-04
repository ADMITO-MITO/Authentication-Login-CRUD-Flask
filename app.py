from flask import Flask, render_template, jsonify, request
from flask_login import LoginManager, login_required, login_user, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = "Your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# banco de dados
from database import db
db.init_app(app)

# importar os modelos DEPOIS de inicializar o db
from models.user import User

# login manager
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

# criar as tabelas do banco de dados
@app.before_request
def create_tables():
    db.create_all()

# rota de login
@app.route('/login', methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if username and password:
        # Login
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            # autenticação de login
            login_user(user)
            print(f"Usuário autenticado: {current_user.is_authenticated}")
            return jsonify({"message": "Autenticação realizada com sucesso"})

    return jsonify({"message": "Credenciais inválidas"}), 400

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

# rota para cadastrar usuário Admin
@app.route('/register', methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username e password são obrigatórios"}), 400

    # verificar se o usuário já existe
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Usuário já existe"}), 400

    # criar novo usuário
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuário cadastrado com sucesso"}), 201

# rota para cadastrar usuarios (logado como admin)
@app.route('/user', methods=["POST"])
@login_required
def create_user():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username e password são obrigatórios"}), 400

    # verificar se o usuário já existe
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Usuário já existe"}), 400

    # criar novo usuário
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "Usuário cadastrado com sucesso"}), 201


@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def get_user(id_user):
    user = User.query.get(id_user)
    # mostra o nome do usuario
    if user:
        return {"usaname": user.username}

    return jsonify({"message": "Usuário não encotrado"}), 404

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_password(id_user):
    data = request.get_json(silent=True) or {}
    user = User.query.get(id_user)
    # mostra o nome do usuario
    if user and data.get("password"):
        user.password = data.get("password")
        db.session.add(user)
        db.session.commit()

        return {"message": f"Usuario {id_user} atualizado com sucesso"}

    return jsonify({"message": "Usuário não encotrado"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)
    if id_user == current_user.id:
        return {"message": "Operação não válida"}, 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return {"message": f"Usuario {id_user} deletado com sucesso com sucesso"}

    return jsonify({"message": "Usuário não encotrado"}), 404

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # criar tabelas caso ainda não tenha
    app.run(debug=True)
