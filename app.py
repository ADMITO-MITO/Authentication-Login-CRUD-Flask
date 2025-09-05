from flask import Flask, jsonify, request
from flask_login import LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = "Your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializar banco de dados
from database import db
db.init_app(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_message = "Você precisa estar logado para acessar essa página."
login_manager.login_message_category = "warning"

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"error": "Login obrigatório"}), 401

@login_manager.user_loader
def load_user(user_id):
    from models.user import User  # Importar aqui para evitar circular imports
    return db.session.get(User, int(user_id))

# Rotas de autenticação
@app.route('/login', methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"message": "Content-Type deve ser application/json"}), 400

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username e password são obrigatórios"}), 400

    try:
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"})

        return jsonify({"message": "Credenciais inválidas"}), 400

    except Exception as e:
        return jsonify({"message": "Erro interno do servidor"}), 500

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

# Rotas de usuário
@app.route('/register', methods=["POST"])
def register():
    if not request.is_json:
        return jsonify({"message": "Content-Type deve ser application/json"}), 400

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username e password são obrigatórios"}), 400

    if not username.strip() or not password.strip():
        return jsonify({"message": "Username e password não podem ser vazios"}), 400

    try:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Usuário já existe"}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuário cadastrado com sucesso"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erro ao cadastrar usuário"}), 500

@app.route('/users', methods=["GET"])
@login_required
def get_users():
    try:
        users = User.query.all()
        users_list = [{"id": user.id, "username": user.username} for user in users]
        return jsonify({"users": users_list})

    except Exception as e:
        return jsonify({"message": "Erro ao buscar usuários"}), 500

@app.route('/user', methods=["POST"])
@login_required
def create_user():
    if not request.is_json:
        return jsonify({"message": "Content-Type deve ser application/json"}), 400

    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username e password são obrigatórios"}), 400

    if not username.strip() or not password.strip():
        return jsonify({"message": "Username e password não podem ser vazios"}), 400

    try:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Usuário já existe"}), 400

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": "Usuário cadastrado com sucesso"}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erro ao cadastrar usuário"}), 500

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def get_user(id_user):
    try:
        user = User.query.get(id_user)
        if user:
            return jsonify({
                "id": user.id,
                "username": user.username
            })

        return jsonify({"message": "Usuário não encontrado"}), 404

    except Exception as e:
        return jsonify({"message": "Erro ao buscar usuário"}), 500

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_password(id_user):
    if not request.is_json:
        return jsonify({"message": "Content-Type deve ser application/json"}), 400

    data = request.get_json()
    password = data.get("password")

    if not password:
        return jsonify({"message": "Nova senha é obrigatória"}), 400

    try:
        user = User.query.get(id_user)
        if user:
            hashed_password = generate_password_hash(password)
            user.password = hashed_password
            db.session.commit()

            return jsonify({"message": f"Usuário {id_user} atualizado com sucesso"})

        return jsonify({"message": "Usuário não encontrado"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erro ao atualizar usuário"}), 500

@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
    try:
        if id_user == current_user.id:
            return jsonify({"message": "Você não pode deletar sua própria conta"}), 403

        user = User.query.get(id_user)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": f"Usuário {id_user} deletado com sucesso"})

        return jsonify({"message": "Usuário não encontrado"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erro ao deletar usuário"}), 500

# Rota para informações do usuário atual
@app.route('/me', methods=["GET"])
@login_required
def get_current_user():
    return jsonify({
        "id": current_user.id,
        "username": current_user.username,
        "authenticated": current_user.is_authenticated
    })

if __name__ == "__main__":
    with app.app_context():
        # Importar modelos dentro do contexto para evitar problemas
        from models.user import User
        db.create_all()
        print("Tabelas criadas com sucesso!")
    app.run(debug=True)
