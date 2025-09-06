from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_login import LoginManager, login_required, login_user, current_user, logout_user
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "Your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Babedobabe1#@127.0.0.1:3306/flask-crud'
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
    from models.user import User
    return db.session.get(User, int(user_id))

# Rotas de API
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
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            return jsonify({"message": "Autenticação realizada com sucesso"})

        return jsonify({"message": "Credenciais inválidas"}), 400

    except Exception as e:
        return jsonify({"message": "Erro interno do servidor"}), 500

@app.route('/logout', methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso!"})

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

        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        new_user = User(username=username, password=hashed_password, role='admin')
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

    if current_user.role=='user':
        return jsonify({"message": "é necessario ser admin para criar outros usuários"}), 403

    try:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({"message": "Usuário já existe"}), 400

        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        new_user = User(username=username, password=hashed_password, role='user')
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
        user = db.session.get(User, id_user)
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
        user = db.session.get(User, id_user)
        if id_user != current_user.id and current_user.role == 'user':
            return jsonify({"message": "Voce não pode alterar a senha de outros usuários"}), 403

        if user:
            hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
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
    if current_user.role!='admin':
        return jsonify({"message": "Operação válida somente para admins"}), 403
    try:
        if id_user == current_user.id:
            return jsonify({"message": "Você não pode deletar sua própria conta"}), 403

        user = db.session.get(User, id_user)
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"message": f"Usuário {id_user} deletado com sucesso"})

        return jsonify({"message": "Usuário não encontrado"}), 404

    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Erro ao deletar usuário"}), 500

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
        from models.user import User
        db.create_all()
        db.session.commit()
        print("Tabelas criadas com sucesso!")
    app.run(debug=True)
