# 🔐 Authentication Login CRUD — Flask API

API REST de autenticação e gerenciamento de usuários com sistema de roles (admin/user), construída com Flask, Flask-Login, bcrypt e MySQL via Docker.

---

## 🧰 Tecnologias

- Python 3 + Flask
- Flask-Login (gerenciamento de sessão)
- bcrypt (hash de senhas)
- SQLAlchemy + MySQL
- Docker + Docker Compose

---

## 🚀 Como rodar localmente

### Pré-requisitos

- Docker e Docker Compose instalados

### 1. Clone o repositório

```bash
git clone https://github.com/ADMITO-MITO/Authentication-Login-CRUD-Flask.git
cd Authentication-Login-CRUD-Flask
```

### 2. Configure as variáveis de ambiente

Crie um arquivo `.env` na raiz do projeto com base no `.env.example`:

```env
MYSQL_USER=seu_usuario
MYSQL_PASSWORD=sua_senha
MYSQL_DATABASE=flask-crud
MYSQL_ROOT_PASSWORD=sua_senha_root
SECRET_KEY=sua_chave_secreta
```

### 3. Suba o banco de dados

```bash
docker compose up -d
```

### 4. Instale as dependências e rode a aplicação

```bash
pip install -r requirements.txt
python app.py
```

A API estará disponível em `http://localhost:5000`.

---

## 📬 Rotas da API

> Todas as requisições com body devem ter o header `Content-Type: application/json`.

### Autenticação

| Método | Rota        | Descrição                        | Auth necessária |
|--------|-------------|----------------------------------|-----------------|
| POST   | `/register` | Cria uma conta de admin          | ❌              |
| POST   | `/login`    | Autentica o usuário              | ❌              |
| POST   | `/logout`   | Encerra a sessão                 | ✅              |

### Gerenciamento de Usuários

| Método | Rota              | Descrição                              | Auth necessária |
|--------|-------------------|----------------------------------------|-----------------|
| GET    | `/me`             | Retorna dados do usuário logado        | ✅              |
| GET    | `/users`          | Lista todos os usuários                | ✅              |
| GET    | `/user/<id>`      | Busca usuário por ID                   | ✅              |
| POST   | `/user`           | Cria novo usuário (somente admin)      | ✅ (admin)      |
| PUT    | `/user/<id>`      | Atualiza senha do usuário              | ✅              |
| DELETE | `/user/<id>`      | Remove usuário (somente admin)         | ✅ (admin)      |

---

## 🔒 Sistema de Roles

- **admin** — acesso total: criar, listar, atualizar e deletar usuários
- **user** — acesso limitado: pode ver e atualizar apenas a própria conta

---

## 🧪 Testando com Postman

Importe o arquivo `postman_collection.json` disponível na raiz do projeto para ter todas as rotas configuradas e prontas para uso.

---

## 📁 Estrutura do projeto

```
├── app.py
├── database.py
├── models/
│   └── user.py
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── postman_collection.json
```

---

## 📌 Melhorias futuras

- [ ] Autenticação com JWT
- [ ] Refresh token
- [ ] Paginação na listagem de usuários
- [ ] Testes automatizados