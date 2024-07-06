from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os

# Configuración de la aplicación Flask
app = Flask(__name__)

# Ruta a la base de datos SQLite
DATABASE = 'users.db'

# Función para inicializar la base de datos
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()

# Inicializar la base de datos
init_db()

# Ruta para registrar un nuevo usuario
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'El nombre de usuario y la contraseña son obligatorios'}), 400

    # Generar hash de la contraseña
    password_hash = hashlib.sha256(password.encode()).hexdigest()

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'El nombre de usuario ya existe'}), 400

    return jsonify({'message': 'Usuario registrado exitosamente'}), 201

# Ruta para validar un usuario
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if not username or not password:
        return jsonify({'error': 'El nombre de usuario y la contraseña son obligatorios'}), 400

    # Obtener hash de la contraseña almacenada en la base de datos
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()

    if result is None:
        return jsonify({'error': 'Nombre de usuario o contraseña no válidos'}), 401

    # Comparar el hash de la contraseña proporcionada con el almacenado
    stored_password_hash = result[0]
    if hashlib.sha256(password.encode()).hexdigest() == stored_password_hash:
        return jsonify({'message': 'Inicio de sesión exitoso'}), 200
    else:
        return jsonify({'error': 'Nombre de usuario o contraseña no válidos'}), 401

# Ejecutar el servidor en el puerto 5800
if __name__ == '__main__':
    app.run(port=5800)
