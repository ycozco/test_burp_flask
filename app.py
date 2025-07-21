from flask import Flask, request, make_response, redirect, render_template_string
from Crypto.Cipher import AES
import base64
import os
import json

app = Flask(__name__)
key = b'Sixteen byte key'  # 16 bytes

USERS = {
    "admin": "admin123",
    "juan": "juan123"
}

ROLES = {
    "admin": "admin",
    "juan": "user"
}

TEMPLATE_LOGIN = """
<h2>Iniciar Sesión</h2>
<form method="POST">
  <label>Usuario: <input name="username"></label><br>
  <label>Contraseña: <input type="password" name="password"></label><br>
  <button type="submit">Entrar</button>
</form>
"""
TEMPLATE_INDEX = """
{% if role == 'admin' %}
  <h2>Panel de Administrador</h2>
  <p><b>Nombre:</b> {{ user }}</p>
  <p><b>Rol:</b> {{ role }}</p>
  <h3>Usuarios activos:</h3>
  <ul>
    {% for u in users %}
      <li>{{ u }}</li>
    {% endfor %}
  </ul>
{% else %}
  <h2>Panel de Usuario</h2>
  <p><b>Nombre:</b> {{ user }}</p>
  <p><b>Rol:</b> {{ role }}</p>
{% endif %}
<a href="/logout">Cerrar sesión</a>
"""


def pad(data):
    pad_len = 16 - len(data) % 16
    return data + chr(pad_len) * pad_len

def unpad(data):
    pad_len = ord(data[-1])
    return data[:-pad_len]

def encrypt(data):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(iv + encrypted).decode()

def decrypt(enc):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc[16:]).decode()
    return unpad(decrypted)

@app.route('/', methods=["GET"])
def index():
    cookie = request.cookies.get('session')
    if cookie:
        try:
            payload = decrypt(cookie)
            data = json.loads(payload)
            user = data.get("user", "Inválido")
            role = data.get("role", "Desconocido")
        except Exception as e:
            print("Error:", e)
            user = "Inválido"
            role = "-"
    else:
        return redirect("/login")

    return render_template_string(
        TEMPLATE_INDEX,
        user=user,
        role=role,
        users=USERS.keys(),
        roles=ROLES
    )

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if USERS.get(username) == password:
            role = ROLES.get(username, "user")
            payload = json.dumps({"user": username, "role": role})
            session_cookie = encrypt(payload)
            resp = make_response(redirect("/"))
            resp.set_cookie("session", session_cookie)
            return resp
        else:
            return "Credenciales incorrectas", 401
    return TEMPLATE_LOGIN

@app.route('/logout')
def logout():
    resp = make_response(redirect("/login"))
    resp.set_cookie("session", "", expires=0)
    return resp

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
