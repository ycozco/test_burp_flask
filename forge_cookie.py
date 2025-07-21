from Crypto.Cipher import AES
import base64
import os
import json

key = b'Sixteen byte key'  # ⚠️ Clave conocida en este entorno vulnerable

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + chr(pad_len) * pad_len

def unpad(data):
    pad_len = ord(data[-1])
    return data[:-pad_len]

def encrypt(data):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(data).encode())).decode()

def decrypt(enc):
    try:
        raw = base64.b64decode(enc)
        iv = raw[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(raw[16:]).decode()
        return unpad(decrypted)
    except Exception as e:
        print("[!] Error al desencriptar:", e)
        return None

if __name__ == "__main__":
    print("=== 🔍 Forjador de Cookies AES CBC ===\n")
    enc_cookie = input("🔐 Ingresa la cookie cifrada (session):\n> ").strip()
    
    decrypted = decrypt(enc_cookie)
    
    if not decrypted:
        print("[✘] No se pudo desencriptar la cookie.")
        exit()

    print("\n✅ Cookie desencriptada correctamente:")
    print(decrypted)

    try:
        parsed = json.loads(decrypted)
    except json.JSONDecodeError:
        print("[!] El contenido no es un JSON válido.")
        exit()

    keys = list(parsed.keys())
    print("\n📋 Campos disponibles en la cookie:")
    for i, k in enumerate(keys):
        print(f"  [{i}] {k}: {parsed[k]}")

    try:
        idx = int(input("\n✏️ Ingresa el número del campo que deseas cambiar (ej. 1): "))
        if idx < 0 or idx >= len(keys):
            print("[!] Índice fuera de rango.")
            exit()
        selected_key = keys[idx]
        new_value = input(f"🔧 Nuevo valor para '{selected_key}': ").strip()
        parsed[selected_key] = new_value
    except ValueError:
        print("[!] Entrada inválida.")
        exit()

    new_data = json.dumps(parsed)
    forged_cookie = encrypt(new_data)

    print("\n🔥 Nueva cookie forjada:")
    print(forged_cookie)
