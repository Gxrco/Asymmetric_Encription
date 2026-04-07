"""
Módulo para verificar contraseñas contra Have I Been Pwned
Laboratorio de Hashes y Firmas Digitales

Demuestra k-Anonymity: solo los primeros 5 caracteres del hash SHA-1
se envían a la API, protegiendo la privacidad de la contraseña.
"""

import hashlib
import requests


def sha1_hex(texto: str) -> str:
    """
    Calcula SHA-1 de un texto y retorna el hexdigest en mayúsculas.
    HIBP usa SHA-1 en mayúsculas para sus consultas.
    """
    return hashlib.sha1(texto.encode('utf-8')).hexdigest().upper()


def consultar_hibp(password: str) -> int:
    """
    Consulta Have I Been Pwned usando k-Anonymity con SHA-1.
    Retorna cuántas veces aparece el hash en filtraciones conocidas (0 si ninguna).

    Solo se envían los primeros 5 caracteres del hash SHA-1 a la API.
    La API devuelve todos los sufijos que coinciden con ese prefijo.
    Se busca el sufijo propio en la respuesta para determinar las apariciones.
    """
    # Calcular SHA-1 de la contraseña
    hash_sha1 = sha1_hex(password)

    # Dividir en prefijo (5 chars) y sufijo (resto)
    prefijo = hash_sha1[:5]
    sufijo = hash_sha1[5:]

    # Consultar la API de HIBP
    url = f"https://api.pwnedpasswords.com/range/{prefijo}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error consultando HIBP: {e}")
        return -1  # Indica error de conexión

    # Buscar el sufijo en la respuesta
    # Formato de respuesta: SUFIJO:CONTEO\r\n
    for linea in response.text.splitlines():
        partes = linea.split(':')
        if len(partes) == 2:
            sufijo_resp, conteo = partes
            if sufijo_resp == sufijo:
                return int(conteo)

    # No se encontró el hash - la contraseña no está en filtraciones conocidas
    return 0


def verificar_passwords(passwords: list[str]) -> None:
    """
    Verifica una lista de contraseñas contra HIBP e imprime tabla de resultados.
    Demuestra que contraseñas comunes tienen sus hashes indexados.
    """
    print("\n" + "=" * 80)
    print(f"{'Contraseña':<20} {'SHA-1 (primeros 10)...':<28} {'Apariciones'}")
    print("=" * 80)

    for password in passwords:
        hash_sha1 = sha1_hex(password)
        hash_truncado = hash_sha1[:10] + "..."
        apariciones = consultar_hibp(password)

        if apariciones == -1:
            estado = "Error de conexión"
        elif apariciones == 0:
            estado = "No encontrada"
        else:
            estado = f"{apariciones:,} veces"

        print(f"{password:<20} {hash_truncado:<28} {estado}")

    print("=" * 80)


if __name__ == '__main__':
    print("=== Verificación de Contraseñas contra Have I Been Pwned ===\n")

    print("Este módulo demuestra k-Anonymity:")
    print("- Solo se envían los primeros 5 caracteres del hash SHA-1 a la API.")
    print("- El hash completo nunca sale de tu equipo.")
    print("- La respuesta contiene todos los sufijos con ese prefijo.")
    print("- Buscamos nuestro sufijo localmente para determinar las apariciones.\n")

    # Lista de contraseñas a verificar según especificación
    passwords = ["admin", "123456", "hospital", "medisoft2024"]

    print("Contraseñas a verificar:", passwords)
    verificar_passwords(passwords)

    print("\n=== Conclusiones ===\n")
    print("1. Las contraseñas comunes aparecen millones de veces en filtraciones.")
    print("2. SHA-1/SHA-256 directo sobre contraseñas es inseguro porque:")
    print("   - Las contraseñas comunes tienen sus hashes indexados en tablas rainbow.")
    print("   - Un atacante puede pre-calcular hashes de millones de contraseñas.")
    print("\n3. Para almacenar contraseñas de forma segura se debe usar:")
    print("   - Funciones de derivación de clave (PBKDF2, bcrypt, Argon2)")
    print("   - Salt único por contraseña")
    print("   - Factor de trabajo (iterations) alto")
