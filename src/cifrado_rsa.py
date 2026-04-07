"""
Módulo para cifrado directo con RSA-OAEP
Laboratorio de Cifrado Asimétrico - RSA
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Directorio de salida para archivos RSA
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'rsa')


def cifrar_con_rsa(mensaje: bytes, public_key_pem: bytes) -> bytes:
    """
    Cifra un mensaje usando la clave pública RSA con padding OAEP.
    El padding OAEP añade aleatoriedad para que cada cifrado sea diferente.
    """
    # Importar la clave pública desde el formato PEM
    public_key = RSA.import_key(public_key_pem)

    # Crear el cifrador RSA-OAEP
    cipher = PKCS1_OAEP.new(public_key)

    # Cifrar el mensaje
    ciphertext = cipher.encrypt(mensaje)

    return ciphertext


def descifrar_con_rsa(cifrado: bytes, private_key_pem: bytes, passphrase: str = 'lab04uvg') -> bytes:
    """
    Descifra un mensaje usando la clave privada RSA protegida con contraseña.
    Revierte el proceso de cifrado OAEP para recuperar el mensaje original.
    """
    # Importar la clave privada desde el formato PEM con la contraseña
    private_key = RSA.import_key(private_key_pem, passphrase=passphrase)

    # Crear el descifrador RSA-OAEP
    cipher = PKCS1_OAEP.new(private_key)

    # Descifrar el mensaje
    plaintext = cipher.decrypt(cifrado)

    return plaintext


if __name__ == '__main__':
    from .generar_claves import generar_par_claves

    # Generar claves para prueba
    print("Generando claves RSA...")
    generar_par_claves(2048)

    # Leer las claves desde output/rsa/
    with open(os.path.join(OUTPUT_DIR, 'public_key.pem'), 'rb') as f:
        public_key = f.read()

    with open(os.path.join(OUTPUT_DIR, 'private_key.pem'), 'rb') as f:
        private_key = f.read()

    # Mensaje de prueba
    mensaje = b"Mensaje confidencial de prueba"
    print(f"\nMensaje original: {mensaje.decode()}")

    # Cifrar el mensaje dos veces para demostrar aleatoriedad de OAEP
    print("\nCifrando el mismo mensaje dos veces...")
    cifrado1 = cifrar_con_rsa(mensaje, public_key)
    cifrado2 = cifrar_con_rsa(mensaje, public_key)

    print(f"Cifrado 1: {cifrado1.hex()[:64]}...")
    print(f"Cifrado 2: {cifrado2.hex()[:64]}...")
    print(f"¿Son iguales? {cifrado1 == cifrado2}")

    # Descifrar ambos
    descifrado1 = descifrar_con_rsa(cifrado1, private_key)
    descifrado2 = descifrar_con_rsa(cifrado2, private_key)

    print(f"\nDescifrado 1: {descifrado1.decode()}")
    print(f"Descifrado 2: {descifrado2.decode()}")
    print(f"Descifrados correctamente: {descifrado1 == descifrado2 == mensaje}")
