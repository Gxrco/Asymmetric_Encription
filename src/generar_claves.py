"""
Módulo para generación de claves RSA
Laboratorio de Cifrado Asimétrico - RSA
"""

import os
from Crypto.PublicKey import RSA

# Directorio de salida para archivos RSA
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'rsa')


def generar_par_claves(bits: int = 3072):
    """
    Crea un par de claves RSA y las guarda en archivos PEM.
    La clave privada se protege con una contraseña.
    """
    # Asegurar que el directorio de salida existe
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Generar par de claves RSA
    key = RSA.generate(bits)

    # Exportar clave privada con protección de contraseña
    private_key = key.export_key(
        format='PEM',
        passphrase='lab04uvg',
        pkcs=8,
        protection='PBKDF2WithHMAC-SHA1AndAES256-CBC'
    )

    # Exportar clave pública
    public_key = key.publickey().export_key(format='PEM')

    # Rutas de archivos
    private_path = os.path.join(OUTPUT_DIR, 'private_key.pem')
    public_path = os.path.join(OUTPUT_DIR, 'public_key.pem')

    # Guardar clave privada
    with open(private_path, 'wb') as f:
        f.write(private_key)

    # Guardar clave pública
    with open(public_path, 'wb') as f:
        f.write(public_key)

    return private_key, public_key


if __name__ == '__main__':
    generar_par_claves(3072)
    print("Claves generadas exitosamente:")
    print(f"  - {os.path.join(OUTPUT_DIR, 'private_key.pem')} (protegida con passphrase)")
    print(f"  - {os.path.join(OUTPUT_DIR, 'public_key.pem')}")
