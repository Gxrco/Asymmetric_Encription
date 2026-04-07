"""
Módulo para generar claves RSA de MediSoft para firma digital
Laboratorio de Hashes y Firmas Digitales

Este módulo genera el par de claves RSA que MediSoft usará para
firmar digitalmente sus releases. Es diferente de generar_claves.py
porque estas claves son específicas para firma, no para cifrado.
"""

import os
from Crypto.PublicKey import RSA

# Directorio de salida para archivos de Hashes y Firmas
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'hashes')


def generar_claves_medisoft(bits: int = 2048) -> tuple[bytes, bytes]:
    """
    Genera par de claves RSA para MediSoft.
    Guarda medisoft_priv.pem (privada) y medisoft_pub.pem (pública) en output/hashes/.
    Retorna (private_key_pem, public_key_pem).

    Diferencias con generar_claves.py del Lab RSA:
    - Claves de 2048 bits (especificado por el enunciado)
    - Sin passphrase (PEM plano estándar)
    - Archivos con prefijo 'medisoft_' para distinguirlos
    """
    # Asegurar que el directorio de salida existe
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Generar par de claves RSA
    key = RSA.generate(bits)

    # Exportar clave privada sin protección de contraseña
    private_key = key.export_key(format='PEM')

    # Exportar clave pública
    public_key = key.publickey().export_key(format='PEM')

    # Rutas de archivos
    private_path = os.path.join(OUTPUT_DIR, 'medisoft_priv.pem')
    public_path = os.path.join(OUTPUT_DIR, 'medisoft_pub.pem')

    # Guardar clave privada
    with open(private_path, 'wb') as f:
        f.write(private_key)

    # Guardar clave pública
    with open(public_path, 'wb') as f:
        f.write(public_key)

    return private_key, public_key


if __name__ == '__main__':
    print("=== Generación de Claves RSA para MediSoft ===\n")

    print("Generando par de claves RSA de 2048 bits...")
    priv, pub = generar_claves_medisoft(2048)

    print("\nClaves generadas exitosamente:")
    print(f"  - {os.path.join(OUTPUT_DIR, 'medisoft_priv.pem')} (clave privada, mantener segura)")
    print(f"  - {os.path.join(OUTPUT_DIR, 'medisoft_pub.pem')} (clave pública, distribuir a hospitales)")

    print("\n=== Contenido de medisoft_pub.pem ===\n")
    print(pub.decode())

    print("=== Información de las claves ===\n")
    print("Estas claves se usarán para:")
    print("  1. Firmar digitalmente SHA256SUMS.txt con la clave privada")
    print("  2. Los hospitales verificarán la firma con la clave pública")
    print("\nIMPORTANTE: medisoft_priv.pem debe mantenerse segura y")
    print("nunca compartirse. Solo MediSoft debe tener acceso a ella.")
    print("\nmedisoft_pub.pem debe distribuirse a todos los hospitales")
    print("que instalarán el software para que puedan verificar")
    print("la autenticidad de las actualizaciones.")
