"""
Módulo para firmar digitalmente el manifiesto SHA256SUMS.txt
Laboratorio de Hashes y Firmas Digitales

MediSoft firma el manifiesto con su clave privada RSA usando PSS
(Probabilistic Signature Scheme) para que los hospitales puedan
verificar la autenticidad del paquete de software.
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# Directorio de salida para archivos de Hashes y Firmas
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'hashes')


def firmar_manifiesto(
    manifiesto: str = None,
    clave_privada_pem: str = None,
    salida_firma: str = None
) -> None:
    """
    Firma digitalmente el manifiesto SHA256SUMS.txt con la clave privada RSA usando PSS.
    El resultado se guarda en SHA256SUMS.sig como bytes binarios.

    PSS (Probabilistic Signature Scheme) es más seguro que PKCS#1 v1.5 porque:
    - Añade aleatoriedad al proceso de firma
    - Tiene prueba de seguridad formal
    - Es el estándar recomendado para nuevas aplicaciones
    """
    # Rutas por defecto
    if manifiesto is None:
        manifiesto = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')
    if clave_privada_pem is None:
        clave_privada_pem = os.path.join(OUTPUT_DIR, 'medisoft_priv.pem')
    if salida_firma is None:
        salida_firma = os.path.join(OUTPUT_DIR, 'SHA256SUMS.sig')

    # Leer el contenido del manifiesto
    with open(manifiesto, 'rb') as f:
        contenido = f.read()

    # Calcular hash SHA-256 del contenido
    hash_obj = SHA256.new(contenido)

    # Cargar clave privada
    with open(clave_privada_pem, 'rb') as f:
        clave_privada = RSA.import_key(f.read())

    # Crear firmador PSS y generar firma
    firmador = pss.new(clave_privada)
    firma = firmador.sign(hash_obj)

    # Guardar firma en archivo binario
    with open(salida_firma, 'wb') as f:
        f.write(firma)

    print(f"Manifiesto firmado exitosamente.")
    print(f"  Entrada:  {manifiesto}")
    print(f"  Clave:    {clave_privada_pem}")
    print(f"  Firma:    {salida_firma} ({len(firma)} bytes)")


if __name__ == '__main__':
    print("=== Firma Digital del Manifiesto SHA256SUMS.txt ===\n")

    # Rutas de archivos
    manifiesto_path = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')
    clave_privada_path = os.path.join(OUTPUT_DIR, 'medisoft_priv.pem')
    firma_path = os.path.join(OUTPUT_DIR, 'SHA256SUMS.sig')

    # Verificar que existen los archivos necesarios
    if not os.path.exists(manifiesto_path):
        print(f"No se encontró {manifiesto_path}")
        print("Ejecute primero: python -m src.generar_manifiesto")
        exit(1)

    if not os.path.exists(clave_privada_path):
        print(f"No se encontró {clave_privada_path}")
        print("Ejecute primero: python -m src.generar_claves_rsa")
        exit(1)

    print(f"Contenido de {manifiesto_path} a firmar:")
    print("-" * 60)
    with open(manifiesto_path, 'r') as f:
        print(f.read())
    print("-" * 60)

    # Firmar el manifiesto
    print("\nFirmando con RSA-PSS + SHA-256...")
    firmar_manifiesto(manifiesto_path, clave_privada_path, firma_path)

    # Mostrar información de la firma
    print("\n=== Información de la firma ===\n")
    with open(firma_path, 'rb') as f:
        firma = f.read()

    print(f"Tamaño de la firma: {len(firma)} bytes")
    print(f"Firma (hex, primeros 64 chars): {firma.hex()[:64]}...")

    print("\n=== Proceso de firma RSA-PSS ===\n")
    print("1. Se lee el contenido completo de SHA256SUMS.txt")
    print("2. Se calcula el hash SHA-256 del contenido")
    print("3. Se aplica el esquema PSS al hash:")
    print("   - Se genera salt aleatorio")
    print("   - Se combina hash + salt usando MGF (Mask Generation Function)")
    print("   - Se añade padding especial")
    print("4. Se firma el resultado con la clave privada RSA")
    print("5. La firma se guarda en SHA256SUMS.sig")

    print("\n=== ¿Por qué usar PSS en lugar de PKCS#1 v1.5? ===\n")
    print("- PSS tiene prueba de seguridad formal (reducción al problema RSA)")
    print("- PKCS#1 v1.5 tiene vulnerabilidades conocidas (ataques Bleichenbacher)")
    print("- PSS es el estándar recomendado por NIST para nuevas aplicaciones")
    print("- Consistente con el uso de OAEP para cifrado en el lab anterior")
