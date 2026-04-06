import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from generar_claves import generar_par_claves


def encrypt_document(document: bytes, recipient_public_key_pem: bytes) -> bytes:
    """
    Cifra un documento usando cifrado híbrido.
    Genera una clave AES aleatoria, cifra el documento con AES-GCM,
    y luego cifra la clave AES con la clave pública RSA.
    """
    # 1. Generar clave AES aleatoria de 256 bits (32 bytes)
    aes_key = os.urandom(32)

    # 2. Cifrar el documento con AES-256-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(document)
    nonce = cipher_aes.nonce

    # 3. Cifrar la clave AES con la clave pública RSA usando OAEP
    public_key = RSA.import_key(recipient_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # 4. Construir el paquete final
    # Formato: [tamaño_clave_cifrada (4 bytes)] + [clave_cifrada] + [nonce (16 bytes)] + [tag (16 bytes)] + [ciphertext]
    len_encrypted_key = len(encrypted_aes_key).to_bytes(4, byteorder='big')
    package = len_encrypted_key + encrypted_aes_key + nonce + tag + ciphertext

    return package


def decrypt_document(pkg: bytes, recipient_private_key_pem: bytes, passphrase: str = 'lab04uvg') -> bytes:
    """
    Descifra un documento cifrado con el esquema híbrido.
    Extrae y descifra la clave AES con RSA, luego usa esa clave
    para descifrar el documento con AES-GCM.
    """
    # 1. Leer el tamaño de la clave cifrada
    len_encrypted_key = int.from_bytes(pkg[:4], byteorder='big')

    # 2. Extraer los componentes del paquete
    offset = 4
    encrypted_aes_key = pkg[offset:offset + len_encrypted_key]
    offset += len_encrypted_key

    nonce = pkg[offset:offset + 16]
    offset += 16

    tag = pkg[offset:offset + 16]
    offset += 16

    ciphertext = pkg[offset:]

    # 3. Descifrar la clave AES con la clave privada RSA
    private_key = RSA.import_key(recipient_private_key_pem, passphrase=passphrase)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # 4. Descifrar el documento con AES-GCM
    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext


if __name__ == '__main__':
    print("=== Prueba de Cifrado Híbrido RSA-OAEP + AES-GCM ===\n")

    # Generar claves RSA
    print("Generando claves RSA de 2048 bits...")
    generar_par_claves(2048)

    # Leer las claves
    with open("public_key.pem", "rb") as f:
        pub = f.read()

    with open("private_key.pem", "rb") as f:
        priv = f.read()

    # Prueba 1: Documento pequeño
    print("\n--- Prueba 1: Documento pequeño ---")
    doc = b"Contrato de confidencialidad No. 2025-GT-001"
    print(f"Documento original: {doc.decode()}")

    pkg = encrypt_document(doc, pub)
    print(f"Tamaño del paquete cifrado: {len(pkg)} bytes")

    resultado = decrypt_document(pkg, priv)
    print(f"Documento descifrado: {resultado.decode()}")
    print(f"Descifrado correcto: {resultado == doc}")

    # Prueba 2: Archivo de 1 MB
    print("\n--- Prueba 2: Archivo de 1 MB ---")
    doc_grande = os.urandom(1024 * 1024)
    print(f"Tamaño del documento: {len(doc_grande)} bytes")

    pkg2 = encrypt_document(doc_grande, pub)
    print(f"Tamaño del paquete cifrado: {len(pkg2)} bytes")

    resultado_grande = decrypt_document(pkg2, priv)
    assert resultado_grande == doc_grande
    print("Archivo 1 MB: OK")

    # Demostrar que cifrar el mismo documento produce resultados diferentes
    print("\n--- Prueba 3: Aleatoriedad del cifrado ---")
    pkg3 = encrypt_document(doc, pub)
    pkg4 = encrypt_document(doc, pub)
    print(f"Primer cifrado:  {pkg3[:32].hex()}...")
    print(f"Segundo cifrado: {pkg4[:32].hex()}...")
    print(f"¿Son iguales? {pkg3 == pkg4}")
    print("(Diferente porque AES-GCM usa un nonce aleatorio cada vez)")
