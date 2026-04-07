"""
Tests para los módulos RSA del Lab RSA
Laboratorio de Cifrado Asimétrico - RSA
"""

import os
import pytest
from src.generar_claves import generar_par_claves
from src.cifrado_rsa import cifrar_con_rsa, descifrar_con_rsa
from src.cifrado_hibrido import encrypt_document, decrypt_document


@pytest.fixture(scope="module")
def claves_rsa():
    """Genera claves RSA una vez para todos los tests del módulo."""
    generar_par_claves(2048)

    with open('public_key.pem', 'rb') as f:
        pub = f.read()
    with open('private_key.pem', 'rb') as f:
        priv = f.read()

    yield pub, priv

    # Limpieza opcional (comentada para no eliminar claves que pueden ser útiles)
    # os.remove('public_key.pem')
    # os.remove('private_key.pem')


def test_generacion_claves():
    """Verifica que se generen correctamente los archivos de claves."""
    generar_par_claves(2048)

    assert os.path.exists('public_key.pem'), "No se generó public_key.pem"
    assert os.path.exists('private_key.pem'), "No se generó private_key.pem"

    # Verificar que los archivos tienen contenido
    with open('public_key.pem', 'rb') as f:
        pub = f.read()
    with open('private_key.pem', 'rb') as f:
        priv = f.read()

    assert len(pub) > 0, "public_key.pem está vacío"
    assert len(priv) > 0, "private_key.pem está vacío"

    # Verificar formato PEM
    assert b'-----BEGIN PUBLIC KEY-----' in pub
    assert b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in priv


def test_cifrado_descifrado_rsa(claves_rsa):
    """Verifica que el cifrado y descifrado RSA-OAEP funcionen correctamente."""
    pub, priv = claves_rsa

    mensaje = b"Mensaje de prueba confidencial"
    cifrado = cifrar_con_rsa(mensaje, pub)
    descifrado = descifrar_con_rsa(cifrado, priv)

    assert descifrado == mensaje, "El mensaje descifrado no coincide con el original"


def test_cifrado_rsa_aleatorio(claves_rsa):
    """Verifica que OAEP produce cifrados diferentes para el mismo mensaje."""
    pub, _ = claves_rsa

    mensaje = b"Mensaje de prueba"
    cifrado1 = cifrar_con_rsa(mensaje, pub)
    cifrado2 = cifrar_con_rsa(mensaje, pub)

    assert cifrado1 != cifrado2, "OAEP debe producir cifrados diferentes"


def test_cifrado_hibrido_documento_pequeno(claves_rsa):
    """Verifica cifrado híbrido con documento pequeño."""
    pub, priv = claves_rsa

    documento = b"Contrato de confidencialidad No. 2025-GT-001"
    paquete = encrypt_document(documento, pub)
    resultado = decrypt_document(paquete, priv)

    assert resultado == documento, "Documento descifrado no coincide"


def test_cifrado_hibrido_documento_grande(claves_rsa):
    """Verifica cifrado híbrido con documento de 1 MB."""
    pub, priv = claves_rsa

    # Documento de 1 MB
    documento = os.urandom(1024 * 1024)
    paquete = encrypt_document(documento, pub)
    resultado = decrypt_document(paquete, priv)

    assert resultado == documento, "Documento grande descifrado no coincide"


def test_cifrado_hibrido_aleatorio(claves_rsa):
    """Verifica que el cifrado híbrido produce resultados diferentes."""
    pub, _ = claves_rsa

    documento = b"Documento de prueba"
    paquete1 = encrypt_document(documento, pub)
    paquete2 = encrypt_document(documento, pub)

    assert paquete1 != paquete2, "El cifrado híbrido debe usar nonce aleatorio"


def test_cifrado_rsa_limite_tamano(claves_rsa):
    """Verifica que RSA-OAEP rechaza mensajes muy grandes."""
    pub, _ = claves_rsa

    # Para claves de 2048 bits, el límite es ~190 bytes con OAEP
    mensaje_grande = b"X" * 250

    with pytest.raises(Exception):
        cifrar_con_rsa(mensaje_grande, pub)
