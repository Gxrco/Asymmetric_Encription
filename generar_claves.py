"""
Módulo para generación de claves RSA
Laboratorio de Cifrado Asimétrico - RSA
"""

from Crypto.PublicKey import RSA


def generar_par_claves(bits: int = 3072):
    """
    Crea un par de claves RSA y las guarda en archivos PEM.
    La clave privada se protege con una contraseña.
    """
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

    # Guardar clave privada
    with open('private_key.pem', 'wb') as f:
        f.write(private_key)

    # Guardar clave pública
    with open('public_key.pem', 'wb') as f:
        f.write(public_key)

    return private_key, public_key


if __name__ == '__main__':
    generar_par_claves(3072)
    print("Claves generadas exitosamente:")
    print("  - private_key.pem (protegida con passphrase)")
    print("  - public_key.pem")
