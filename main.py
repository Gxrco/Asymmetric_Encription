"""
Programa principal para el Laboratorio de Cifrado Asimétrico - RSA
Universidad del Valle de Guatemala
Cifrados y Criptografía

Este programa demuestra el uso de cifrado RSA y cifrado híbrido
para la transferencia segura de documentos.
"""

import os
from generar_claves import generar_par_claves
from cifrado_rsa import cifrar_con_rsa, descifrar_con_rsa
from cifrado_hibrido import encrypt_document, decrypt_document


def mostrar_menu():
    """
    Muestra el menú principal con las opciones disponibles.
    """
    print("\n" + "=" * 60)
    print("   LABORATORIO DE CIFRADO ASIMÉTRICO - RSA")
    print("   Plataforma de Transferencia de Documentos Legales")
    print("=" * 60)
    print("\n1. Generar par de claves RSA")
    print("2. Cifrado directo con RSA-OAEP (mensajes pequeños)")
    print("3. Cifrado híbrido RSA + AES-GCM (documentos)")
    print("4. Ejecutar todas las pruebas")
    print("5. Salir")
    print("-" * 60)


def prueba_generacion_claves():
    """
    Ejecuta la generación de claves RSA y muestra información.
    """
    print("\n--- GENERACIÓN DE CLAVES RSA ---")
    bits = int(input("Ingrese el tamaño de las claves (2048 o 3072): "))

    if bits not in [2048, 3072]:
        print("Tamaño no válido. Usando 3072 bits por defecto.")
        bits = 3072

    print(f"\nGenerando claves RSA de {bits} bits...")
    generar_par_claves(bits)

    print("\nClaves generadas exitosamente:")
    print("  - private_key.pem (protegida con passphrase 'lab04uvg')")
    print("  - public_key.pem")

    # Mostrar información de la clave pública
    with open('public_key.pem', 'r') as f:
        print("\nContenido de public_key.pem:")
        print(f.read())


def prueba_cifrado_rsa():
    """
    Demuestra el cifrado directo con RSA-OAEP.
    """
    print("\n--- CIFRADO DIRECTO CON RSA-OAEP ---")

    # Verificar que existan las claves
    if not os.path.exists('public_key.pem') or not os.path.exists('private_key.pem'):
        print("Error: No se encontraron las claves. Genere las claves primero (opción 1).")
        return

    # Leer las claves
    with open('public_key.pem', 'rb') as f:
        public_key = f.read()

    with open('private_key.pem', 'rb') as f:
        private_key = f.read()

    # Solicitar mensaje al usuario
    mensaje_texto = input("\nIngrese el mensaje a cifrar: ")
    mensaje = mensaje_texto.encode('utf-8')

    # Verificar tamaño del mensaje (RSA-OAEP tiene límite)
    max_size = 190  # Para claves de 2048 bits con OAEP
    if len(mensaje) > max_size:
        print(f"\nAdvertencia: El mensaje es muy largo ({len(mensaje)} bytes).")
        print(f"RSA-OAEP puede cifrar máximo ~{max_size} bytes.")
        print("Use la opción 3 (cifrado híbrido) para mensajes grandes.")
        return

    print(f"\nMensaje original: {mensaje.decode()}")
    print(f"Tamaño: {len(mensaje)} bytes")

    # Cifrar dos veces para demostrar aleatoriedad
    print("\nCifrando el mensaje dos veces...")
    cifrado1 = cifrar_con_rsa(mensaje, public_key)
    cifrado2 = cifrar_con_rsa(mensaje, public_key)

    print(f"\nCifrado 1 (primeros 32 bytes): {cifrado1[:32].hex()}...")
    print(f"Cifrado 2 (primeros 32 bytes): {cifrado2[:32].hex()}...")
    print(f"\n¿Los cifrados son iguales? {cifrado1 == cifrado2}")
    print("Respuesta: NO - OAEP añade padding aleatorio en cada cifrado")

    # Descifrar ambos
    descifrado1 = descifrar_con_rsa(cifrado1, private_key)
    descifrado2 = descifrar_con_rsa(cifrado2, private_key)

    print(f"\nDescifrado 1: {descifrado1.decode()}")
    print(f"Descifrado 2: {descifrado2.decode()}")
    print(f"\nDescifrado correcto: {descifrado1 == descifrado2 == mensaje}")


def prueba_cifrado_hibrido():
    """
    Demuestra el cifrado híbrido RSA-OAEP + AES-GCM.
    """
    print("\n--- CIFRADO HÍBRIDO RSA-OAEP + AES-GCM ---")

    # Verificar que existan las claves
    if not os.path.exists('public_key.pem') or not os.path.exists('private_key.pem'):
        print("Error: No se encontraron las claves. Genere las claves primero (opción 1).")
        return

    # Leer las claves
    with open('public_key.pem', 'rb') as f:
        pub = f.read()

    with open('private_key.pem', 'rb') as f:
        priv = f.read()

    # Prueba 1: Documento de texto
    print("\nPrueba 1: Documento legal")
    doc = b"Contrato de confidencialidad No. 2025-GT-001\nEntre las oficinas de Guatemala City, Miami y Madrid."
    print(f"Documento original ({len(doc)} bytes):")
    print(doc.decode())

    pkg = encrypt_document(doc, pub)
    print(f"\nPaquete cifrado: {len(pkg)} bytes")

    resultado = decrypt_document(pkg, priv)
    print(f"\nDocumento descifrado:")
    print(resultado.decode())
    print(f"\nDescifrado correcto: {resultado == doc}")

    # Prueba 2: Archivo grande
    print("\n\nPrueba 2: Archivo de 1 MB (simulación de contrato con imágenes)")
    doc_grande = os.urandom(1024 * 1024)
    print(f"Tamaño del documento: {len(doc_grande):,} bytes")

    pkg2 = encrypt_document(doc_grande, pub)
    print(f"Tamaño del paquete cifrado: {len(pkg2):,} bytes")

    resultado_grande = decrypt_document(pkg2, priv)
    verificacion = resultado_grande == doc_grande
    print(f"Descifrado correcto: {verificacion}")

    if verificacion:
        print("\n¡Archivo de 1 MB cifrado y descifrado exitosamente!")


def ejecutar_todas_pruebas():
    """
    Ejecuta todas las pruebas del laboratorio de forma automática.
    """
    print("\n" + "=" * 60)
    print("   EJECUTANDO TODAS LAS PRUEBAS")
    print("=" * 60)

    # 1. Generar claves
    print("\n1. Generando claves RSA de 2048 bits...")
    generar_par_claves(2048)
    print("   ✓ Claves generadas")

    # Leer las claves
    with open('public_key.pem', 'rb') as f:
        pub = f.read()

    with open('private_key.pem', 'rb') as f:
        priv = f.read()

    # 2. Cifrado directo RSA
    print("\n2. Probando cifrado directo RSA-OAEP...")
    mensaje = b"Mensaje de prueba confidencial"
    c1 = cifrar_con_rsa(mensaje, pub)
    c2 = cifrar_con_rsa(mensaje, pub)
    d1 = descifrar_con_rsa(c1, priv)
    print(f"   ✓ Cifrado aleatorio: {c1 != c2}")
    print(f"   ✓ Descifrado correcto: {d1 == mensaje}")

    # 3. Cifrado híbrido
    print("\n3. Probando cifrado híbrido RSA + AES-GCM...")
    doc = b"Contrato de confidencialidad No. 2025-GT-001"
    pkg = encrypt_document(doc, pub)
    resultado = decrypt_document(pkg, priv)
    print(f"   ✓ Documento pequeño: {resultado == doc}")

    doc_grande = os.urandom(1024 * 1024)
    pkg2 = encrypt_document(doc_grande, pub)
    resultado_grande = decrypt_document(pkg2, priv)
    print(f"   ✓ Archivo 1 MB: {resultado_grande == doc_grande}")

    print("\n" + "=" * 60)
    print("   TODAS LAS PRUEBAS COMPLETADAS EXITOSAMENTE")
    print("=" * 60)


def main():
    """
    Función principal que maneja el flujo del programa.
    """
    while True:
        mostrar_menu()

        try:
            opcion = input("\nSeleccione una opción: ")

            if opcion == '1':
                prueba_generacion_claves()

            elif opcion == '2':
                prueba_cifrado_rsa()

            elif opcion == '3':
                prueba_cifrado_hibrido()

            elif opcion == '4':
                ejecutar_todas_pruebas()

            elif opcion == '5':
                print("\n¡Hasta pronto!")
                break

            else:
                print("\nOpción no válida. Intente de nuevo.")

        except KeyboardInterrupt:
            print("\n\nPrograma interrumpido por el usuario.")
            break
        except Exception as e:
            print(f"\nError: {e}")
            print("Por favor, intente nuevamente.")


if __name__ == '__main__':
    main()
