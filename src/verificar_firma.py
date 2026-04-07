"""
Módulo para verificar firma digital del manifiesto
Laboratorio de Hashes y Firmas Digitales

El hospital verifica que SHA256SUMS.txt fue creado por MediSoft
y no fue alterado, usando la clave pública de MediSoft.
"""

import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# Directorio de salida para archivos de Hashes y Firmas
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'hashes')


def verificar_firma(
    manifiesto: str = None,
    clave_publica_pem: str = None,
    firma: str = None
) -> bool:
    """
    Verifica la firma digital de SHA256SUMS.txt usando la clave pública de MediSoft.
    Retorna True si la firma es válida, False si fue alterada.
    Imprime resultado claro: FIRMA VÁLIDA o FIRMA INVÁLIDA con explicación.
    """
    # Rutas por defecto
    if manifiesto is None:
        manifiesto = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')
    if clave_publica_pem is None:
        clave_publica_pem = os.path.join(OUTPUT_DIR, 'medisoft_pub.pem')
    if firma is None:
        firma = os.path.join(OUTPUT_DIR, 'SHA256SUMS.sig')

    # Verificar que existen los archivos necesarios
    for archivo in [manifiesto, clave_publica_pem, firma]:
        if not os.path.exists(archivo):
            print(f"Error: No se encontró {archivo}")
            return False

    # Leer el contenido del manifiesto
    with open(manifiesto, 'rb') as f:
        contenido = f.read()

    # Calcular hash SHA-256 del contenido
    hash_obj = SHA256.new(contenido)

    # Cargar clave pública
    with open(clave_publica_pem, 'rb') as f:
        clave_publica = RSA.import_key(f.read())

    # Leer firma
    with open(firma, 'rb') as f:
        firma_bytes = f.read()

    # Crear verificador PSS y verificar firma
    verificador = pss.new(clave_publica)

    try:
        verificador.verify(hash_obj, firma_bytes)
        print("FIRMA VÁLIDA")
        print("El manifiesto SHA256SUMS.txt fue firmado por MediSoft")
        print("y no ha sido alterado desde su publicación.")
        return True
    except (ValueError, TypeError):
        print("FIRMA INVÁLIDA")
        print("El manifiesto SHA256SUMS.txt ha sido alterado o")
        print("la firma no corresponde a la clave pública de MediSoft.")
        return False


if __name__ == '__main__':
    print("=== Verificación de Firma Digital del Manifiesto ===\n")
    print("Simulando verificación por administrador TI del hospital\n")

    # Rutas de archivos
    manifiesto_path = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')
    clave_publica_path = os.path.join(OUTPUT_DIR, 'medisoft_pub.pem')
    firma_path = os.path.join(OUTPUT_DIR, 'SHA256SUMS.sig')

    # Verificar que existen los archivos necesarios
    archivos_requeridos = [manifiesto_path, clave_publica_path, firma_path]
    for archivo in archivos_requeridos:
        if not os.path.exists(archivo):
            print(f"Error: No se encontró {archivo}")
            print("Ejecute primero los módulos de generación de manifiesto y firma.")
            exit(1)

    # Guardar contenido original del manifiesto para restaurar después
    with open(manifiesto_path, 'rb') as f:
        manifiesto_original = f.read()

    # === ESCENARIO A: Todo válido ===
    print("=" * 60)
    print("ESCENARIO A: Verificación normal (todo válido)")
    print("=" * 60)
    print()
    resultado_a = verificar_firma(manifiesto_path, clave_publica_path, firma_path)
    print(f"\nResultado: {'ÉXITO' if resultado_a else 'FALLO'}")

    # === ESCENARIO B: Manifiesto alterado ===
    print("\n" + "=" * 60)
    print("ESCENARIO B: Manifiesto alterado (ataque man-in-the-middle)")
    print("=" * 60)

    # Modificar un carácter del manifiesto
    print("\nModificando un carácter del SHA256SUMS.txt...")
    manifiesto_alterado = bytearray(manifiesto_original)
    if manifiesto_alterado[0] != ord('X'):
        manifiesto_alterado[0] = ord('X')
    else:
        manifiesto_alterado[0] = ord('Y')

    with open(manifiesto_path, 'wb') as f:
        f.write(manifiesto_alterado)

    print(f"Primer carácter cambiado: '{chr(manifiesto_original[0])}' -> '{chr(manifiesto_alterado[0])}'")
    print()
    resultado_b = verificar_firma(manifiesto_path, clave_publica_path, firma_path)
    print(f"\nResultado: {'ÉXITO' if resultado_b else 'FALLO - Ataque detectado'}")

    # Restaurar manifiesto original
    with open(manifiesto_path, 'wb') as f:
        f.write(manifiesto_original)
    print("\nManifiesto restaurado a su estado original.")

    # === ESCENARIO C: Archivo del paquete modificado ===
    print("\n" + "=" * 60)
    print("ESCENARIO C: Archivo del paquete modificado")
    print("=" * 60)

    archivo_a_modificar = os.path.join(OUTPUT_DIR, 'medisoft_core.bin')
    if os.path.exists(archivo_a_modificar):
        # Modificar un byte del archivo
        with open(archivo_a_modificar, 'rb') as f:
            contenido_original = f.read()

        contenido_modificado = bytearray(contenido_original)
        contenido_modificado[0] ^= 0xFF

        with open(archivo_a_modificar, 'wb') as f:
            f.write(contenido_modificado)

        print(f"\nArchivo medisoft_core.bin modificado (byte invertido).")
        print("El manifiesto SHA256SUMS.txt NO fue alterado.")
        print()
        print("Verificando firma del manifiesto...")
        resultado_c = verificar_firma(manifiesto_path, clave_publica_path, firma_path)

        print(f"\nResultado de verificación de firma: {'VÁLIDA' if resultado_c else 'INVÁLIDA'}")

        # Ahora verificar el paquete con verificar_paquete
        print("\nPero al verificar integridad del paquete...")
        from .verificar_paquete import verificar_manifiesto
        resultado_integridad = verificar_manifiesto(manifiesto_path, OUTPUT_DIR)

        # Restaurar archivo original
        with open(archivo_a_modificar, 'wb') as f:
            f.write(contenido_original)
        print(f"\nArchivo medisoft_core.bin restaurado.")
    else:
        print(f"\nNo se encontró medisoft_core.bin para demostrar este escenario.")
        resultado_c = None

    # === ANÁLISIS FINAL ===
    print("\n" + "=" * 60)
    print("ANÁLISIS: ¿Por qué la firma es válida si el archivo cambió?")
    print("=" * 60)
    print("""
La firma digital RSA-PSS protege SOLO el contenido del archivo
SHA256SUMS.txt (el manifiesto), NO los archivos directamente.

- Si el manifiesto NO cambió → la firma sigue siendo válida
- Si un archivo del paquete cambió → verificar_paquete lo detecta

Las DOS capas son necesarias y complementarias:

1. FIRMA DIGITAL (verificar_firma.py):
   - Autentica QUIÉN creó el manifiesto (MediSoft)
   - Detecta si el manifiesto fue alterado
   - Sin firma, un atacante podría modificar archivos Y el manifiesto

2. VERIFICACIÓN DE INTEGRIDAD (verificar_paquete.py):
   - Verifica QUÉ contiene cada archivo
   - Compara hashes actuales vs hashes en el manifiesto
   - Detecta cualquier modificación a los archivos

Conclusión: Ambas verificaciones deben pasar para confiar en el paquete.
- Firma válida + integridad OK = paquete auténtico de MediSoft
- Firma válida + integridad FALLO = archivos corrompidos (error de descarga)
- Firma inválida = posible ataque man-in-the-middle
""")
