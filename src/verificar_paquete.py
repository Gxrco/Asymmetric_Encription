"""
Módulo para verificar integridad de paquete contra manifiesto
Laboratorio de Hashes y Firmas Digitales

Simula al administrador TI del hospital verificando que los archivos
descargados coinciden con los hashes publicados por MediSoft.
"""

import os
from .generar_manifiesto import sha256_archivo

# Directorio de salida para archivos de Hashes y Firmas
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'hashes')


def verificar_manifiesto(manifiesto: str = None, directorio: str = None) -> bool:
    """
    Verifica cada archivo listado en el manifiesto SHA256SUMS.txt.
    Retorna True si todos los archivos son válidos, False si alguno falló.
    Imprime reporte detallado de cada verificación.
    """
    if manifiesto is None:
        manifiesto = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')

    if directorio is None:
        directorio = OUTPUT_DIR

    if not os.path.exists(manifiesto):
        print(f"Error: No se encontró el archivo de manifiesto {manifiesto}")
        return False

    ok_count = 0
    fail_count = 0

    print(f"\nVerificando archivos contra {manifiesto}...")
    print("=" * 80)

    with open(manifiesto, 'r') as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue

            # Formato: <hash>  <nombre> (dos espacios)
            partes = linea.split('  ', 1)
            if len(partes) != 2:
                print(f"Línea mal formada: {linea}")
                fail_count += 1
                continue

            hash_esperado, nombre_archivo = partes

            # Buscar el archivo en el directorio especificado
            ruta_archivo = os.path.join(directorio, nombre_archivo)

            if not os.path.exists(ruta_archivo):
                print(f"FALLO: {nombre_archivo}")
                print(f"       Archivo no encontrado en {directorio}")
                fail_count += 1
                continue

            # Calcular hash actual del archivo
            hash_actual = sha256_archivo(ruta_archivo)

            if hash_actual == hash_esperado:
                print(f"OK:    {nombre_archivo}")
                ok_count += 1
            else:
                print(f"FALLO: {nombre_archivo}")
                print(f"       Esperado: {hash_esperado}")
                print(f"       Actual:   {hash_actual}")
                fail_count += 1

    print("=" * 80)
    print(f"\nResumen: {ok_count} OK, {fail_count} FALLIDOS")

    if fail_count == 0:
        print("\nTodos los archivos pasaron la verificación de integridad.")
        return True
    else:
        print("\nADVERTENCIA: Algunos archivos no coinciden con el manifiesto.")
        print("Los archivos pueden haber sido modificados o corrompidos.")
        return False


if __name__ == '__main__':
    print("=== Verificación de Integridad del Paquete MediSoft ===\n")
    print("Simulando verificación por administrador TI del hospital\n")

    # Asegurar que el directorio de salida existe
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Rutas de archivos
    manifiesto_path = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')

    # Primero asegurarse de que existen los archivos de prueba
    archivos_prueba = [
        ('medisoft_core.bin', b'MediSoft Core Engine v2.1.0 - Procesamiento de muestras de laboratorio'),
        ('medisoft_db.dll', b'MediSoft Database Module - Conexion segura con base de datos de pacientes'),
        ('medisoft_ui.exe', b'MediSoft User Interface - Interfaz grafica para tecnicos de laboratorio'),
        ('medisoft_report.dll', b'MediSoft Report Generator - Generacion de informes medicos en PDF'),
        ('medisoft_config.xml', b'<?xml version="1.0"?><config><hospital>Guatemala Central</hospital></config>')
    ]

    # Crear archivos si no existen
    rutas_completas = []
    for nombre, contenido in archivos_prueba:
        ruta = os.path.join(OUTPUT_DIR, nombre)
        if not os.path.exists(ruta):
            with open(ruta, 'wb') as f:
                f.write(contenido)
        rutas_completas.append(ruta)

    # Regenerar manifiesto limpio
    if os.path.exists(manifiesto_path):
        os.remove(manifiesto_path)

    from .generar_manifiesto import generar_manifiesto
    print("Generando manifiesto fresco...")
    with open(os.devnull, 'w') as devnull:
        import sys
        old_stdout = sys.stdout
        sys.stdout = devnull
        generar_manifiesto(rutas_completas, manifiesto_path)
        sys.stdout = old_stdout
    print("Manifiesto generado.\n")

    # === Escenario 1: Verificación normal (todos correctos) ===
    print("=" * 60)
    print("ESCENARIO 1: Verificación normal (archivos intactos)")
    print("=" * 60)

    resultado = verificar_manifiesto(manifiesto_path, OUTPUT_DIR)
    print(f"\nResultado: {'ÉXITO' if resultado else 'FALLO'}")

    # === Escenario 2: Archivo modificado (detección de tamper) ===
    print("\n" + "=" * 60)
    print("ESCENARIO 2: Archivo modificado (simulando ataque)")
    print("=" * 60)

    # Modificar un byte del archivo
    archivo_a_modificar = os.path.join(OUTPUT_DIR, 'medisoft_core.bin')
    print(f"\nModificando primer byte de medisoft_core.bin...")

    with open(archivo_a_modificar, 'rb') as f:
        contenido = bytearray(f.read())

    # Guardar byte original para restaurar después
    byte_original = contenido[0]
    contenido[0] ^= 0xFF  # XOR con 0xFF invierte todos los bits

    with open(archivo_a_modificar, 'wb') as f:
        f.write(contenido)

    print(f"Byte modificado: {byte_original:02X} -> {contenido[0]:02X}")

    resultado = verificar_manifiesto(manifiesto_path, OUTPUT_DIR)
    print(f"\nResultado: {'ÉXITO' if resultado else 'FALLO - ¡Ataque detectado!'}")

    # Restaurar archivo original
    contenido[0] = byte_original
    with open(archivo_a_modificar, 'wb') as f:
        f.write(contenido)
    print(f"\nArchivo medisoft_core.bin restaurado a su estado original.")

    # === Conclusión ===
    print("\n" + "=" * 60)
    print("CONCLUSIÓN")
    print("=" * 60)
    print("\nEl manifiesto SHA256SUMS.txt permite detectar cualquier modificación")
    print("a los archivos del paquete, incluso cambios de un solo byte.")
    print("\nSin embargo, un atacante podría modificar tanto los archivos como")
    print("el manifiesto. Por eso es necesario firmar digitalmente el manifiesto")
    print("con la clave privada de MediSoft (ver módulo firmar_manifiesto.py).")
