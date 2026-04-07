"""
Módulo para generar manifiesto SHA256SUMS.txt
Laboratorio de Hashes y Firmas Digitales

Simula el rol de MediSoft al publicar un release: calcula SHA-256
de cada archivo y construye el archivo de manifiesto.
"""

import hashlib
import os

# Directorio de salida para archivos de Hashes y Firmas
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'output', 'hashes')


def sha256_archivo(ruta: str) -> str:
    """
    Calcula SHA-256 de un archivo leyendo en bloques de 65536 bytes.
    Funciona correctamente con archivos de cualquier tamaño sin cargar todo en memoria.
    """
    sha256 = hashlib.sha256()

    with open(ruta, 'rb') as f:
        while True:
            bloque = f.read(65536)  # 64 KB
            if not bloque:
                break
            sha256.update(bloque)

    return sha256.hexdigest()


def generar_manifiesto(archivos: list[str], salida: str = None) -> None:
    """
    Calcula SHA-256 de cada archivo y agrega las entradas al historial SHA256SUMS.txt.
    Formato por línea: '<hash>  <nombre_archivo>' (dos espacios, estilo sha256sum de Linux).
    """
    # Asegurar que el directorio de salida existe
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if salida is None:
        salida = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')

    with open(salida, 'a') as f:
        for archivo in archivos:
            if not os.path.exists(archivo):
                print(f"Advertencia: {archivo} no existe, omitiendo...")
                continue

            hash_sha256 = sha256_archivo(archivo)
            nombre = os.path.basename(archivo)

            # Formato: hash  nombre (dos espacios entre hash y nombre)
            linea = f"{hash_sha256}  {nombre}\n"
            f.write(linea)

            print(f"Procesado: {nombre}")
            print(f"  SHA-256: {hash_sha256}")


if __name__ == '__main__':
    print("=== Generación de Manifiesto SHA256SUMS.txt ===\n")
    print("Simulando publicación de release MediSoft v2.1.0\n")

    # Asegurar que el directorio de salida existe
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Rutas de archivos
    manifiesto_path = os.path.join(OUTPUT_DIR, 'SHA256SUMS.txt')

    # Limpiar archivo de manifiesto anterior para demostración reproducible
    if os.path.exists(manifiesto_path):
        os.remove(manifiesto_path)
        print("Limpiado SHA256SUMS.txt anterior\n")

    # Crear 5 archivos de prueba simulando componentes de software médico
    archivos_prueba = [
        ('medisoft_core.bin', b'MediSoft Core Engine v2.1.0 - Procesamiento de muestras de laboratorio'),
        ('medisoft_db.dll', b'MediSoft Database Module - Conexion segura con base de datos de pacientes'),
        ('medisoft_ui.exe', b'MediSoft User Interface - Interfaz grafica para tecnicos de laboratorio'),
        ('medisoft_report.dll', b'MediSoft Report Generator - Generacion de informes medicos en PDF'),
        ('medisoft_config.xml', b'<?xml version="1.0"?><config><hospital>Guatemala Central</hospital></config>')
    ]

    print("Creando archivos de prueba en output/hashes/...")
    print("-" * 60)

    rutas_completas = []
    for nombre, contenido in archivos_prueba:
        ruta = os.path.join(OUTPUT_DIR, nombre)
        with open(ruta, 'wb') as f:
            f.write(contenido)
        rutas_completas.append(ruta)
        print(f"  Creado: {ruta} ({len(contenido)} bytes)")

    print("-" * 60)
    print()

    # Generar manifiesto
    print("Generando manifiesto SHA256SUMS.txt...")
    print("-" * 60)
    generar_manifiesto(rutas_completas, manifiesto_path)
    print("-" * 60)

    # Mostrar contenido del manifiesto generado
    print(f"\n=== Contenido de {manifiesto_path} ===\n")
    with open(manifiesto_path, 'r') as f:
        print(f.read())

    print("El manifiesto sigue el formato estándar de sha256sum (Linux):")
    print("  <hash_64_caracteres>  <nombre_archivo>")
    print("\nEste archivo será firmado digitalmente por MediSoft")
    print("para que los hospitales puedan verificar su autenticidad.")
