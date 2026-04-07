"""
Módulo para explorar propiedades de algoritmos hash
Laboratorio de Hashes y Firmas Digitales

Demuestra el efecto avalancha y compara MD5, SHA-1, SHA-256 y SHA-3/256.
"""

import hashlib


def calcular_hashes(texto: str) -> dict:
    """
    Calcula MD5, SHA-1, SHA-256 y SHA-3/256 de un texto.
    Retorna un diccionario con el nombre del algoritmo como clave y el hexdigest como valor.
    """
    datos = texto.encode('utf-8')

    return {
        'MD5': hashlib.md5(datos).hexdigest(),
        'SHA-1': hashlib.sha1(datos).hexdigest(),
        'SHA-256': hashlib.sha256(datos).hexdigest(),
        'SHA-3/256': hashlib.sha3_256(datos).hexdigest()
    }


def bits_diferentes(hash1: str, hash2: str) -> int:
    """
    Cuenta bits distintos entre dos hexdigests usando XOR.
    Demuestra el efecto avalancha: un cambio mínimo produce ~50% de bits diferentes.
    """
    # Convertir hexdigests a bytes
    bytes1 = bytes.fromhex(hash1)
    bytes2 = bytes.fromhex(hash2)

    # Contar bits diferentes usando XOR
    bits_diff = 0
    for b1, b2 in zip(bytes1, bytes2):
        xor = b1 ^ b2
        # Contar bits en 1 del resultado XOR
        bits_diff += bin(xor).count('1')

    return bits_diff


def imprimir_tabla(resultados: list[dict]) -> None:
    """
    Imprime una tabla comparativa con Algoritmo, Bits, Hex chars y Hash.
    """
    # Información de cada algoritmo
    info_algoritmos = {
        'MD5': 128,
        'SHA-1': 160,
        'SHA-256': 256,
        'SHA-3/256': 256
    }

    print("\n" + "=" * 100)
    print(f"{'Algoritmo':<12} {'Bits':>6} {'Hex chars':>10}   {'Hash value'}")
    print("=" * 100)

    for resultado in resultados:
        texto = resultado['texto']
        hashes = resultado['hashes']
        print(f"\nTexto: \"{texto}\"")
        print("-" * 100)

        for algo, hash_val in hashes.items():
            bits = info_algoritmos[algo]
            hex_chars = len(hash_val)
            print(f"{algo:<12} {bits:>6} {hex_chars:>10}   {hash_val}")

    print("\n" + "=" * 100)


if __name__ == '__main__':
    print("=== Exploración de Algoritmos Hash ===\n")

    # Textos a comparar
    texto1 = "MediSoft-v2.1.0"
    texto2 = "medisoft-v2.1.0"  # Solo cambia capitalización

    print(f"Texto 1: \"{texto1}\"")
    print(f"Texto 2: \"{texto2}\"")
    print("\n(Solo cambia 'M' por 'm' - un bit de diferencia en ASCII)")

    # Calcular hashes
    hashes1 = calcular_hashes(texto1)
    hashes2 = calcular_hashes(texto2)

    # Imprimir tabla comparativa
    resultados = [
        {'texto': texto1, 'hashes': hashes1},
        {'texto': texto2, 'hashes': hashes2}
    ]
    imprimir_tabla(resultados)

    # Demostrar efecto avalancha con SHA-256
    print("\n=== Efecto Avalancha (SHA-256) ===\n")

    sha256_1 = hashes1['SHA-256']
    sha256_2 = hashes2['SHA-256']

    print(f"SHA-256 texto 1: {sha256_1}")
    print(f"SHA-256 texto 2: {sha256_2}")

    bits_diff = bits_diferentes(sha256_1, sha256_2)
    total_bits = 256
    porcentaje = (bits_diff / total_bits) * 100

    print(f"\nBits diferentes: {bits_diff} de {total_bits} ({porcentaje:.1f}%)")
    print(f"\nConclusión: Un cambio mínimo (una letra) produce ~{porcentaje:.0f}% de bits diferentes.")
    print("Esto demuestra la propiedad de EFECTO AVALANCHA de los hashes criptográficos.")

    # Explicación sobre MD5
    print("\n=== ¿Por qué MD5 es inseguro para integridad? ===\n")
    print("1. MD5 produce solo 128 bits de salida.")
    print("   - Ataques de cumpleaños requieren O(2^64) operaciones, factible con hardware moderno.")
    print("\n2. Existen colisiones MD5 conocidas y publicadas.")
    print("   - Un atacante puede fabricar dos archivos distintos con el mismo MD5.")
    print("\n3. Para software médico (MediSoft), esto es inaceptable:")
    print("   - Un binario malicioso podría reemplazar al legítimo sin detección.")
    print("   - Se recomienda usar SHA-256 o SHA-3 para verificación de integridad.")
