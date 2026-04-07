"""
Tests para los módulos del Lab Hashes y Firmas Digitales

Prompt: Genera los tests para los módulos implementados en la generación de hashes y firmas digitales.
- generar_claves_rsa.py
- explorar_hashes.py
- generar_manifiesto.py
- verificar_paquete.py
- firmar_manifiesto.py
- verificar_firma.py
Estas funcionalidades has sido validadas en las pruebas generales.
Cubre los casos adicionales que muestren evidencias más específicas de la correcta implementación de cada módulo.
"""

import os
import pytest
from src.explorar_hashes import calcular_hashes, bits_diferentes
from src.generar_manifiesto import sha256_archivo, generar_manifiesto
from src.verificar_paquete import verificar_manifiesto
from src.generar_claves_rsa import generar_claves_medisoft
from src.firmar_manifiesto import firmar_manifiesto
from src.verificar_firma import verificar_firma


class TestHashes:
    """Tests para el módulo explorar_hashes."""

    def test_calcular_hashes_algoritmos(self):
        """Verifica que se calculen los 4 algoritmos."""
        hashes = calcular_hashes("test")

        assert 'MD5' in hashes
        assert 'SHA-1' in hashes
        assert 'SHA-256' in hashes
        assert 'SHA-3/256' in hashes

    def test_calcular_hashes_longitudes(self):
        """Verifica que los hashes tengan la longitud correcta."""
        hashes = calcular_hashes("test")

        assert len(hashes['MD5']) == 32, "MD5 debe tener 32 hex chars (128 bits)"
        assert len(hashes['SHA-1']) == 40, "SHA-1 debe tener 40 hex chars (160 bits)"
        assert len(hashes['SHA-256']) == 64, "SHA-256 debe tener 64 hex chars (256 bits)"
        assert len(hashes['SHA-3/256']) == 64, "SHA-3/256 debe tener 64 hex chars (256 bits)"

    def test_efecto_avalancha(self):
        """Verifica que cambiar un carácter produce hashes completamente distintos."""
        hashes1 = calcular_hashes("MediSoft-v2.1.0")
        hashes2 = calcular_hashes("medisoft-v2.1.0")

        # Los hashes deben ser completamente diferentes
        for algo in hashes1:
            assert hashes1[algo] != hashes2[algo], f"{algo} no muestra efecto avalancha"

    def test_bits_diferentes_aproximadamente_mitad(self):
        """El XOR entre dos SHA-256 de entradas similares debe cambiar ~50% de bits."""
        hashes1 = calcular_hashes("MediSoft-v2.1.0")
        hashes2 = calcular_hashes("medisoft-v2.1.0")

        bits_diff = bits_diferentes(hashes1['SHA-256'], hashes2['SHA-256'])

        # Debe estar entre 25% y 75% (64-192 bits de 256)
        # Típicamente estará cerca del 50% (~128 bits)
        assert 64 <= bits_diff <= 192, f"Bits diferentes fuera de rango esperado: {bits_diff}"

        # Verificar que está razonablemente cerca del 50%
        porcentaje = (bits_diff / 256) * 100
        assert 30 <= porcentaje <= 70, f"Porcentaje de bits diferentes muy alejado del 50%: {porcentaje}%"


class TestManifiesto:
    """Tests para los módulos de manifiesto."""

    @pytest.fixture(autouse=True)
    def setup_archivos_prueba(self, tmp_path):
        """Crea archivos de prueba antes de cada test."""
        self.original_dir = os.getcwd()
        os.chdir(tmp_path)

        # Crear archivos de prueba
        self.archivos = ['test1.txt', 'test2.txt', 'test3.txt']
        for i, nombre in enumerate(self.archivos):
            with open(nombre, 'wb') as f:
                f.write(f"Contenido del archivo {i+1}".encode())

        yield

        os.chdir(self.original_dir)

    def test_sha256_archivo(self):
        """Verifica que sha256_archivo calcule correctamente."""
        hash_val = sha256_archivo('test1.txt')

        assert len(hash_val) == 64, "SHA-256 debe tener 64 caracteres hex"
        assert all(c in '0123456789abcdef' for c in hash_val), "Hash debe ser hexadecimal"

    def test_generar_manifiesto_crea_archivo(self):
        """Verifica que se cree el archivo de manifiesto."""
        generar_manifiesto(self.archivos, 'SHA256SUMS.txt')

        assert os.path.exists('SHA256SUMS.txt'), "No se creó SHA256SUMS.txt"

    def test_generar_manifiesto_formato(self):
        """Verifica el formato del manifiesto (hash  nombre)."""
        generar_manifiesto(self.archivos, 'SHA256SUMS.txt')

        with open('SHA256SUMS.txt', 'r') as f:
            lineas = f.readlines()

        assert len(lineas) == len(self.archivos), "Número incorrecto de líneas"

        for linea in lineas:
            partes = linea.strip().split('  ')
            assert len(partes) == 2, "Formato incorrecto (debe ser 'hash  nombre')"
            hash_val, nombre = partes
            assert len(hash_val) == 64, "Hash debe tener 64 caracteres"
            assert nombre in self.archivos, f"Nombre de archivo no esperado: {nombre}"

    def test_manifiesto_detecta_tamper(self):
        """Modificar un byte de un archivo debe hacer fallar la verificación."""
        # Generar manifiesto
        generar_manifiesto(self.archivos, 'SHA256SUMS.txt')

        # Verificar que todo esté OK inicialmente
        assert verificar_manifiesto('SHA256SUMS.txt') == True

        # Modificar un archivo
        with open('test1.txt', 'rb') as f:
            contenido = bytearray(f.read())
        contenido[0] ^= 0xFF
        with open('test1.txt', 'wb') as f:
            f.write(contenido)

        # La verificación debe fallar
        assert verificar_manifiesto('SHA256SUMS.txt') == False


class TestFirmaDigital:
    """Tests para los módulos de firma digital."""

    @pytest.fixture(autouse=True)
    def setup_firmas(self, tmp_path):
        """Prepara ambiente para tests de firmas."""
        self.original_dir = os.getcwd()
        os.chdir(tmp_path)

        # Generar claves
        generar_claves_medisoft(2048)

        # Crear manifiesto de prueba
        with open('SHA256SUMS.txt', 'w') as f:
            f.write("abc123  archivo.txt\n")

        yield

        os.chdir(self.original_dir)

    def test_generar_claves_medisoft(self):
        """Verifica que se generen las claves de MediSoft."""
        assert os.path.exists('medisoft_priv.pem'), "No se generó medisoft_priv.pem"
        assert os.path.exists('medisoft_pub.pem'), "No se generó medisoft_pub.pem"

    def test_firmar_manifiesto_crea_sig(self):
        """Verifica que se cree el archivo de firma."""
        firmar_manifiesto('SHA256SUMS.txt', 'medisoft_priv.pem', 'SHA256SUMS.sig')

        assert os.path.exists('SHA256SUMS.sig'), "No se creó SHA256SUMS.sig"

    def test_firma_valida(self):
        """Verifica que una firma válida sea aceptada."""
        firmar_manifiesto('SHA256SUMS.txt', 'medisoft_priv.pem', 'SHA256SUMS.sig')

        assert verificar_firma('SHA256SUMS.txt', 'medisoft_pub.pem', 'SHA256SUMS.sig') == True

    def test_firma_invalida_si_manifiesto_alterado(self):
        """Cambiar el manifiesto debe invalidar la firma RSA-PSS."""
        firmar_manifiesto('SHA256SUMS.txt', 'medisoft_priv.pem', 'SHA256SUMS.sig')

        # Alterar el manifiesto
        with open('SHA256SUMS.txt', 'a') as f:
            f.write("modificado\n")

        # La verificación debe fallar
        assert verificar_firma('SHA256SUMS.txt', 'medisoft_pub.pem', 'SHA256SUMS.sig') == False

    def test_firma_tamano_correcto(self):
        """La firma RSA-2048 debe tener 256 bytes."""
        firmar_manifiesto('SHA256SUMS.txt', 'medisoft_priv.pem', 'SHA256SUMS.sig')

        with open('SHA256SUMS.sig', 'rb') as f:
            firma = f.read()

        # RSA-2048 produce firmas de 256 bytes (2048 bits / 8)
        assert len(firma) == 256, f"Tamaño de firma incorrecto: {len(firma)} bytes"
