# Análisis Lab RSA - Cifrado Asimétrico

## 1. ¿Por qué no cifrar el documento directamente con RSA?

RSA tiene varias limitaciones que lo hacen inadecuado para cifrar documentos completos:

### Limitación de tamaño
RSA solo puede cifrar datos hasta un tamaño máximo determinado por el tamaño de la clave menos el overhead del padding. Para una clave de 2048 bits con OAEP, el máximo es aproximadamente **190 bytes**.

### Rendimiento
RSA es computacionalmente muy costoso. Cifrar un documento de 1 MB directamente con RSA sería extremadamente lento comparado con algoritmos simétricos como AES.

### Seguridad
Cifrar bloques grandes de datos con RSA requeriría dividirlos en fragmentos pequeños, lo cual podría comprometer la seguridad si no se implementa correctamente.

### Solución: Cifrado Híbrido
- Se genera una clave AES aleatoria de 256 bits
- El documento se cifra con AES-256-GCM (rápido y seguro)
- Solo la clave AES (32 bytes) se cifra con RSA-OAEP
- Esto combina la velocidad de AES con la seguridad del intercambio de claves de RSA

---

## 2. ¿Qué información contiene un archivo .pem?

Un archivo PEM (Privacy Enhanced Mail) contiene datos criptográficos codificados en Base64 con encabezados y pies de página específicos.

### Estructura de public_key.pem
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
[Datos codificados en Base64]
...
-----END PUBLIC KEY-----
```

### Contenido
- **Encabezado**: Identifica el tipo de clave
- **Datos en Base64**: La clave pública en formato DER (Distinguished Encoding Rules)
- **Información incluida**:
  - Módulo (n): El producto de dos números primos grandes
  - Exponente público (e): Generalmente 65537

### Estructura de private_key.pem
```
-----BEGIN ENCRYPTED PRIVATE KEY-----
[Datos cifrados en Base64]
-----END ENCRYPTED PRIVATE KEY-----
```

La clave privada está cifrada con la passphrase e incluye el exponente privado (d) y otros parámetros para optimización.

---

## 3. ¿Por qué cifrar el mismo mensaje dos veces produce resultados distintos?

Esto se debe al **padding OAEP (Optimal Asymmetric Encryption Padding)** que añade aleatoriedad al proceso de cifrado.

### Proceso de OAEP
1. **Generación de valores aleatorios**: OAEP genera un valor aleatorio diferente en cada cifrado
2. **Padding aleatorio**: Este valor se combina con el mensaje usando funciones hash
3. **Resultado**: Aunque el mensaje sea idéntico, el padding cambia en cada cifrado

### Demostración
```python
mensaje = b"Mensaje confidencial"
cifrado1 = cifrar_con_rsa(mensaje, pub)
cifrado2 = cifrar_con_rsa(mensaje, pub)

print(cifrado1 == cifrado2)  # False
```

### Propiedad de seguridad
Esta característica es fundamental para la seguridad porque:
- **Previene ataques de análisis**: Un atacante no puede saber si dos mensajes cifrados son iguales
- **Protege contra ataques de texto conocido**: Aunque el atacante conozca el mensaje, no puede verificarlo comparando cifrados
- **Aleatoriedad criptográfica**: Hace que el cifrado sea probabilístico en lugar de determinístico

---

## Fundamentación Matemática

### RSA - Conceptos Clave
1. **Factorización de primos**: La seguridad de RSA se basa en la dificultad de factorizar números muy grandes en sus factores primos.
2. **Aritmética modular**:
   - Cifrado: c = m^e mod n
   - Descifrado: m = c^d mod n
3. **Teorema de Euler**: φ(n) = (p-1)(q-1), donde n = p × q

### Padding OAEP
OAEP añade estructura al mensaje antes del cifrado RSA para:
- Prevenir ataques de texto conocido
- Añadir aleatoriedad
- Proveer seguridad semántica

### AES-GCM
- **AES-256**: Cifrado simétrico de bloque con clave de 256 bits
- **GCM (Galois/Counter Mode)**: Modo de operación que proporciona cifrado y autenticación
