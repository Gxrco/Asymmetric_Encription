# Laboratorio de Cifrado Asimétrico - RSAß

## Descripción del Proyecto

Este proyecto implementa un sistema de transferencia segura de documentos legales utilizando criptografía asimétrica RSA y cifrado híbrido RSA-OAEP + AES-GCM. El sistema está diseñado para una firma de abogados que necesita transferir documentos confidenciales entre sus oficinas en Guatemala City, Miami y Madrid.

### Escenario

Una firma de abogados requiere transferir documentos confidenciales (contratos, acuerdos de confidencialidad, datos personales) garantizando que solo el destinatario autorizado pueda leer el contenido. El sistema utiliza:

- **RSA-OAEP** para el intercambio seguro de claves
- **AES-256-GCM** para el cifrado eficiente de documentos
- **Cifrado híbrido** que combina las ventajas de ambos sistemas

## Uso
Existe un menú interactivo para ejecutar cada parte del proyecto, correspondiente a cada módulo implementado.
Las siguientes opciones disponibles son:

### Opciones del Menú 

1. **Generar par de claves RSA**
   - Permite generar claves de 2048 o 3072 bits
   - Guarda las claves en formato PEM
   - La clave privada está protegida con passphrase

2. **Cifrado directo con RSA-OAEP**
   - Para mensajes pequeños (< 190 bytes)
   - Demuestra la aleatoriedad del padding OAEP

3. **Cifrado híbrido RSA + AES-GCM**
   - Para documentos de cualquier tamaño
   - Incluye prueba con archivo de 1 MB

4. **Ejecutar todas las pruebas**
   - Ejecuta todas las funcionalidades automáticamente
   - Útil para verificar que todo funciona correctamente

5. **Salir**

### Ejecución de Módulos Individuales

También puedes ejecutar cada módulo por separado:

```bash
# Generar claves
python generar_claves.py

# Probar cifrado directo RSA
python cifrado_rsa.py

# Probar cifrado híbrido
python cifrado_hibrido.py
```

## Ejemplos de Ejecución

### Ejemplo 1: Generación de Claves

```bash
$ python generar_claves.py
Claves generadas exitosamente:
  - private_key.pem (protegida con passphrase)
  - public_key.pem
```

### Ejemplo 2: Cifrado Directo RSA-OAEP

```python
from cifrado_rsa import cifrar_con_rsa, descifrar_con_rsa

# Leer claves
with open('public_key.pem', 'rb') as f:
    pub = f.read()
with open('private_key.pem', 'rb') as f:
    priv = f.read()

# Cifrar mensaje
mensaje = b"Documento confidencial"
cifrado = cifrar_con_rsa(mensaje, pub)

# Descifrar
original = descifrar_con_rsa(cifrado, priv)
print(original.decode())  # "Documento confidencial"
```

### Ejemplo 3: Cifrado Híbrido

```python
from cifrado_hibrido import encrypt_document, decrypt_document

# Cifrar documento grande
documento = b"Contrato de confidencialidad No. 2025-GT-001" * 1000
paquete = encrypt_document(documento, pub)

# Descifrar
original = decrypt_document(paquete, priv)
assert original == documento  # Verificación exitosa
```

## Respuestas a las Preguntas de Análisis

### 1. ¿Explique por qué no cifrar el documento directamente con RSA?

**Respuesta:**

RSA tiene varias limitaciones que lo hacen inadecuado para cifrar documentos completos:

1. **Limitación de tamaño**: RSA solo puede cifrar datos hasta un tamaño máximo determinado por el tamaño de la clave menos el overhead del padding. Para una clave de 2048 bits con OAEP, el máximo es aproximadamente 190 bytes.

2. **Rendimiento**: RSA es computacionalmente muy costoso. Cifrar un documento de 1 MB directamente con RSA sería extremadamente lento comparado con algoritmos simétricos como AES.

3. **Seguridad**: Cifrar bloques grandes de datos con RSA requeriría dividirlos en fragmentos pequeños, lo cual podría comprometer la seguridad si no se implementa correctamente.

**Solución - Cifrado Híbrido:**
- Se genera una clave AES aleatoria de 256 bits
- El documento se cifra con AES-256-GCM (rápido y seguro)
- Solo la clave AES (32 bytes) se cifra con RSA-OAEP
- Esto combina la velocidad de AES con la seguridad del intercambio de claves de RSA

### 2. ¿Qué información contiene un archivo .pem? Abre public_key.pem con un editor de texto y describe su estructura.

**Respuesta:**

Un archivo PEM (Privacy Enhanced Mail) contiene datos criptográficos codificados en Base64 con encabezados y pies de página específicos.

**Estructura de public_key.pem:**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
[Datos codificados en Base64]
...
-----END PUBLIC KEY-----
```

**Contenido:**
- **Encabezado**: Identifica el tipo de clave
- **Datos en Base64**: La clave pública en formato DER (Distinguished Encoding Rules)
- **Información incluida**:
  - Módulo (n): El producto de dos números primos grandes
  - Exponente público (e): Generalmente 65537

**Estructura de private_key.pem:**
```
-----BEGIN ENCRYPTED PRIVATE KEY-----
[Datos cifrados en Base64]
-----END ENCRYPTED PRIVATE KEY-----
```

**Contenido:**
- Similar al público pero cifrado con la passphrase
- Incluye el exponente privado (d) y otros parámetros para optimización

### 3. ¿Por qué cifrar el mismo mensaje dos veces produce resultados distintos? Demuéstrenlo y expliquen qué propiedad de OAEP lo causa.

**Respuesta:**

Esto se debe al **padding OAEP (Optimal Asymmetric Encryption Padding)** que añade aleatoriedad al proceso de cifrado.

**Proceso de OAEP:**

1. **Generación de valores aleatorios**: OAEP genera un valor aleatorio diferente en cada cifrado
2. **Padding aleatorio**: Este valor se combina con el mensaje usando funciones hash
3. **Resultado**: Aunque el mensaje sea idéntico, el padding cambia en cada cifrado

**Demostración:**
```python
mensaje = b"Mensaje confidencial"
cifrado1 = cifrar_con_rsa(mensaje, pub)
cifrado2 = cifrar_con_rsa(mensaje, pub)

print(cifrado1 == cifrado2)  # False
```

**Propiedad de seguridad:**

Esta característica es fundamental para la seguridad porque:
- **Previene ataques de análisis**: Un atacante no puede saber si dos mensajes cifrados son iguales
- **Protege contra ataques de texto conocido**: Aunque el atacante conozca el mensaje, no puede verificarlo comparando cifrados
- **Aleatoriedad criptográfica**: Hace que el cifrado sea probabilístico en lugar de determinístico

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
- **GCM (Galois/Counter Mode)**: Modo de operación que proporciona:
  - Cifrado
  - Autenticación (integridad del mensaje)
  - Uso de nonce para evitar repetición de claves de flujo

## Protocolos Reales que Usan RSA

1. **TLS 1.3**: Aunque TLS 1.3 prefiere curvas elípticas, RSA sigue usándose para:
   - Firma digital de certificados
   - Intercambio de claves (en versiones anteriores)

2. **Certificados X.509**: Formato estándar para certificados digitales
   - La clave pública se codifica en el certificado
   - La autoridad certificadora firma con su clave privada RSA

3. **SSH (Secure Shell)**:
   - Autenticación de host
   - Autenticación de usuario con claves RSA

## Recomendaciones de Seguridad

1. **Tamaño de clave**: Usar mínimo 2048 bits, recomendado 3072 bits para nuevas aplicaciones
2. **Padding**: Siempre usar OAEP, nunca PKCS#1 v1.5 (vulnerable)
3. **Protección de clave privada**: Usar passphrase fuerte
4. **Cifrado híbrido**: Usar RSA solo para intercambio de claves, AES para datos
5. **Modo de AES**: Usar GCM que proporciona autenticación