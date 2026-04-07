# Análisis Lab Hashes y Firmas Digitales

## 1. ¿Cuántos bits cambiaron entre los dos SHA-256?

**Respuesta:** Entre los hashes SHA-256 de `"MediSoft-v2.1.0"` y `"medisoft-v2.1.0"` (solo cambia una letra mayúscula a minúscula), el XOR entre los bytes del hash produce aproximadamente **128 bits distintos** (≈50% de los 256 bits totales).

### Demostración empírica con explorar_hashes.py
```
SHA-256 de "MediSoft-v2.1.0":
  64942401fe64ac1182bd88326ba7ca57a23ea5d0475653dea996ac15e8e74996

SHA-256 de "medisoft-v2.1.0":
  ec8d163da33b9832c33fbb2d7cba98f5a7087aa6cbdecc04eb32810b1f1f895e

Bits diferentes (XOR): 128 de 256 (50%)
```

### Efecto Avalancha

Este resultado demuestra empíricamente el **efecto avalancha**, una propiedad fundamental de las funciones hash criptográficas:

- **Cambio mínimo → Hash completamente diferente**: Un solo carácter modificado produce un hash donde aproximadamente la mitad de los bits cambian
- **Impredecibilidad**: No se puede deducir el nuevo hash conociendo el anterior
- **Independencia**: Cada bit del hash depende de manera compleja de todos los bits de la entrada

### Importancia para seguridad

Esta propiedad es crucial porque:
1. **Impide ataques de aproximación**: No existe forma de "acercarse" al hash objetivo modificando gradualmente la entrada
2. **Previene análisis de patrones**: Entradas similares no producen hashes similares
3. **Protege contra fuerza bruta dirigida**: Cada intento de colisión es completamente independiente del anterior

---

## 2. ¿Por qué MD5 es inseguro para integridad de archivos?

**Respuesta:** MD5 es **criptográficamente roto** y no debe usarse para verificación de integridad de software. Dos razones concretas:

### 1. Longitud insuficiente (128 bits)

Con solo 128 bits de salida:
- **Ataques de cumpleaños** tienen complejidad O(2^64) operaciones
- **2^64 ≈ 18.4 quintillones** de operaciones es **factible con hardware moderno** (GPU clusters pueden ejecutar esto en días o semanas)
- Compare con SHA-256 que requiere 2^128 operaciones (completamente inviable)

### 2. Colisiones conocidas y publicadas

**El problema crítico:** Existen métodos documentados para construir colisiones MD5:
- En 2008, investigadores crearon certificados X.509 fraudulentos explotando colisiones MD5
- En 2012, se publicó el ataque "Flame malware" que usó colisión MD5 para falsificar certificados de Microsoft
- **Herramientas públicas** como `MD5 Collision Generator` permiten crear dos archivos con el mismo hash MD5

### Impacto para MediSoft (software médico)

Para software que controla equipos de laboratorio clínico, esto es **inaceptable**:

**Escenario de ataque:**
1. El atacante crea dos versiones de `medisoft_core.bin`:
   - Versión A: Binario legítimo (funcionalidad normal)
   - Versión B: Binario malicioso (backdoor, manipulación de resultados)
2. Mediante ingeniería de colisión, ambos archivos tienen el **mismo MD5**
3. MediSoft publica la versión A con su MD5
4. Un atacante man-in-the-middle reemplaza la versión A por la versión B durante la descarga
5. El hospital verifica el MD5 → **coincide** → instala el malware

### Conclusión

Para distribución de software crítico se debe usar:
- **SHA-256** (mínimo recomendado)
- **SHA-3** (estándar moderno alternativo)
- **NUNCA** MD5 o SHA-1 (también roto)

---

## 3. ¿Por qué la firma es válida si se modifica un archivo del paquete?

**Respuesta:** La firma digital RSA-PSS protege **solo el archivo `SHA256SUMS.txt`** (el manifiesto), **NO** los archivos del paquete directamente. Si un archivo se corrompe pero el manifiesto permanece intacto, la firma sigue siendo matemáticamente válida.

### Explicación del comportamiento

```
Flujo de verificación:
┌─────────────────────┐
│  SHA256SUMS.txt     │ ← Firmado con RSA-PSS por MediSoft
│  ─────────────────  │
│  hash1  file1.bin   │ ← Lista de hashes
│  hash2  file2.dll   │
│  hash3  file3.exe   │
└─────────────────────┘
         │
         ├─→ verificar_firma.py   → Verifica firma RSA-PSS
         │                          (Valida SI el manifiesto NO cambió)
         │
         └─→ verificar_paquete.py → Recalcula SHA-256 de cada archivo
                                     (Detecta SI un archivo cambió)
```

### Demostración empírica (verificar_firma.py)

**Escenario A - Todo válido:**
- Manifiesto intacto → Firma ✓ VÁLIDA
- Archivos intactos → Verificación ✓ OK

**Escenario B - Manifiesto alterado:**
- Manifiesto modificado → Firma ✗ INVÁLIDA
- (No importa el estado de los archivos)

**Escenario C - Archivo modificado, manifiesto intacto:**
- Manifiesto intacto → Firma ✓ **VÁLIDA** (la firma no cambia)
- Archivo modificado → Verificación ✗ **FALLO** (hash no coincide)

### Las dos capas son complementarias y necesarias

| Capa | Qué protege | Qué detecta | Implementación |
|------|------------|-------------|----------------|
| **Firma digital RSA-PSS** | Autenticidad e integridad **del manifiesto** | Alteración del manifiesto<br>Suplantación de MediSoft | `firmar_manifiesto.py`<br>`verificar_firma.py` |
| **Verificación de hashes** | Integridad **de cada archivo** | Corrupción de archivos<br>Modificación de binarios<br>Errores de descarga | `generar_manifiesto.py`<br>`verificar_paquete.py` |

### ¿Por qué ambas son necesarias?

**Sin firma digital (solo hashes SHA-256):**
- ✗ Un atacante puede modificar `medisoft_core.bin` Y actualizar `SHA256SUMS.txt` con el nuevo hash
- ✗ El hospital no puede verificar quién creó el manifiesto
- ✗ **Ataque man-in-the-middle posible**

**Sin verificación de hashes (solo firma):**
- ✗ La firma solo garantiza que el manifiesto es auténtico
- ✗ No detecta corrupción de archivos durante la descarga
- ✗ **Archivos dañados podrían instalarse**

### Tabla de diagnóstico completa

| Firma digital | Verificación hashes | Diagnóstico | Acción |
|--------------|---------------------|-------------|---------|
| ✓ Válida | ✓ Todos OK | Paquete auténtico e íntegro | Instalar |
| ✓ Válida | ✗ Fallo en archivos | Archivos corrompidos (red, disco) | Redescargar |
| ✗ Inválida | - | Ataque o manifiesto alterado | **NO INSTALAR** |

### Conclusión

La firma digital RSA-PSS NO protege los archivos directamente porque:
1. **Diseño del sistema**: La firma cubre el manifiesto, el manifiesto cubre los archivos
2. **Arquitectura de dos capas**: Firma = autenticidad, Hashes = integridad
3. **Ambas son necesarias**: Sin una de ellas, el sistema es vulnerable

Esta arquitectura es estándar en distribución de software (Debian apt, RedHat rpm, Alpine apk, todos usan firma + hashes).

---

## 4. k-Anonymity en Have I Been Pwned

### El problema
Queremos verificar si una contraseña ha sido filtrada, pero no queremos enviar la contraseña (ni su hash completo) a un servidor externo.

### La solución: k-Anonymity
1. Calcular SHA-1 de la contraseña localmente
2. Enviar solo los primeros **5 caracteres** del hash a la API
3. La API devuelve todos los hashes que comienzan con ese prefijo
4. Buscar localmente si nuestro hash está en la respuesta

### Ventajas
- El hash completo **nunca sale del equipo**
- La API no puede saber qué contraseña estamos verificando
- Hay miles de hashes por cada prefijo (k > 1000)

### Por qué SHA-1/SHA-256 directo es inseguro para contraseñas
Las contraseñas comunes tienen sus hashes indexados en **tablas rainbow**:
- "123456" aparece 209+ millones de veces
- "admin" aparece 42+ millones de veces
- Un atacante puede pre-calcular hashes de millones de contraseñas

### Almacenamiento seguro de contraseñas
Para almacenar contraseñas se debe usar:
- Funciones de derivación de clave (PBKDF2, bcrypt, Argon2)
- Salt único por contraseña
- Factor de trabajo (iterations) alto
