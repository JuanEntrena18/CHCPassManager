# CHC PassManager

CHC PassManager es una aplicación de gestión de contraseñas simple, segura y local para Android, creada con prácticas modernas de desarrollo de Android. Te permite almacenar y gestionar tus credenciales de forma segura en tu dispositivo, con todos los datos encriptados mediante una contraseña maestra.

## 🚀 Características

- **Almacenamiento Seguro**: Guarda nombres de usuario, contraseñas, URLs y notas de forma segura.
- **Cifrado Local**: Todos los datos se cifran localmente en el dispositivo utilizando AES-GCM. Nada se envía a la nube.
- **UI Moderna**: Interfaz de usuario sencilla e intuitiva creada con Jetpack Compose.
- **Gestión de Entradas**: Añade, visualiza y elimina entradas de contraseñas.
- **Lista Dinámica**: Muestra una lista de contraseñas con detalles expandibles.
- **Pantalla de Bienvenida**: Una pantalla de bienvenida con una animación de logo personalizada.

## 🛠️ Tech Stack y Arquitectura

Este proyecto demuestra un conjunto de herramientas y patrones modernos para el desarrollo de Android.

- **Lenguaje**: **Kotlin** como único lenguaje de programación.
- **UI**: **Jetpack Compose** para una UI declarativa y reactiva.
- **Arquitectura**: Sigue un patrón de arquitectura limpia en capas dentro de un único módulo:
  - **Capa de UI (Presentación)**: `Activity` y `Composables` que muestran los datos y envían eventos de usuario.
  - **Capa de ViewModel**: `MainViewModel` para gestionar el estado de la UI y la lógica de negocio.
  - **Capa de Repositorio**: `PasswordRepository` que media entre las fuentes de datos y el resto de la app.
  - **Capa de Datos**: **Room** para la persistencia en una base de datos local (`AppDatabase`, `DAO`, `Entity`).
- **Componentes Principales de Jetpack**:
  - **Coroutines y Flow**: Para la programación asíncrona y reactiva.
  - **Room**: Para la persistencia de datos local.
  - **Lifecycle**: Para gestionar el ciclo de vida de los componentes de la UI (`ViewModel`, `collectAsStateWithLifecycle`).
  - **Navigation for Compose**: Para gestionar la navegación dentro de la aplicación.
- **Seguridad**:
  - **Java Cryptography Architecture (JCA)**: Para el cifrado y descifrado de datos con `AES/GCM` y derivación de claves con `PBKDF2`.

## 📸 Screenshots

*(Aquí puedes añadir capturas de pantalla de tu aplicación para hacer el README más atractivo)*

| Pantalla de Bienvenida | Pantalla Principal |
| :---: | :---: |
| *[Tu captura aquí]* | *[Tu captura aquí]* |

## ⚙️ Configuración y Puesta en Marcha

Para ejecutar este proyecto en tu máquina local, sigue estos pasos:

1. **Clona el repositorio**:
   ```bash
   git clone https://github.com/tu-usuario/CHCPassManager.git
   ```
2. **Abre en Android Studio**:
   - Abre la última versión estable de Android Studio.
   - Selecciona `File > Open` y navega hasta el directorio del proyecto clonado.

3. **Sincroniza Gradle**:
   - Android Studio sincronizará automáticamente los archivos de Gradle. Si no lo hace, haz clic en `File > Sync Project with Gradle Files`.

4. **Ejecuta la aplicación**:
   - Selecciona un emulador o conecta un dispositivo físico.
   - Haz clic en el botón `Run 'app'` (▶️).

## 📖 Cómo Usar la App

1.  Al iniciar la app por primera vez, verás una pantalla de bienvenida.
2.  Haz clic en **"Crear Baúl de Contraseñas"** para continuar.
3.  La aplicación inicializará una bóveda segura para tus contraseñas.
4.  Haz clic en el botón flotante `+` para añadir una nueva entrada.
5.  Rellena los detalles (título, usuario, contraseña, etc.) y haz clic en **"Guardar"**.
6.  Tu nueva entrada aparecerá en la lista. Toca una entrada para expandirla y ver los detalles, incluida la contraseña descifrada.
7.  Para eliminar una entrada, haz clic en el icono de la papelera.

## ⚠️ Nota de Seguridad Importante

Esta aplicación está diseñada como una **demostración de prácticas de desarrollo de Android y no es segura para uso en producción** en su estado actual. La contraseña maestra y la "sal" criptográfica están **hardcodeadas** (escritas directamente en el código) en el composable `PasswordManagerScreen`.

```kotlin
// NO HACER ESTO EN PRODUCCIÓN
val masterPassword = "SuperPassword123!".toCharArray()
val salt = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".toByteArray()
```

Para una aplicación real, necesitarías implementar un mecanismo seguro para que el usuario establezca y gestione su propia contraseña maestra, y generar y almacenar la "sal" de forma segura utilizando el **Android Keystore System**.

## 🔮 Posibles Mejoras Futuras

- [ ] Implementar una pantalla de inicio de sesión segura para la contraseña maestra.
- [ ] Almacenar la "sal" criptográfica de forma segura utilizando Android Keystore.
- [ ] Añadir un generador de contraseñas seguras.
- [ ] Implementar autenticación biométrica (huella dactilar/desbloqueo facial).
- [ ] Añadir funcionalidad de búsqueda y filtrado.
- [ ] Implementar la funcionalidad de copia de seguridad y restauración (cifrada) de la base de datos.
- [ ] Permitir la categorización de contraseñas.

## 📄 Licencia

Distribuido bajo la Licencia MIT. Consulta el archivo `LICENSE` para más información.
