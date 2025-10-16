CHC PassManager
Cyber Haute Couture: Seguridad a la medida de tu vida digital.
CHC PassManager es un gestor de contraseñas moderno y seguro para Android, diseñado con un enfoque en la simplicidad y una seguridad robusta. La aplicación está dirigida a usuarios que buscan una forma fácil de gestionar sus credenciales sin comprometer la protección, gracias a su arquitectura de seguridad de múltiples capas.
✨ Características Principales
🔐 Almacenamiento Cifrado: Todas tus contraseñas y datos sensibles se guardan localmente utilizando el robusto cifrado AES-256 GCM.
🛡️ Flujo de Autenticación Avanzado:
Configuración Única: Establece un PIN de 4 dígitos y una Contraseña Maestra la primera vez que usas la app.
Desbloqueo Rápido: Accede a la aplicación de forma segura y rápida usando tu PIN o tu huella dactilar (autenticación biométrica).
Descifrado Bajo Demanda: La Contraseña Maestra es necesaria para descifrar el baúl de contraseñas, asegurando que solo tú puedas ver tus datos.
🔑 Generador de Contraseñas:
Crea contraseñas fuertes y aleatorias con opciones personalizables (longitud, uso de mayúsculas, números y símbolos).
Incluye un estimador de fortaleza que calcula el tiempo aproximado que se tardaría en descifrar la contraseña generada.
🔒 Seguridad Anclada al Hardware: El salt criptográfico, esencial para la seguridad de tus datos, se cifra y se almacena en el Android KeyStore. Esto lo protege a nivel de hardware, haciéndolo inaccesible incluso en dispositivos comprometidos.
📱 Interfaz Nativa y Moderna: La interfaz de usuario está construida 100% con Jetpack Compose, ofreciendo una experiencia fluida, reactiva y visualmente atractiva.
📋 Gestión Sencilla: Añade, visualiza y elimina tus credenciales de forma intuitiva. Copia contraseñas al portapapeles con un solo toque.
🚀 Arquitectura de Seguridad
La seguridad de CHC PassManager se basa en una separación clara entre el desbloqueo de la aplicación y el descifrado de los datos.
Configuración Inicial: El usuario crea un PIN y una Contraseña Maestra. En este momento, se genera un salt único y aleatorio. Este salt se cifra con una clave almacenada en el Android KeyStore y se guarda en las preferencias seguras de la aplicación. El PIN se guarda como un hash. La Contraseña Maestra nunca se almacena en el dispositivo.
Desbloqueo de la App: Para acceder, el usuario se autentica con su PIN (que se verifica contra el hash guardado) o con su huella dactilar. Este paso solo desbloquea la interfaz de usuario.
Descifrado del Baúl: Una vez dentro, se le solicita al usuario su Contraseña Maestra. Esta contraseña, combinada con el salt (que se descifra de forma segura usando la clave del KeyStore), se utiliza para derivar la clave de cifrado AES-256 y finalmente acceder a las contraseñas.
Este modelo garantiza que aunque alguien consiga acceder a tu dispositivo y superar el PIN, no podrá ver tus contraseñas sin la Contraseña Maestra.
🛠️ Stack Tecnológico
Lenguaje: 100% Kotlin
Interfaz de Usuario: Jetpack Compose
Arquitectura: MVVM (ViewModel, Repository, Coroutines, Flow)
Navegación: Navigation Compose
Base de Datos Local: Room
Seguridad:
AndroidX Biometric
Android KeyStore System
Criptografía nativa de Java (JCA) para AES-256 y PBKDF2.
📄 Licencia
Este proyecto se distribuye bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.
