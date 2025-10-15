import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.glance.appwidget.compose
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Update


// =================================================================================
// --- CAPA DE SEGURIDAD (Implementación de la sección 4 y 6.1) ---
// =================================================================================

/**
 * Encapsula el texto cifrado, el vector de inicialización (IV) y el tag de autenticación.
 */
data class CiphertextWrapper(
    val ciphertext: ByteArray,
    val initializationVector: ByteArray,
    val authenticationTag: ByteArray
)

/**
 * Gestiona todas las operaciones de cifrado y descifrado usando AES-256 GCM.
 * Corresponde a la clase EncryptionManager descrita en la sección 6.1.
 */
class EncryptionManager {
    private val ALGORITHM = "AES"
    private val BLOCK_MODE = "GCM"
    private val PADDING = "NoPadding"
    private val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

    private val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private val PBKDF2_ITERATIONS = 100000 // Alto número de iteraciones para mayor seguridad
    private val KEY_SIZE_BITS = 256
    private val SALT_SIZE_BYTES = 32
    private val IV_SIZE_BYTES = 12 // Tamaño estándar para GCM
    private val TAG_SIZE_BITS = 128

    /**
     * Cifra un texto plano utilizando una clave derivada de la contraseña maestra.
     * @param plaintext El texto a cifrar.
     * @param masterPassword La contraseña maestra para derivar la clave.
     * @param salt El salt a usar en la derivación de la clave.
     * @return Un CiphertextWrapper con los datos cifrados.
     */
    fun encrypt(plaintext: ByteArray, masterPassword: CharArray, salt: ByteArray): CiphertextWrapper {
        val secretKey = deriveKey(masterPassword, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val iv = ByteArray(IV_SIZE_BYTES)
        SecureRandom().nextBytes(iv)
        val gcmParameterSpec = GCMParameterSpec(TAG_SIZE_BITS, iv)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
        val ciphertext = cipher.doFinal(plaintext)

        // El tag de autenticación se añade al final del ciphertext por GCM.
        val authenticationTag = ciphertext.copyOfRange(ciphertext.size - (TAG_SIZE_BITS / 8), ciphertext.size)
        val actualCiphertext = ciphertext.copyOfRange(0, ciphertext.size - (TAG_SIZE_BITS / 8))

        return CiphertextWrapper(actualCiphertext, iv, authenticationTag)
    }

    /**
     * Descifra un CiphertextWrapper utilizando la clave derivada de la contraseña maestra.
     * @param wrapper El objeto con los datos cifrados.
     * @param masterPassword La contraseña maestra para derivar la clave.
     * @param salt El salt usado en la derivación de la clave.
     * @return El texto plano descifrado.
     */
    fun decrypt(wrapper: CiphertextWrapper, masterPassword: CharArray, salt: ByteArray): ByteArray {
        val secretKey = deriveKey(masterPassword, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val gcmParameterSpec = GCMParameterSpec(TAG_SIZE_BITS, wrapper.initializationVector)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)

        // Concatenamos el texto cifrado y el tag para el descifrado GCM
        val ciphertextWithTag = wrapper.ciphertext + wrapper.authenticationTag

        return cipher.doFinal(ciphertextWithTag)
    }

    /**
     * Genera un salt criptográficamente seguro.
     */
    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_SIZE_BYTES)
        SecureRandom().nextBytes(salt)
        return salt
    }

    /**
     * Deriva una clave secreta a partir de la contraseña maestra y un salt usando PBKDF2.
     */
    private fun deriveKey(masterPassword: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(masterPassword, salt, PBKDF2_ITERATIONS, KEY_SIZE_BITS)
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, ALGORITHM)
    }
}


// =================================================================================
// --- CAPA DE DATOS (Implementación de la sección 3 y 6.4) ---
// =================================================================================

/**
 * Entidad de Room que representa una entrada de contraseña en la base de datos.
 * El campo `passwordCiphertext` almacena el resultado del cifrado.
 */
@Entity(tableName = "password_entries")
data class PasswordEntry(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val title: String,
    val username: String,
    val url: String,
    val notes: String,
    // Datos cifrados
    val passwordCiphertext: ByteArray,
    val initializationVector: ByteArray,
    val authenticationTag: ByteArray
)

/**
 * Clase de datos para representar una entrada de contraseña descifrada en la UI.
 */
data class DecryptedPasswordEntry(
    val id: Int,
    val title: String,
    val username: String,
    val passwordPlainText: String,
    val url: String,
    val notes: String
)

/**
 * DAO (Data Access Object) para interactuar con la tabla de contraseñas.
 */
@Dao
interface PasswordEntryDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: PasswordEntry)

    @Update
    suspend fun update(entry: PasswordEntry)

    @Delete
    suspend fun delete(entry: PasswordEntry)

    @Query("SELECT * FROM password_entries ORDER BY title ASC")
    fun getAllEntries(): Flow<List<PasswordEntry>>

    @Query("SELECT * FROM password_entries WHERE id = :id")
    suspend fun getEntryById(id: Int): PasswordEntry?
}

/**
 * La base de datos de la aplicación con Room.
 */
@Database(entities = [PasswordEntry::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun passwordEntryDao(): PasswordEntryDao

    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null

        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "password_manager_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}

// =================================================================================
// --- CAPA DE REPOSITORIO (Implementación de la sección 3 y 6.4) ---
// =================================================================================

/**
 * Repositorio que gestiona los datos de las contraseñas, abstrayendo el acceso a la
 * base de datos y la lógica de cifrado/descifrado.
 */
class PasswordRepository(
    private val passwordEntryDao: PasswordEntryDao,
    private val encryptionManager: EncryptionManager,
    private val masterPasswordProvider: () -> CharArray, // Provee la contraseña maestra
    private val saltProvider: () -> ByteArray // Provee el salt del usuario
) {

    /**
     * Obtiene todas las contraseñas descifradas como un Flow.
     */
    fun getAllDecryptedEntries(): Flow<List<DecryptedPasswordEntry>> {
        // Esta es una simplificación. En una app real, el descifrado
        // se haría de forma más granular o "just-in-time".
        // Por ahora, para la demo, desciframos todo al observar el Flow.
        return kotlinx.coroutines.flow.map(passwordEntryDao.getAllEntries()) { encryptedList ->
            encryptedList.mapNotNull { decryptEntry(it) }
        }
    }

    /**
     * Añade una nueva entrada de contraseña, cifrándola antes de guardarla.
     */
    suspend fun addPassword(entry: DecryptedPasswordEntry) {
        val encryptedPassword = encryptionManager.encrypt(
            entry.passwordPlainText.toByteArray(),
            masterPasswordProvider(),
            saltProvider()
        )
        val newEntry = PasswordEntry(
            title = entry.title,
            username = entry.username,
            url = entry.url,
            notes = entry.notes,
            passwordCiphertext = encryptedPassword.ciphertext,
            initializationVector = encryptedPassword.initializationVector,
            authenticationTag = encryptedPassword.authenticationTag
        )
        passwordEntryDao.insert(newEntry)
    }

    /**
     * Elimina una entrada de contraseña.
     */
    suspend fun deletePassword(entry: DecryptedPasswordEntry) {
        // Necesitamos la versión cifrada para poder eliminarla por su ID
        val encryptedEntry = passwordEntryDao.getEntryById(entry.id)
        encryptedEntry?.let {
            passwordEntryDao.delete(it)
        }
    }

    private fun decryptEntry(entry: PasswordEntry): DecryptedPasswordEntry? {
        return try {
            val decryptedPasswordBytes = encryptionManager.decrypt(
                CiphertextWrapper(entry.passwordCiphertext, entry.initializationVector, entry.authenticationTag),
                masterPasswordProvider(),
                saltProvider()
            )
            DecryptedPasswordEntry(
                id = entry.id,
                title = entry.title,
                username = entry.username,
                passwordPlainText = String(decryptedPasswordBytes),
                url = entry.url,
                notes = entry.notes
            )
        } catch (e: Exception) {
            // Error en el descifrado, podría ser por contraseña maestra incorrecta.
            e.printStackTrace()
            null
        }
    }
}


// =================================================================================
// --- CAPA DE VIEWMODEL (Implementación de la sección 3 y 6.5) ---
// =================================================================================

class MainViewModel(private val repository: PasswordRepository) : ViewModel() {

    val allPasswords: LiveData<List<DecryptedPasswordEntry>> = repository.getAllDecryptedEntries().asLiveData()

    fun addPassword(entry: DecryptedPasswordEntry) {
        viewModelScope.launch {
            repository.addPassword(entry)
        }
    }

    fun deletePassword(entry: DecryptedPasswordEntry) {
        viewModelScope.launch {
            repository.deletePassword(entry)
        }
    }
}

// Factory para poder inyectar el repositorio en el ViewModel manualmente
// En una app real, Hilt/Dagger se encargaría de esto.
class MainViewModelFactory(private val repository: PasswordRepository) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return MainViewModel(repository) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}


// =================================================================================
// --- CAPA DE PRESENTACIÓN (UI) con Jetpack Compose (Implementación de la sección 6.5) ---
// =================================================================================

class MainActivity : AppCompatActivity() {

    // Simulación de una contraseña maestra y salt. En una app real, esto se gestionaría
    // de forma segura en la AuthActivity/SetupActivity y se guardaría en EncryptedSharedPreferences.
    private val masterPassword = "SuperPassword123!".toCharArray()
    private val salt = EncryptionManager().generateSalt()

    private val database by lazy { AppDatabase.getDatabase(this) }
    private val repository by lazy {
        PasswordRepository(database.passwordEntryDao(), EncryptionManager(), { masterPassword }, { salt })
    }

    private val mainViewModel: MainViewModel by viewModels {
        MainViewModelFactory(repository)
    }

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                PasswordManagerApp(mainViewModel)
            }
        }
    }
}

@Composable
fun PasswordManagerApp(viewModel: MainViewModel) {
    val passwords by viewModel.allPasswords.observeAsState(initial = emptyList())
    var showDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Gestor de Contraseñas") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = "Añadir contraseña")
            }
        }
    ) { padding ->
        Box(modifier = Modifier.padding(padding)) {
            if (passwords.isEmpty()) {
                EmptyState()
            } else {
                PasswordList(passwords = passwords, onDelete = { viewModel.deletePassword(it) })
            }

            if (showDialog) {
                AddPasswordDialog(
                    onDismiss = { showDialog = false },
                    onConfirm = { entry ->
                        viewModel.addPassword(entry)
                        showDialog = false
                    }
                )
            }
        }
    }
}

@Composable
fun PasswordList(passwords: List<DecryptedPasswordEntry>, onDelete: (DecryptedPasswordEntry) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp)
    ) {
        items(passwords, key = { it.id }) { entry ->
            PasswordListItem(entry = entry, onDelete = { onDelete(entry) })
            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Composable
fun PasswordListItem(entry: DecryptedPasswordEntry, onDelete: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
        onClick = { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(entry.title, style = MaterialTheme.typography.titleLarge)
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, contentDescription = "Eliminar")
                }
            }
            Text(entry.username, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

            if (expanded) {
                Spacer(modifier = Modifier.height(12.dp))
                Text("Contraseña: ${entry.passwordPlainText}", fontWeight = FontWeight.SemiBold)
                Text("URL: ${entry.url}", style = MaterialTheme.typography.bodySmall)
                Text("Notas: ${entry.notes}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun AddPasswordDialog(onDismiss: () -> Unit, onConfirm: (DecryptedPasswordEntry) -> Unit) {
    var title by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var notes by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Añadir Nueva Contraseña") },
        text = {
            Column {
                OutlinedTextField(value = title, onValueChange = { title = it }, label = { Text("Título") })
                OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("Nombre de usuario") })
                OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("Contraseña") })
                OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("URL") })
                OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text("Notas") })
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    val newEntry = DecryptedPasswordEntry(0, title, username, password, url, notes)
                    onConfirm(newEntry)
                },
                enabled = title.isNotBlank() && username.isNotBlank() && password.isNotBlank()
            ) {
                Text("Guardar")
            }
        },
        dismissButton = {
            Button(onClick = onDismiss) {
                Text("Cancelar")
            }
        }
    )
}

@Composable
fun EmptyState() {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "No hay contraseñas guardadas.\nPulsa el botón '+' para añadir una.",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center
        )
    }
}

