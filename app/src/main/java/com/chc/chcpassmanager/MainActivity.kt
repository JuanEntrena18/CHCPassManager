package com.chc.CHCPassManager // Asegúrate de que coincida con tu package name

import android.content.Context
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.*
import androidx.room.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// =================================================================================
// --- CAPA DE SEGURIDAD (Implementación de la sección 4 y 6.1) ---
// =================================================================================

data class CiphertextWrapper(
    val ciphertext: ByteArray,
    val initializationVector: ByteArray,
    val authenticationTag: ByteArray
)

class EncryptionManager {
    private val ALGORITHM = "AES"
    private val BLOCK_MODE = "GCM"
    private val PADDING = "NoPadding"
    private val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

    private val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private val PBKDF2_ITERATIONS = 100000
    private val KEY_SIZE_BITS = 256
    private val SALT_SIZE_BYTES = 32
    private val IV_SIZE_BYTES = 12
    private val TAG_SIZE_BITS = 128

    fun encrypt(plaintext: ByteArray, masterPassword: CharArray, salt: ByteArray): CiphertextWrapper {
        val secretKey = deriveKey(masterPassword, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val iv = ByteArray(IV_SIZE_BYTES)
        SecureRandom().nextBytes(iv)
        val gcmParameterSpec = GCMParameterSpec(TAG_SIZE_BITS, iv)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
        val ciphertext = cipher.doFinal(plaintext)

        val authenticationTag = ciphertext.copyOfRange(ciphertext.size - (TAG_SIZE_BITS / 8), ciphertext.size)
        val actualCiphertext = ciphertext.copyOfRange(0, ciphertext.size - (TAG_SIZE_BITS / 8))

        return CiphertextWrapper(actualCiphertext, iv, authenticationTag)
    }

    fun decrypt(wrapper: CiphertextWrapper, masterPassword: CharArray, salt: ByteArray): ByteArray {
        val secretKey = deriveKey(masterPassword, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val gcmParameterSpec = GCMParameterSpec(TAG_SIZE_BITS, wrapper.initializationVector)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec)

        val ciphertextWithTag = wrapper.ciphertext + wrapper.authenticationTag

        return cipher.doFinal(ciphertextWithTag)
    }

    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_SIZE_BYTES)
        SecureRandom().nextBytes(salt)
        return salt
    }

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

@Entity(tableName = "passwords")
data class PasswordEntry(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val title: String,
    val username: String,
    val url: String, // **CORREGIDO: Campo URL añadido**
    val encryptedData: ByteArray,
    val iv: ByteArray,
    val tag: ByteArray,
    val notes: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PasswordEntry

        if (id != other.id) return false
        if (title != other.title) return false
        if (username != other.username) return false
        if (url != other.url) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!tag.contentEquals(other.tag)) return false
        if (notes != other.notes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id
        result = 31 * result + title.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + url.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + tag.contentHashCode()
        result = 31 * result + notes.hashCode()
        return result
    }
}

data class DecryptedPasswordEntry(
    val id: Int,
    val title: String,
    val username: String,
    val passwordPlainText: String,
    val url: String,
    val notes: String
)

@Dao
interface PasswordEntryDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: PasswordEntry)

    @Update
    suspend fun update(entry: PasswordEntry)

    @androidx.room.Delete
    suspend fun delete(entry: PasswordEntry)

    @Query("SELECT * FROM passwords ORDER BY title ASC")
    fun getAllEntries(): Flow<List<PasswordEntry>>

    @Query("SELECT * FROM passwords WHERE id = :id")
    suspend fun getEntryById(id: Int): PasswordEntry?
}

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
                )
                    // ESTA LÍNEA SOLUCIONA EL CIERRE INESPERADO.
                    // Permite a Room realizar la consulta inicial en el hilo principal.
                    .allowMainThreadQueries()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}


// =================================================================================
// --- CAPA DE REPOSITORIO (Implementación de la sección 3 y 6.4) ---
// =================================================================================

class PasswordRepository(
    private val passwordEntryDao: PasswordEntryDao,
    private val encryptionManager: EncryptionManager,
    private val masterPasswordProvider: () -> CharArray,
    private val saltProvider: () -> ByteArray
) {
    fun getAllDecryptedEntries(): Flow<List<DecryptedPasswordEntry>> {
        // **CORREGIDO: Sintaxis del 'map' arreglada**
        return passwordEntryDao.getAllEntries().map { encryptedList ->
            encryptedList.mapNotNull { decryptEntry(it) }
        }
    }

    suspend fun addPassword(entry: DecryptedPasswordEntry) {
        val encryptedPassword = encryptionManager.encrypt(
            entry.passwordPlainText.toByteArray(),
            masterPasswordProvider(),
            saltProvider()
        )
        // **CORREGIDO: Nombres de campos y 'url' coinciden con la entidad PasswordEntry**
        val newEntry = PasswordEntry(
            title = entry.title,
            username = entry.username,
            url = entry.url,
            notes = entry.notes,
            encryptedData = encryptedPassword.ciphertext,
            iv = encryptedPassword.initializationVector,
            tag = encryptedPassword.authenticationTag
        )
        passwordEntryDao.insert(newEntry)
    }

    suspend fun deletePassword(entry: DecryptedPasswordEntry) {
        val encryptedEntry = passwordEntryDao.getEntryById(entry.id)
        encryptedEntry?.let {
            passwordEntryDao.delete(it)
        }
    }

    private fun decryptEntry(entry: PasswordEntry): DecryptedPasswordEntry? {
        return try {
            // **CORREGIDO: Nombres de campos coinciden con la entidad PasswordEntry**
            val decryptedPasswordBytes = encryptionManager.decrypt(
                CiphertextWrapper(entry.encryptedData, entry.iv, entry.tag),
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

    private val masterPassword = "SuperPassword123!".toCharArray()
    private val salt by lazy { EncryptionManager().generateSalt() }

    private val database by lazy { AppDatabase.getDatabase(this) }
    private val repository by lazy {
        PasswordRepository(database.passwordEntryDao(), EncryptionManager(), { masterPassword }, { salt })
    }

    private val mainViewModel: MainViewModel by viewModels {
        MainViewModelFactory(repository)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                PasswordManagerApp(mainViewModel)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordManagerApp(viewModel: MainViewModel) {
    val passwords by viewModel.allPasswords.observeAsState(initial = emptyList())
    var showDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Cyber Haute Couture") },
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
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        items(passwords, key = { it.id }) { entry ->
            PasswordListItem(entry = entry, onDelete = { onDelete(entry) })
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordListItem(entry: DecryptedPasswordEntry, onDelete: () -> Unit) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
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
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = title, onValueChange = { title = it }, label = { Text("Título") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("Nombre de usuario") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = password, onValueChange = { password = it }, label = { Text("Contraseña") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = url, onValueChange = { url = it }, label = { Text("URL") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = notes, onValueChange = { notes = it }, label = { Text("Notas") }, modifier = Modifier.fillMaxWidth())
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
        modifier = Modifier.fillMaxSize().padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "No hay contraseñas guardadas.\nPulsa el botón '+' para añadir una.",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center
        )
    }
}

