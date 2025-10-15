package com.chc.chcpassmanager

import android.content.Context
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.room.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

// =================================================================================
// --- CAPA DE SEGURIDAD ---
// =================================================================================
data class CiphertextWrapper(val ciphertext: ByteArray, val initializationVector: ByteArray, val authenticationTag: ByteArray)

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
        val iv = ByteArray(IV_SIZE_BYTES).apply { SecureRandom().nextBytes(this) }
        val gcmParameterSpec = GCMParameterSpec(TAG_SIZE_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec)
        val ciphertext = cipher.doFinal(plaintext)
        val tagSize = TAG_SIZE_BITS / 8
        val authenticationTag = ciphertext.copyOfRange(ciphertext.size - tagSize, ciphertext.size)
        val actualCiphertext = ciphertext.copyOfRange(0, ciphertext.size - tagSize)
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

    private fun deriveKey(masterPassword: CharArray, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val spec = PBEKeySpec(masterPassword, salt, PBKDF2_ITERATIONS, KEY_SIZE_BITS)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, ALGORITHM)
    }
}

// =================================================================================
// --- CAPA DE DATOS (MODELOS Y ROOM) ---
// =================================================================================

@Entity(tableName = "passwords")
data class PasswordEntry(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val title: String,
    val username: String,
    val url: String,
    val encryptedData: ByteArray,
    val iv: ByteArray,
    val tag: ByteArray,
    val notes: String
)

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

    @Delete
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
        @Volatile private var INSTANCE: AppDatabase? = null
        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(context.applicationContext, AppDatabase::class.java, "password_manager_database")
                    .fallbackToDestructiveMigration().build().also { INSTANCE = it }
            }
        }
    }
}

// =================================================================================
// --- CAPA DE REPOSITORIO (IMPLEMENTACIÓN COMPLETA) ---
// =================================================================================

class PasswordRepository(
    private val passwordEntryDao: PasswordEntryDao,
    private val encryptionManager: EncryptionManager,
    private val masterPassword: CharArray,
    private val salt: ByteArray
) {
    fun getAllDecryptedEntries(): Flow<List<DecryptedPasswordEntry>> {
        return passwordEntryDao.getAllEntries()
            .map { encryptedList ->
                encryptedList.mapNotNull { decryptEntry(it) }
            }
            .flowOn(Dispatchers.IO)
    }

    suspend fun addPassword(entry: DecryptedPasswordEntry) {
        val encryptedPassword = encryptionManager.encrypt(entry.passwordPlainText.toByteArray(), masterPassword, salt)
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
        passwordEntryDao.getEntryById(entry.id)?.let {
            passwordEntryDao.delete(it)
        }
    }

    private fun decryptEntry(entry: PasswordEntry): DecryptedPasswordEntry? {
        return try {
            val decryptedPasswordBytes = encryptionManager.decrypt(CiphertextWrapper(entry.encryptedData, entry.iv, entry.tag), masterPassword, salt)
            DecryptedPasswordEntry(entry.id, entry.title, entry.username, String(decryptedPasswordBytes), entry.url, entry.notes)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}

// =================================================================================
// --- CAPA DE VIEWMODEL ---
// =================================================================================

class MainViewModel(private val repository: PasswordRepository) : ViewModel() {
    val allPasswords: Flow<List<DecryptedPasswordEntry>> = repository.getAllDecryptedEntries()
    fun addPassword(entry: DecryptedPasswordEntry) = viewModelScope.launch { repository.addPassword(entry) }
    fun deletePassword(entry: DecryptedPasswordEntry) = viewModelScope.launch { repository.deletePassword(entry) }
}

class MainViewModelFactory(private val repository: PasswordRepository) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(MainViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST") return MainViewModel(repository) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}

// =================================================================================
// --- CAPA DE PRESENTACIÓN (UI) ---
// =================================================================================

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                val navController = rememberNavController()
                NavHost(navController = navController, startDestination = "welcome") {
                    composable("welcome") {
                        WelcomeScreen(
                            onContinue = {
                                navController.navigate("main") { popUpTo("welcome") { inclusive = true } }
                            }
                        )
                    }
                    composable("main") {
                        PasswordManagerScreen()
                    }
                }
            }
        }
    }
}

@Composable
fun WelcomeScreen(onContinue: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text("CHC PassManager", style = MaterialTheme.typography.headlineLarge)
        Spacer(modifier = Modifier.height(32.dp))
        AppLogo(modifier = Modifier.size(150.dp))
        Spacer(modifier = Modifier.height(50.dp))
        Text(
            "Bienvenido a tu gestor de contraseñas seguro.",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onContinue) {
            Text("Crear Baúl de Contraseñas")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordManagerScreen() {
    var viewModel by remember { mutableStateOf<MainViewModel?>(null) }
    val context = LocalContext.current.applicationContext

    LaunchedEffect(key1 = Unit) {
        withContext(Dispatchers.IO) {
            val masterPassword = "SuperPassword123!".toCharArray()
            val salt = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".toByteArray()
            val database = AppDatabase.getDatabase(context)
            val repository = PasswordRepository(
                passwordEntryDao = database.passwordEntryDao(),
                encryptionManager = EncryptionManager(),
                masterPassword = masterPassword,
                salt = salt
            )
            val factory = MainViewModelFactory(repository)
            withContext(Dispatchers.Main) {
                viewModel = factory.create(MainViewModel::class.java)
            }
        }
    }

    if (viewModel == null) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
            Text("Creando baúl seguro...", modifier = Modifier.padding(top = 80.dp), style = MaterialTheme.typography.bodyLarge)
        }
    } else {
        val passwords by viewModel!!.allPasswords.collectAsStateWithLifecycle(initialValue = emptyList())
        var showAddDialog by rememberSaveable { mutableStateOf(false) }

        Scaffold(
            topBar = { TopAppBar(title = { Text("Mis Contraseñas") }, colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) },
            floatingActionButton = { FloatingActionButton(onClick = { showAddDialog = true }) { Icon(Icons.Filled.Add, contentDescription = "Añadir Contraseña") } }
        ) { paddingValues ->
            PasswordManagerContent(modifier = Modifier.padding(paddingValues), passwords = passwords, onDeletePassword = viewModel!!::deletePassword)
            if (showAddDialog) {
                AddPasswordDialog(
                    onDismiss = { showAddDialog = false },
                    onConfirm = { newEntry -> viewModel!!.addPassword(newEntry); showAddDialog = false }
                )
            }
        }
    }
}

@Composable
private fun PasswordManagerContent(modifier: Modifier = Modifier, passwords: List<DecryptedPasswordEntry>, onDeletePassword: (DecryptedPasswordEntry) -> Unit) {
    if (passwords.isEmpty()) {
        EmptyState(modifier = modifier.fillMaxSize())
    } else {
        LazyColumn(
            modifier = modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(items = passwords, key = { it.id }) { password ->
                PasswordListItem(entry = password, onDelete = { onDeletePassword(password) })
            }
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
                    Icon(Icons.Filled.Delete, contentDescription = "Eliminar", tint = Color.Gray)
                }
            }
            Text(entry.username, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (expanded) {
                Spacer(modifier = Modifier.height(12.dp))
                Text("Contraseña: ${entry.passwordPlainText}", fontWeight = FontWeight.SemiBold)
                if (entry.url.isNotBlank()) Text("URL: ${entry.url}", style = MaterialTheme.typography.bodySmall)
                if (entry.notes.isNotBlank()) Text("Notas: ${entry.notes}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
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
                onClick = { onConfirm(DecryptedPasswordEntry(0, title, username, password, url, notes)) },
                enabled = title.isNotBlank() && username.isNotBlank() && password.isNotBlank()
            ) { Text("Guardar") }
        },
        dismissButton = { Button(onClick = onDismiss) { Text("Cancelar") } }
    )
}

@Composable
fun EmptyState(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "No hay contraseñas guardadas.\nPulsa el botón '+' para añadir una.",
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center
        )
    }
}

@Composable
fun AppLogo(modifier: Modifier = Modifier) {
    val animatedProgress = remember { Animatable(0f) }
    LaunchedEffect(Unit) {
        animatedProgress.animateTo(targetValue = 1f, animationSpec = tween(durationMillis = 1500))
    }

    Canvas(modifier = modifier) {
        val shieldGradient = Brush.linearGradient(colors = listOf(Color(0xFF1e3a8a), Color(0xFF3b82f6)))

        // 1. Dibuja el escudo
        val shieldPath = Path().apply {
            moveTo(size.width * 0.50f, size.height * 0.05f)
            cubicTo(size.width * 0.25f, size.height * 0.15f, size.width * 0.20f, size.height * 0.40f, size.width * 0.50f, size.height * 0.95f)
            cubicTo(size.width * 0.80f, size.height * 0.40f, size.width * 0.75f, size.height * 0.15f, size.width * 0.50f, size.height * 0.05f)
            close()
        }
        drawPath(path = shieldPath, brush = shieldGradient)

        // 2. Dibuja el icono de la llave dentro del escudo (con animación)
        val keyProgress = (animatedProgress.value - 0.3f).coerceIn(0f, 1f) / 0.7f
        if (keyProgress > 0) {
            val keyPath = Path().apply {
                moveTo(size.width * 0.40f, size.height * 0.70f)
                lineTo(size.width * 0.60f, size.height * 0.50f)
                lineTo(size.width * 0.45f, size.height * 0.35f)
            }
            drawPath(
                path = keyPath,
                color = Color.White.copy(alpha = keyProgress),
                style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round, join = StrokeJoin.Round)
            )
            drawCircle(
                color = Color.White.copy(alpha = keyProgress),
                radius = 3.dp.toPx(),
                center = Offset(size.width * 0.40f, size.height * 0.70f)
            )
        }
    }
}
