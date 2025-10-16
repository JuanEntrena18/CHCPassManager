package com.chc.chcpassmanager

import android.content.Context
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
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
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.room.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.math.BigDecimal
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.log2
import kotlin.math.pow


// =================================================================================
// --- CAPA DE SEGURIDAD (ENCRIPTACIÓN DE DATOS) ---
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
    private val TAG_SIZE_BITS = 128

    fun encrypt(plaintext: ByteArray, masterPassword: CharArray, salt: ByteArray): CiphertextWrapper {
        val secretKey = deriveKey(masterPassword, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // GCM genera un IV seguro por defecto si no se especifica
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertextWithTag = cipher.doFinal(plaintext)
        val tagSize = TAG_SIZE_BITS / 8
        val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - tagSize)
        val tag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - tagSize, ciphertextWithTag.size)
        return CiphertextWrapper(ciphertext, iv, tag)
    }

    fun decrypt(wrapper: CiphertextWrapper, masterPassword: CharArray, salt: ByteArray): ByteArray {
        val secretKey = deriveKey(masterPassword, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val gcmSpec = GCMParameterSpec(TAG_SIZE_BITS, wrapper.initializationVector)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
        val ciphertextWithTag = wrapper.ciphertext + wrapper.authenticationTag
        return cipher.doFinal(ciphertextWithTag)
    }

    private fun deriveKey(masterPassword: CharArray, salt: ByteArray): SecretKeySpec {
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        val spec = PBEKeySpec(masterPassword, salt, PBKDF2_ITERATIONS, KEY_SIZE_BITS)
        return SecretKeySpec(factory.generateSecret(spec).encoded, ALGORITHM)
    }
}


// =================================================================================
// --- CAPA DE SEGURIDAD (GESTIÓN DE ACCESO) ---
// =================================================================================

object SecureStorageManager {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "chc_pass_manager_salt_key"
    private const val PREFS_FILE = "chc_secure_prefs"
    private const val PREF_ENCRYPTED_SALT = "encrypted_salt"
    private const val PREF_PIN_HASH = "pin_hash"

    private fun getKeyStore(): KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = getKeyStore()
        return (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: generateSecretKey()
    }

    private fun generateSecretKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER).apply { init(spec) }.generateKey()
    }

    suspend fun saveSalt(context: Context, salt: ByteArray) = withContext(Dispatchers.IO) {
        val key = getOrCreateSecretKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedData = cipher.doFinal(salt)
        val encryptedPayload = cipher.iv + encryptedData
        context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE).edit()
            .putString(PREF_ENCRYPTED_SALT, Base64.encodeToString(encryptedPayload, Base64.NO_WRAP))
            .apply()
    }

    suspend fun getSalt(context: Context): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
            val data = prefs.getString(PREF_ENCRYPTED_SALT, null) ?: return@withContext null
            val encryptedPayload = Base64.decode(data, Base64.NO_WRAP)
            val key = getOrCreateSecretKey()
            val ivSize = 12 // Standard GCM IV size
            val iv = encryptedPayload.copyOfRange(0, ivSize)
            val encryptedSalt = encryptedPayload.copyOfRange(ivSize, encryptedPayload.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(encryptedSalt)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    suspend fun savePin(context: Context, pin: String) = withContext(Dispatchers.IO) {
        val hash = hashString(pin)
        context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE).edit()
            .putString(PREF_PIN_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
            .apply()
    }

    suspend fun verifyPin(context: Context, pin: String): Boolean = withContext(Dispatchers.IO) {
        val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
        val savedHashString = prefs.getString(PREF_PIN_HASH, null) ?: return@withContext false
        val savedHash = Base64.decode(savedHashString, Base64.NO_WRAP)
        val enteredHash = hashString(pin)
        savedHash.contentEquals(enteredHash)
    }

    private fun hashString(input: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(input.toByteArray())
}


// =================================================================================
// --- CAPA DE DATOS (ROOM DATABASE) ---
// =================================================================================

@Entity(tableName = "passwords")
data class PasswordEntry(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val title: String, val username: String, val url: String,
    val encryptedData: ByteArray, val iv: ByteArray, val tag: ByteArray, val notes: String
)

data class DecryptedPasswordEntry(
    val id: Int, val title: String, val username: String,
    val passwordPlainText: String, val url: String, val notes: String
)

@Dao
interface PasswordEntryDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE) suspend fun insert(entry: PasswordEntry)
    @Delete suspend fun delete(entry: PasswordEntry)
    @Query("SELECT * FROM passwords ORDER BY title ASC") fun getAllEntries(): Flow<List<PasswordEntry>>
    @Query("SELECT * FROM passwords WHERE id = :id") suspend fun getEntryById(id: Int): PasswordEntry?
}

@Database(entities = [PasswordEntry::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun passwordEntryDao(): PasswordEntryDao
    companion object {
        @Volatile private var INSTANCE: AppDatabase? = null
        fun getDatabase(context: Context): AppDatabase =
            INSTANCE ?: synchronized(this) {
                Room.databaseBuilder(context.applicationContext, AppDatabase::class.java, "password_manager_database")
                    .fallbackToDestructiveMigration().build().also { INSTANCE = it }
            }
    }
}


// =================================================================================
// --- CAPA DE REPOSITORIO ---
// =================================================================================

class PasswordRepository(
    private val dao: PasswordEntryDao, private val encryptionManager: EncryptionManager,
    private val masterPassword: CharArray, private val salt: ByteArray
) {
    fun getAllDecryptedEntries(): Flow<List<DecryptedPasswordEntry>> =
        dao.getAllEntries().map { list -> list.mapNotNull { decryptEntry(it) } }.flowOn(Dispatchers.IO)

    suspend fun addPassword(entry: DecryptedPasswordEntry) {
        val encrypted = encryptionManager.encrypt(entry.passwordPlainText.toByteArray(), masterPassword, salt)
        val newEntry = PasswordEntry(
            title = entry.title, username = entry.username, url = entry.url, notes = entry.notes,
            encryptedData = encrypted.ciphertext, iv = encrypted.initializationVector, tag = encrypted.authenticationTag
        )
        dao.insert(newEntry)
    }

    suspend fun deletePassword(entry: DecryptedPasswordEntry) {
        dao.getEntryById(entry.id)?.let { dao.delete(it) }
    }

    private fun decryptEntry(entry: PasswordEntry): DecryptedPasswordEntry? = try {
        val decryptedBytes = encryptionManager.decrypt(CiphertextWrapper(entry.encryptedData, entry.iv, entry.tag), masterPassword, salt)
        DecryptedPasswordEntry(entry.id, entry.title, entry.username, String(decryptedBytes), entry.url, entry.notes)
    } catch (e: Exception) {
        e.printStackTrace()
        null
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

class SessionViewModel : ViewModel() {
    var mainViewModel by mutableStateOf<MainViewModel?>(null)
        private set

    fun initializePasswordViewModel(context: Context, masterPassword: CharArray) {
        viewModelScope.launch {
            val salt = SecureStorageManager.getSalt(context)
            if (salt != null) {
                val repo = PasswordRepository(AppDatabase.getDatabase(context).passwordEntryDao(), EncryptionManager(), masterPassword, salt)
                withContext(Dispatchers.Main) {
                    mainViewModel = MainViewModel(repo)
                }
            }
        }
    }
}


// =================================================================================
// --- CAPA DE PRESENTACIÓN (UI) ---
// =================================================================================

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { MainApp() } }
    }
}

@Composable
fun MainApp() {
    val context = LocalContext.current
    val navController = rememberNavController()
    val sessionViewModel: SessionViewModel = viewModel()
    var startDestination by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(key1 = Unit) {
        startDestination = if (SecureStorageManager.getSalt(context) != null) "unlock" else "welcome"
    }

    if (startDestination != null) {
        NavHost(navController = navController, startDestination = startDestination!!) {
            composable("welcome") {
                WelcomeScreen { navController.navigate("setup") }
            }
            composable("setup") {
                SetupScreen(onSetupComplete = {
                    navController.navigate("main") {
                        popUpTo("welcome") { inclusive = true }
                        popUpTo("setup") { inclusive = true }
                    }
                })
            }
            composable("unlock") {
                UnlockScreen {
                    navController.navigate("masterPasswordEntry") { popUpTo("unlock") { inclusive = true } }
                }
            }
            composable("masterPasswordEntry") {
                MasterPasswordEntryScreen(
                    onUnlock = { masterPassword ->
                        sessionViewModel.initializePasswordViewModel(context, masterPassword.toCharArray())
                        navController.navigate("main") { popUpTo("masterPasswordEntry") { inclusive = true } }
                    }
                )
            }
            composable("main") {
                val mainViewModel = sessionViewModel.mainViewModel
                if (mainViewModel != null) {
                    PasswordManagerScreen(mainViewModel)
                } else {
                    Box(contentAlignment = Alignment.Center, modifier = Modifier.fillMaxSize()) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            CircularProgressIndicator()
                            Spacer(Modifier.height(16.dp))
                            Text("Desbloqueando baúl...")
                        }
                    }
                }
            }
        }
    } else {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
    }
}

@Composable
fun WelcomeScreen(onCreateVault: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        AppLogo(modifier = Modifier.size(150.dp))
        Spacer(Modifier.height(16.dp))
        Text("Bienvenido a CHC PassManager", style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(32.dp))
        Button(onClick = onCreateVault) { Text("Crear Baúl Seguro") }
    }
}

@Composable
fun SetupScreen(onSetupComplete: () -> Unit) {
    val context = LocalContext.current
    var pin by rememberSaveable { mutableStateOf("") }
    var masterPassword by rememberSaveable { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Configuración Segura", style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center)
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = pin, onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) pin = it },
            label = { Text("Crea un PIN de 4 dígitos") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
        )
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = masterPassword, onValueChange = { masterPassword = it },
            label = { Text("Crea tu Contraseña Maestra") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
        )
        Spacer(Modifier.height(24.dp))
        Button(
            onClick = {
                scope.launch {
                    SecureStorageManager.saveSalt(context, SecureRandom().generateSeed(32))
                    SecureStorageManager.savePin(context, pin)
                    // La contraseña maestra NO se guarda, solo se usa para la primera inicialización
                    onSetupComplete()
                }
            },
            enabled = pin.length == 4 && masterPassword.isNotBlank()
        ) {
            Text("Finalizar Configuración")
        }
    }
}

@Composable
fun UnlockScreen(onUnlockSuccess: () -> Unit) {
    val context = LocalContext.current
    val activity = (LocalContext.current as? FragmentActivity)
    var pin by rememberSaveable { mutableStateOf("") }
    var errorText by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    val canAuthenticate = BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    val biometricPrompt = if (activity != null) {
        BiometricPrompt(activity, ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) { onUnlockSuccess() }
            })
    } else { null }

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Desbloqueo Biométrico")
        .setSubtitle("Desbloquea tu baúl de contraseñas")
        .setNegativeButtonText("Usar PIN")
        .build()

    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Desbloquear Baúl", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(
            value = pin, onValueChange = { if (it.length <= 4 && it.all { c -> c.isDigit() }) pin = it },
            label = { Text("Introduce tu PIN") },
            isError = errorText != null,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword)
        )
        errorText?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.height(16.dp))
        Row(
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Button(
                onClick = {
                    scope.launch {
                        if (SecureStorageManager.verifyPin(context, pin)) {
                            onUnlockSuccess()
                        } else {
                            errorText = "PIN incorrecto"
                            pin = ""
                        }
                    }
                },
                enabled = pin.length == 4
            ) { Text("Entrar") }
            if (canAuthenticate && biometricPrompt != null) {
                IconButton(onClick = { biometricPrompt.authenticate(promptInfo) }) {
                    Icon(Icons.Default.Fingerprint, "Desbloqueo Biométrico", modifier = Modifier.size(48.dp))
                }
            }
        }
    }
}

@Composable
fun MasterPasswordEntryScreen(onUnlock: (String) -> Unit) {
    var masterPassword by rememberSaveable { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Contraseña Maestra", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = masterPassword, onValueChange = { masterPassword = it },
            label = { Text("Introduce tu contraseña maestra") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password)
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = { onUnlock(masterPassword) },
            enabled = masterPassword.isNotBlank()
        ) { Text("Desbloquear") }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordManagerScreen(viewModel: MainViewModel) {
    val passwords by viewModel.allPasswords.collectAsStateWithLifecycle(initialValue = emptyList())
    var showAddDialog by rememberSaveable { mutableStateOf(false) }

    Scaffold(
        topBar = { TopAppBar(title = { Text("Mis Contraseñas") }, colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) },
        floatingActionButton = { FloatingActionButton(onClick = { showAddDialog = true }) { Icon(Icons.Filled.Add, "Añadir") } }
    ) { padding ->
        PasswordManagerContent(
            modifier = Modifier.padding(padding),
            passwords = passwords,
            onDeletePassword = viewModel::deletePassword
        )
        if (showAddDialog) {
            AddPasswordDialog(
                onDismiss = { showAddDialog = false },
                onConfirm = { newEntry ->
                    viewModel.addPassword(newEntry)
                    showAddDialog = false
                }
            )
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
        Column(Modifier.padding(16.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(entry.title, style = MaterialTheme.typography.titleLarge)
                IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, "Eliminar", tint = Color.Gray) }
            }
            Text(entry.username, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (expanded) {
                Spacer(Modifier.height(12.dp))
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
    var title by rememberSaveable { mutableStateOf("") }
    var username by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var url by rememberSaveable { mutableStateOf("") }
    var notes by rememberSaveable { mutableStateOf("") }
    var showGenerateDialog by rememberSaveable { mutableStateOf(false) }

    if (showGenerateDialog) {
        GeneratePasswordDialog(
            onDismiss = { showGenerateDialog = false },
            onConfirm = { generatedPassword ->
                password = generatedPassword
                showGenerateDialog = false
            }
        )
    }

    AlertDialog(
        onDismissRequest = onDismiss, title = { Text("Añadir Nueva Contraseña") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = title, onValueChange = { title = it }, label = { Text("Título") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = username, onValueChange = { username = it }, label = { Text("Nombre de usuario") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    value = password, onValueChange = { password = it }, label = { Text("Contraseña") }, modifier = Modifier.fillMaxWidth(),
                    trailingIcon = { IconButton(onClick = { showGenerateDialog = true }) { Icon(Icons.Default.VpnKey, "Generar") } }
                )
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
fun GeneratePasswordDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var length by rememberSaveable { mutableStateOf(16f) }
    var useUppercase by rememberSaveable { mutableStateOf(true) }
    var useNumbers by rememberSaveable { mutableStateOf(true) }
    var useSymbols by rememberSaveable { mutableStateOf(true) }
    var generatedPassword by remember { mutableStateOf("") }
    var strengthText by remember { mutableStateOf("") }
    var triggerGeneration by remember { mutableStateOf(0) }
    val clipboardManager: ClipboardManager = LocalClipboardManager.current
    val context = LocalContext.current

    LaunchedEffect(length, useUppercase, useNumbers, useSymbols, triggerGeneration) {
        val newPassword = generateSecurePassword(length.toInt(), useUppercase, useNumbers, useSymbols)
        generatedPassword = newPassword
        strengthText = estimatePasswordStrength(newPassword)
    }

    AlertDialog(
        onDismissRequest = onDismiss, title = { Text("Generador de Contraseñas") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Surface(
                    shape = MaterialTheme.shapes.medium,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = generatedPassword,
                            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold),
                            modifier = Modifier.weight(1f)
                        )
                        Row {
                            IconButton(onClick = { triggerGeneration++ }) { Icon(Icons.Default.Refresh, "Regenerar") }
                            IconButton(onClick = {
                                clipboardManager.setText(AnnotatedString(generatedPassword))
                                Toast.makeText(context, "Contraseña copiada", Toast.LENGTH_SHORT).show()
                            }) { Icon(Icons.Default.ContentCopy, "Copiar") }
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Tiempo estimado para descifrar: $strengthText",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(Modifier.height(16.dp))
                Text("Longitud: ${length.toInt()}", style = MaterialTheme.typography.bodyMedium)
                Slider(
                    value = length,
                    onValueChange = { length = it },
                    valueRange = 8f..64f,
                    steps = (64 - 8) - 1
                )
                Column(modifier = Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = useUppercase, onCheckedChange = { useUppercase = it })
                        Text("Mayúsculas (A-Z)")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = useNumbers, onCheckedChange = { useNumbers = it })
                        Text("Números (0-9)")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = useSymbols, onCheckedChange = { useSymbols = it })
                        Text("Símbolos (!@#$...%)")
                    }
                }
            }
        },
        confirmButton = { Button(onClick = { onConfirm(generatedPassword) }) { Text("Usar") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } }
    )
}

@Composable
fun EmptyState(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier,
        contentAlignment = Alignment.Center
    ) {
        Text(
            "No hay contraseñas guardadas.\nPulsa el botón '+' para añadir una.",
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.bodyLarge
        )
    }
}

@Composable
fun AppLogo(modifier: Modifier = Modifier) {
    val animatedProgress = remember { Animatable(0f) }
    LaunchedEffect(Unit) { animatedProgress.animateTo(targetValue = 1f, animationSpec = tween(durationMillis = 1500)) }

    Canvas(modifier = modifier) {
        val shieldGradient = Brush.linearGradient(colors = listOf(Color(0xFF1e3a8a), Color(0xFF3b82f6)))
        val shieldPath = Path().apply {
            moveTo(size.width * 0.50f, size.height * 0.05f)
            cubicTo(size.width * 0.25f, size.height * 0.15f, size.width * 0.20f, size.height * 0.40f, size.width * 0.50f, size.height * 0.95f)
            cubicTo(size.width * 0.80f, size.height * 0.40f, size.width * 0.75f, size.height * 0.15f, size.width * 0.50f, size.height * 0.05f)
            close()
        }
        drawPath(path = shieldPath, brush = shieldGradient)

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

private fun generateSecurePassword(length: Int, useUppercase: Boolean, useNumbers: Boolean, useSymbols: Boolean): String {
    val lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
    val uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    val numberChars = "0123456789"
    val symbolChars = "!@#$%^&*()_+-=[]{}|;':,./<>?"
    val charPool = StringBuilder(lowercaseChars)
    val requiredChars = mutableListOf<Char>()

    if (useUppercase) {
        charPool.append(uppercaseChars)
        requiredChars.add(uppercaseChars.random())
    }
    if (useNumbers) {
        charPool.append(numberChars)
        requiredChars.add(numberChars.random())
    }
    if (useSymbols) {
        charPool.append(symbolChars)
        requiredChars.add(symbolChars.random())
    }

    val remainingLength = length - requiredChars.size
    val randomChars = (1..remainingLength).map { charPool.toString().random() }

    val passwordChars = (requiredChars + randomChars).toMutableList()
    passwordChars.shuffle(SecureRandom())

    return passwordChars.joinToString("")
}

private fun estimatePasswordStrength(password: String): String {
    if (password.isEmpty()) return "N/A"
    var poolSize = 0
    if (password.any { it in 'a'..'z' }) poolSize += 26
    if (password.any { it in 'A'..'Z' }) poolSize += 26
    if (password.any { it.isDigit() }) poolSize += 10
    if (password.any { !it.isLetterOrDigit() }) poolSize += 32 // Approximate symbol count
    if (poolSize == 0) return "Muy débil"
    val entropy = password.length * log2(poolSize.toDouble())
    val guessesPerSecond = BigDecimal("10000000000000") // 10 trillion
    val totalCombinations = try {
        BigDecimal.valueOf(2.0.pow(entropy))
    } catch (e: NumberFormatException) {
        return "eones" // For very high entropy
    }
    val secondsToCrack = totalCombinations.divide(guessesPerSecond, java.math.RoundingMode.HALF_UP)
    val minute = BigDecimal(60)
    val hour = minute * BigDecimal(60)
    val day = hour * BigDecimal(24)
    val year = day * BigDecimal("365.25")
    val century = year * BigDecimal(100)
    val millennium = century * BigDecimal(10)

    return when {
        secondsToCrack < BigDecimal(0.01) -> "instantáneamente"
        secondsToCrack < minute -> "${secondsToCrack.toLong()} segundos"
        secondsToCrack < hour -> "${secondsToCrack.divide(minute, 0, java.math.RoundingMode.HALF_UP).toLong()} minutos"
        secondsToCrack < day -> "${secondsToCrack.divide(hour, 0, java.math.RoundingMode.HALF_UP).toLong()} horas"
        secondsToCrack < year -> "${secondsToCrack.divide(day, 0, java.math.RoundingMode.HALF_UP).toLong()} días"
        secondsToCrack < century -> "${secondsToCrack.divide(year, 0, java.math.RoundingMode.HALF_UP).toLong()} años"
        secondsToCrack < millennium -> "${secondsToCrack.divide(century, 0, java.math.RoundingMode.HALF_UP).toLong()} siglos"
        else -> "milenios"
    }
}