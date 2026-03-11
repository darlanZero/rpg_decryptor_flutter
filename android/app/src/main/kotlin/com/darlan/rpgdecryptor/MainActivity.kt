package com.darlan.rpgdecryptor

import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.io.File

/**
 * MainActivity com platform channel para executar comandos shell no Android.
 * Permite rodar apktool via `java -jar` quando Java estiver disponível.
 */
class MainActivity : FlutterActivity() {

    private val CHANNEL = "com.darlan.rpgdecryptor/shell"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "runCommand" -> {
                        val command = call.argument<String>("command") ?: ""
                        val workDir = call.argument<String>("workDir") ?: ""
                        runCommand(command, workDir, result)
                    }
                    "getExternalStorage" -> {
                        val paths = getExternalStoragePaths()
                        result.success(paths)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun runCommand(command: String, workDir: String, result: MethodChannel.Result) {
        Thread {
            try {
                val pb = ProcessBuilder("sh", "-c", command)
                    .redirectErrorStream(true)

                if (workDir.isNotEmpty()) {
                    pb.directory(File(workDir))
                }

                val process = pb.start()
                val output = process.inputStream.bufferedReader().readText()
                val exitCode = process.waitFor()

                Handler(Looper.getMainLooper()).post {
                    result.success(
                        mapOf(
                            "exitCode" to exitCode,
                            "output" to output
                        )
                    )
                }
            } catch (e: Exception) {
                Handler(Looper.getMainLooper()).post {
                    result.error("SHELL_ERROR", e.message ?: "Unknown error", null)
                }
            }
        }.start()
    }

    private fun getExternalStoragePaths(): List<String> {
        val paths = mutableListOf<String>()
        try {
            val dirs = getExternalFilesDirs(null)
            dirs?.forEach { dir ->
                dir?.absolutePath?.let { path ->
                    // Normaliza para a raiz do storage externo
                    val root = path.substringBefore("/Android/data")
                    paths.add(root)
                }
            }
        } catch (e: Exception) {
            // Fallback
            paths.add("/sdcard")
            paths.add("/storage/emulated/0")
        }
        return paths
    }
}
