package com.wifianalyzer.tools

import android.content.Context
import kotlinx.coroutines.*
import java.io.*

class ToolExecutor(private val context: Context) {

    data class ToolResult(
        val exitCode: Int,
        val output: String,
        val error: String,
        val duration: Long
    )

    interface OutputCallback {
        fun onOutput(line: String)
        fun onError(line: String)
        fun onComplete(exitCode: Int)
    }

    fun extractBinary(assetName: String, targetName: String): String? {
        val targetFile = File(context.filesDir, "tools/$targetName")
        if (targetFile.exists()) return targetFile.absolutePath

        targetFile.parentFile?.mkdirs()

        return try {
            context.assets.open("tools/$assetName").use { input ->
                FileOutputStream(targetFile).use { output ->
                    input.copyTo(output)
                }
            }
            targetFile.setExecutable(true)
            targetFile.absolutePath
        } catch (e: Exception) {
            null
        }
    }

    fun runTool(
        binaryPath: String,
        args: List<String>,
        callback: OutputCallback? = null
    ): ToolResult {
        val startTime = System.currentTimeMillis()
        val output = StringBuilder()
        val error = StringBuilder()

        return try {
            val processBuilder = ProcessBuilder(listOf(binaryPath) + args)
            processBuilder.directory(context.filesDir)
            processBuilder.environment()["PATH"] = "${context.filesDir}/tools:/system/bin:/system/xbin"

            val process = processBuilder.start()

            val outputThread = Thread {
                BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        val l = line ?: continue
                        output.appendLine(l)
                        callback?.onOutput(l)
                    }
                }
            }

            val errorThread = Thread {
                BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        val l = line ?: continue
                        error.appendLine(l)
                        callback?.onError(l)
                    }
                }
            }

            outputThread.start()
            errorThread.start()

            val exitCode = process.waitFor()
            outputThread.join(5000)
            errorThread.join(5000)

            callback?.onComplete(exitCode)

            val duration = System.currentTimeMillis() - startTime
            ToolResult(exitCode, output.toString(), error.toString(), duration)
        } catch (e: Exception) {
            val duration = System.currentTimeMillis() - startTime
            ToolResult(-1, "", e.message ?: "Unknown error", duration)
        }
    }

    suspend fun runToolAsync(
        binaryPath: String,
        args: List<String>,
        callback: OutputCallback? = null
    ): ToolResult = withContext(Dispatchers.IO) {
        runTool(binaryPath, args, callback)
    }

    fun isToolAvailable(toolName: String): Boolean {
        val paths = listOf(
            context.filesDir.absolutePath + "/tools/$toolName",
            "/data/data/com.termux/files/usr/bin/$toolName",
            "/system/bin/$toolName",
            "/system/xbin/$toolName"
        )
        return paths.any { File(it).exists() }
    }

    fun getToolPath(toolName: String): String? {
        val paths = listOf(
            context.filesDir.absolutePath + "/tools/$toolName",
            "/data/data/com.termux/files/usr/bin/$toolName",
            "/system/bin/$toolName",
            "/system/xbin/$toolName"
        )
        return paths.firstOrNull { File(it).exists() }
    }
}
