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
        val toolsDir = File(context.filesDir, "tools")
        toolsDir.mkdirs()

        val targetFile = File(toolsDir, targetName)
        if (targetFile.exists() && targetFile.canExecute()) return targetFile.absolutePath

        // 删除旧文件重新释放
        if (targetFile.exists()) targetFile.delete()

        return try {
            context.assets.open("tools/$assetName").use { input ->
                FileOutputStream(targetFile).use { output ->
                    input.copyTo(output)
                }
            }
            // 设置权限: owner rwx, group rx, others rx
            targetFile.setReadable(true, false)
            targetFile.setExecutable(true, false)
            targetFile.setWritable(true, false)

            // 用 Runtime 确保 chmod 生效
            try {
                Runtime.getRuntime().exec(arrayOf("chmod", "755", targetFile.absolutePath)).waitFor()
            } catch (_: Exception) {}

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

        // 确保有执行权限
        try {
            Runtime.getRuntime().exec(arrayOf("chmod", "755", binaryPath)).waitFor()
        } catch (_: Exception) {}

        return try {
            val cmd = "exec $binaryPath ${args.joinToString(" ") { "\"$it\" }}"
            val processBuilder = ProcessBuilder(listOf("sh", "-c", cmd))
            processBuilder.directory(context.filesDir)
            processBuilder.environment()["PATH"] = "${context.filesDir}/tools:/system/bin:/system/xbin"
            processBuilder.redirectErrorStream(true)

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
        // 1. 检查 app 私有目录
        val appPath = context.filesDir.absolutePath + "/tools/$toolName"
        if (File(appPath).exists()) return appPath

        // 2. 从 assets 释放
        val extracted = extractBinary(toolName, toolName)
        if (extracted != null) return extracted

        // 3. 检查 Termux
        val termuxPath = "/data/data/com.termux/files/usr/bin/$toolName"
        if (File(termuxPath).exists()) return termuxPath

        // 4. 检查系统
        val sysPath = "/system/bin/$toolName"
        if (File(sysPath).exists()) return sysPath

        return null
    }
}
