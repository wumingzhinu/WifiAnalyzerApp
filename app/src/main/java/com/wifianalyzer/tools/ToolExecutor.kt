package com.wifianalyzer.tools

import android.content.Context
import java.io.*

class ToolExecutor(private val context: Context) {

    data class ToolResult(val exitCode: Int, val output: String, val error: String, val duration: Long)

    fun extractBinary(assetName: String, targetName: String): String? {
        val toolsDir = File(context.filesDir, "tools")
        toolsDir.mkdirs()
        val targetFile = File(toolsDir, targetName)
        if (targetFile.exists() && targetFile.canExecute()) return targetFile.absolutePath
        if (targetFile.exists()) targetFile.delete()
        return try {
            context.assets.open("tools/$assetName").use { input ->
                FileOutputStream(targetFile).use { output -> input.copyTo(output) }
            }
            targetFile.setReadable(true, false)
            targetFile.setExecutable(true, false)
            try { Runtime.getRuntime().exec(arrayOf("chmod", "755", targetFile.absolutePath)).waitFor() } catch (_: Exception) {}
            targetFile.absolutePath
        } catch (e: Exception) {
            null
        }
    }

    fun runTool(binaryPath: String, args: List<String>): ToolResult {
        val startTime = System.currentTimeMillis()
        val output = StringBuilder()
        try { Runtime.getRuntime().exec(arrayOf("chmod", "755", binaryPath)).waitFor() } catch (_: Exception) {}
        return try {
            val allArgs = ArrayList<String>()
            allArgs.add(binaryPath)
            allArgs.addAll(args)
            val pb = ProcessBuilder(allArgs)
            pb.directory(context.filesDir)
            pb.environment()["PATH"] = context.filesDir.absolutePath + "/tools:/system/bin:/system/xbin"
            pb.redirectErrorStream(true)
            val process = pb.start()
            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                var line: String? = reader.readLine()
                while (line != null) {
                    output.appendLine(line)
                    line = reader.readLine()
                }
            }
            val exitCode = process.waitFor()
            val duration = System.currentTimeMillis() - startTime
            ToolResult(exitCode, output.toString(), "", duration)
        } catch (e: Exception) {
            val duration = System.currentTimeMillis() - startTime
            ToolResult(-1, "", e.message ?: "Unknown error", duration)
        }
    }

    fun isToolAvailable(toolName: String): Boolean {
        return getToolPath(toolName) != null
    }

    fun getToolPath(toolName: String): String? {
        val appPath = context.filesDir.absolutePath + "/tools/$toolName"
        if (File(appPath).exists()) return appPath
        val extracted = extractBinary(toolName, toolName)
        if (extracted != null) return extracted
        val termuxPath = "/data/data/com.termux/files/usr/bin/$toolName"
        if (File(termuxPath).exists()) return termuxPath
        val sysPath = "/system/bin/$toolName"
        if (File(sysPath).exists()) return sysPath
        return null
    }
}
