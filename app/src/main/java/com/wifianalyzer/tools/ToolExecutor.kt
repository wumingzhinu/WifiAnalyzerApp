package com.wifianalyzer.tools

import android.content.Context
import java.io.*

class ToolExecutor(private val context: Context) {

    data class ToolResult(val exitCode: Int, val output: String, val error: String, val duration: Long)

    fun getToolPath(toolName: String): String? {
        // 1. nativeLibraryDir (jniLibs, always executable)
        val nativePath = File(context.applicationInfo.nativeLibraryDir, toolName)
        if (nativePath.exists()) return nativePath.absolutePath

        // 2. app internal tools dir
        val appPath = File(context.filesDir, "tools/$toolName")
        if (appPath.exists() && appPath.canExecute()) return appPath.absolutePath

        // 3. extract from assets
        val extracted = extractBinary(toolName, toolName)
        if (extracted != null) return extracted

        // 4. Termux
        val termuxPath = "/data/data/com.termux/files/usr/bin/$toolName"
        if (File(termuxPath).exists()) return termuxPath

        return null
    }

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
            try { Runtime.getRuntime().exec(arrayOf("chmod", "755", targetFile.absolutePath)).waitFor() } catch (_: Exception) {}
            targetFile.absolutePath
        } catch (e: Exception) { null }
    }

    fun runTool(binaryPath: String, args: List<String>): ToolResult {
        val startTime = System.currentTimeMillis()
        val output = StringBuilder()
        return try {
            val allArgs = ArrayList<String>()
            allArgs.add(binaryPath)
            allArgs.addAll(args)
            val pb = ProcessBuilder(allArgs)
            pb.directory(context.filesDir)
            pb.environment()["PATH"] = context.applicationInfo.nativeLibraryDir + ":/system/bin:/system/xbin"
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
}
