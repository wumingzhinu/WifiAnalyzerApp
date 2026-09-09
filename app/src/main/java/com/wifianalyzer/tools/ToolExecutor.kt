package com.wifianalyzer.tools

import android.content.Context
import java.io.*

class ToolExecutor(private val context: Context) {

    data class ToolResult(val exitCode: Int, val output: String, val error: String, val duration: Long)

    private fun libDir(): String = context.applicationInfo.nativeLibraryDir

    fun getToolPath(toolName: String): String? {
        val named = File(libDir(), "lib$toolName.so")
        if (named.exists()) return named.absolutePath
        val bare = File(libDir(), toolName)
        if (bare.exists()) return bare.absolutePath
        val termuxPath = "/data/data/com.termux/files/usr/bin/$toolName"
        if (File(termuxPath).exists()) return termuxPath
        return null
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
            pb.environment()["LD_LIBRARY_PATH"] = libDir()
            pb.environment()["PATH"] = libDir() + ":/system/bin:/system/xbin"
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
            ToolResult(exitCode, output.toString(), "", System.currentTimeMillis() - startTime)
        } catch (e: Exception) {
            ToolResult(-1, "", e.message ?: "Unknown error", System.currentTimeMillis() - startTime)
        }
    }
}
