package com.wifianalyzer.tools

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.R
import kotlinx.coroutines.launch
import java.io.*

class ToolsActivity : AppCompatActivity() {

    private lateinit var executor: ToolExecutor
    private lateinit var tvOutput: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var progressIndicator: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tools)

        executor = ToolExecutor(this)
        tvOutput = findViewById(R.id.tvOutput)
        scrollView = findViewById(R.id.scrollView)
        progressIndicator = findViewById(R.id.progressIndicator)

        findViewById<Button>(R.id.btnAircrackView).setOnClickListener { viewWithAircrack() }
        findViewById<Button>(R.id.btnHcxpcapngtoolView).setOnClickListener { viewWithHcxpcapngtool() }
        findViewById<Button>(R.id.btnHcxpcapngtoolInfo).setOnClickListener { infoWithHcxpcapngtool() }
        findViewById<Button>(R.id.btnCustomCmd).setOnClickListener { showCustomCommandDialog() }

        checkTools()
    }

    private fun checkTools() {
        val aircrack = executor.getToolPath("aircrack-ng")
        val hcx = executor.getToolPath("hcxpcapngtool")

        val tvAircrackStatus = findViewById<TextView>(R.id.tvAircrackStatus)
        val tvHcxStatus = findViewById<TextView>(R.id.tvHcxStatus)

        tvAircrackStatus.text = if (aircrack != null) "● 已安装" else "○ 未安装"
        tvAircrackStatus.setTextColor(if (aircrack != null) 0xFF3FB950.toInt() else 0xFF8B949E.toInt())

        tvHcxStatus.text = if (hcx != null) "● 已安装" else "○ 未安装"
        tvHcxStatus.setTextColor(if (hcx != null) 0xFF3FB950.toInt() else 0xFF8B949E.toInt())

        appendOutput("工具状态:")
        appendOutput("  aircrack-ng: ${if (aircrack != null) "✓" else "✗ 请安装"}")
        appendOutput("  hcxpcapngtool: ${if (hcx != null) "✓" else "✗ 请安装"}")
        appendOutput("")
        appendOutput("安装方法 (Termux):")
        appendOutput("  pkg install aircrack-ng")
        appendOutput("  pkg install hcxtools")
        appendOutput("")

        if (aircrack == null && hcx == null) {
            appendOutput("⚠ 没有可用工具，请先安装")
        }
    }

    private fun viewWithAircrack() {
        val path = executor.getToolPath("aircrack-ng")
        if (path == null) {
            toast("aircrack-ng 未安装\n请在Termux执行: pkg install aircrack-ng")
            return
        }
        selectFile { file ->
            clearOutput()
            appendOutput("▶ aircrack-ng (查看模式)\n  文件: ${file.name}\n")
            runCmd(path, listOf("-a", "2", file.absolutePath))
        }
    }

    private fun viewWithHcxpcapngtool() {
        val path = executor.getToolPath("hcxpcapngtool")
        if (path == null) {
            toast("hcxpcapngtool 未安装\n请在Termux执行: pkg install hcxtools")
            return
        }
        selectFile { file ->
            clearOutput()
            appendOutput("▶ hcxpcapngtool (查看握手包详情)\n  文件: ${file.name}\n")
            runCmd(path, listOf(file.absolutePath))
        }
    }

    private fun infoWithHcxpcapngtool() {
        val path = executor.getToolPath("hcxpcapngtool")
        if (path == null) {
            toast("hcxpcapngtool 未安装")
            return
        }
        selectFile { file ->
            clearOutput()
            appendOutput("▶ hcxpcapngtool --all (完整信息)\n  文件: ${file.name}\n")
            runCmd(path, listOf("--all", file.absolutePath))
        }
    }

    private fun selectFile(onSelected: (File) -> Unit) {
        val files = mutableListOf<File>()
        val dirs = listOf(
            File("/storage/emulated/0/Download"),
            File(filesDir.parentFile, "storage/downloads")
        )
        for (dir in dirs) {
            if (dir.exists()) {
                dir.listFiles()?.filter { f ->
                    f.name.endsWith(".cap") || f.name.endsWith(".pcap") || f.name.endsWith(".pcapng") ||
                    f.name.endsWith(".hccapx") || f.name.endsWith(".22000") || f.name.endsWith(".pmkid")
                }?.let { files.addAll(it) }
            }
        }

        if (files.isEmpty()) {
            toast("未找到抓包文件\n请将 .cap/.pcap/.hccapx/.22000 放到 Download 目录")
            return
        }

        val names = files.map { it.name }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("选择文件")
            .setItems(names) { _, i -> onSelected(files[i]) }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun runCmd(binary: String, args: List<String>) {
        progressIndicator.visibility = android.view.View.VISIBLE
        lifecycleScope.launch {
            executor.runToolAsync(binary, args, object : ToolExecutor.OutputCallback {
                override fun onOutput(line: String) { runOnUiThread { appendOutput(line) } }
                override fun onError(line: String) { runOnUiThread { appendOutput(line) } }
                override fun onComplete(exitCode: Int) {
                    runOnUiThread {
                        progressIndicator.visibility = android.view.View.GONE
                        appendOutput("\n───────────────────────")
                        appendOutput("退出码: $exitCode")
                    }
                }
            })
        }
    }

    private fun showCustomCommandDialog() {
        val input = EditText(this).apply {
            hint = "输入命令，如: aircrack-ng -a 2 file.cap"
            setPadding(32, 32, 32, 32)
        }
        AlertDialog.Builder(this)
            .setTitle("自定义命令")
            .setView(input)
            .setPositiveButton("执行") { _, _ ->
                val cmd = input.text.toString().trim()
                if (cmd.isNotEmpty()) {
                    clearOutput()
                    appendOutput("▶ $cmd\n")
                    progressIndicator.visibility = android.view.View.VISIBLE
                    lifecycleScope.launch {
                        executor.runToolAsync("/system/bin/sh", listOf("-c", cmd), object : ToolExecutor.OutputCallback {
                            override fun onOutput(line: String) { runOnUiThread { appendOutput(line) } }
                            override fun onError(line: String) { runOnUiThread { appendOutput(line) } }
                            override fun onComplete(exitCode: Int) {
                                runOnUiThread {
                                    progressIndicator.visibility = android.view.View.GONE
                                    appendOutput("\n退出码: $exitCode")
                                }
                            }
                        })
                    }
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun appendOutput(text: String) {
        tvOutput.append(text + "\n")
        scrollView.post { scrollView.fullScroll(android.view.View.FOCUS_DOWN) }
    }

    private fun clearOutput() { tvOutput.text = "" }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
    }
}
