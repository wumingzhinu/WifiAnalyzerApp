package com.wifianalyzer.tools

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.R
import kotlinx.coroutines.launch
import java.io.File

class ToolsActivity : AppCompatActivity() {

    private lateinit var executor: ToolExecutor
    private lateinit var tvOutput: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var progressIndicator: ProgressBar
    private var currentProcess: Process? = null

    data class Tool(
        val name: String,
        val displayName: String,
        val description: String,
        val assetName: String?,
        val commands: List<ToolCommand>
    )

    data class ToolCommand(
        val name: String,
        val args: List<String>,
        val description: String,
        val needsFile: Boolean = false,
        val needsWordlist: Boolean = false
    )

    private val tools = listOf(
        Tool(
            name = "aircrack-ng",
            displayName = "Aircrack-ng",
            description = "WiFi密码破解/握手包分析",
            assetName = "aircrack-ng",
            commands = listOf(
                ToolCommand(
                    name = "分析握手包",
                    args = listOf("-a", "2"),
                    description = "分析.cap文件中的握手包",
                    needsFile = true
                ),
                ToolCommand(
                    name = "字典破解",
                    args = listOf("-a", "2", "-w"),
                    description = "使用字典破解WPA密码",
                    needsFile = true,
                    needsWordlist = true
                ),
                ToolCommand(
                    name = "显示帮助",
                    args = listOf("--help"),
                    description = "显示aircrack-ng帮助信息"
                )
            )
        ),
        Tool(
            name = "hashcat",
            displayName = "Hashcat",
            description = "GPU加速密码破解",
            assetName = "hashcat",
            commands = listOf(
                ToolCommand(
                    name = "WPA字典攻击",
                    args = listOf("-m", "22000"),
                    description = "使用字典破解WPA/WPA2",
                    needsFile = true,
                    needsWordlist = true
                ),
                ToolCommand(
                    name = "PMKID攻击",
                    args = listOf("-m", "22000", "--attack-mode", "0"),
                    description = "PMKID离线攻击",
                    needsFile = true,
                    needsWordlist = true
                ),
                ToolCommand(
                    name = "显示帮助",
                    args = listOf("--help"),
                    description = "显示hashcat帮助信息"
                )
            )
        ),
        Tool(
            name = "reaver",
            displayName = "Reaver",
            description = "WPS PIN攻击",
            assetName = "reaver",
            commands = listOf(
                ToolCommand(
                    name = "WPS暴力破解",
                    args = listOf("-i", "wlan0mon", "-b"),
                    description = "暴力破解WPS PIN",
                    needsFile = false
                ),
                ToolCommand(
                    name = "扫描WPS",
                    args = listOf("-i", "wlan0mon", "-c"),
                    description = "扫描WPS网络"
                )
            )
        ),
        Tool(
            name = "mdk4",
            displayName = "MDK4",
            description = "无线网络测试工具",
            assetName = "mdk4",
            commands = listOf(
                ToolCommand(
                    name = "Deauth攻击",
                    args = listOf("d", "-B"),
                    description = "发送deauth帧",
                    needsFile = false
                ),
                ToolCommand(
                    name = "AP flooding",
                    args = listOf("a", "-b"),
                    description = "伪造AP洪水攻击"
                )
            )
        ),
        Tool(
            name = "hcxpcapngtool",
            displayName = "HCXpcapngtool (hcxtools)",
            description = "PCAP/PCAPNG → HC22000/HCCAPX 格式转换 + 握手包提取",
            assetName = "hcxpcapngtool",
            commands = listOf(
                ToolCommand(
                    name = "提取握手包 → HC22000",
                    args = listOf("--ouelist"),
                    description = "从pcap提取握手包转为HC22000格式 (hashcat推荐)",
                    needsFile = true
                ),
                ToolCommand(
                    name = "提取握手包 → HCCAPX",
                    args = listOf("--hccapx"),
                    description = "从pcap提取握手包转为HCCAPX格式",
                    needsFile = true
                ),
                ToolCommand(
                    name = "提取PMKID",
                    args = listOf("--pmkid"),
                    description = "从pcap提取PMKID",
                    needsFile = true
                ),
                ToolCommand(
                    name = "显示所有信息",
                    args = listOf("--all"),
                    description = "显示pcap文件的全部详细信息",
                    needsFile = true
                ),
                ToolCommand(
                    name = "显示帮助",
                    args = listOf("--help"),
                    description = "显示hcxpcapngtool帮助"
                )
            )
        ),
        Tool(
            name = "hcxdumptool",
            displayName = "HCXdumptool (hcxtools)",
            description = "主动抓取WPA握手包/PMKID (需root+网卡)",
            assetName = "hcxdumptool",
            commands = listOf(
                ToolCommand(
                    name = "扫描网络",
                    args = listOf("--status"),
                    description = "扫描附近WiFi网络"
                ),
                ToolCommand(
                    name = "抓取握手包",
                    args = listOf("--filterlist", "--filtermode=2"),
                    description = "抓取指定目标的握手包",
                    needsFile = false
                )
            )
        ),
        Tool(
            name = "hashcat-utils",
            displayName = "Hashcat-utils",
            description = "hashcat辅助工具集 (cap2hccapx, combinator等)",
            assetName = "cap2hccapx",
            commands = listOf(
                ToolCommand(
                    name = "CAP → HCCAPX",
                    args = emptyList(),
                    description = "将.cap文件转为HCCAPX格式",
                    needsFile = true
                ),
                ToolCommand(
                    name = "显示帮助",
                    args = listOf("--help"),
                    description = "显示帮助信息"
                )
            )
        ),
        Tool(
            name = "cowpatty",
            displayName = "Cowpatty",
            description = "WPA-PSK字典攻击",
            assetName = "cowpatty",
            commands = listOf(
                ToolCommand(
                    name = "字典攻击",
                    args = listOf("-c", "-r", "-s"),
                    description = "WPA-PSK字典攻击",
                    needsFile = true,
                    needsWordlist = true
                )
            )
        ),
        Tool(
            name = "custom",
            displayName = "自定义命令",
            description = "执行自定义shell命令",
            assetName = null,
            commands = listOf(
                ToolCommand(
                    name = "Shell命令",
                    args = emptyList(),
                    description = "执行任意命令"
                )
            )
        )
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_tools)

        executor = ToolExecutor(this)
        tvOutput = findViewById(R.id.tvOutput)
        scrollView = findViewById(R.id.scrollView)
        progressIndicator = findViewById(R.id.progressIndicator)

        setupToolList()
        extractBundledTools()
    }

    private fun extractBundledTools() {
        lifecycleScope.launch {
            val toolsDir = File(filesDir, "tools")
            toolsDir.mkdirs()

            val assetFiles = try { assets.list("tools") ?: emptyArray() } catch (e: Exception) { emptyArray() }
            if (assetFiles.isNotEmpty()) {
                appendOutput("正在释放工具二进制文件...")
                for (file in assetFiles) {
                    val target = File(toolsDir, file)
                    if (!target.exists()) {
                        try {
                            assets.open("tools/$file").use { input ->
                                target.outputStream().use { output -> input.copyTo(output) }
                            }
                            target.setExecutable(true)
                            appendOutput("✅ 已释放: $file")
                        } catch (e: Exception) {
                            appendOutput("❌ 释放失败: $file - ${e.message}")
                        }
                    }
                }
                appendOutput("工具准备完成\n")
            } else {
                appendOutput("⚠️ 未找到预装工具，请手动放置二进制文件到:")
                appendOutput("${toolsDir.absolutePath}/")
                appendOutput("\n或通过Termux安装:\npkg install aircrack-ng\n")
            }
        }
    }

    private fun setupToolList() {
        val container = findViewById<LinearLayout>(R.id.toolContainer)
        container.removeAllViews()

        for (tool in tools) {
            val toolView = createToolCard(tool)
            container.addView(toolView)
        }
    }

    private fun createToolCard(tool: Tool): View {
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 24, 32, 24)
            setBackgroundColor(0xFF21262D.toInt())
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            lp.bottomMargin = 16
            layoutParams = lp
        }

        val titleRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
        }

        val statusIcon = TextView(this).apply {
            val available = executor.isToolAvailable(tool.name)
            text = if (available) "●" else "○"
            setTextColor(if (available) 0xFF3FB950.toInt() else 0xFF8B949E.toInt())
            textSize = 18f
            setPadding(0, 0, 16, 0)
        }
        titleRow.addView(statusIcon)

        val titleText = TextView(this).apply {
            text = tool.displayName
            setTextColor(0xFFE6EDF3.toInt())
            textSize = 18f
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        titleRow.addView(titleText)
        layout.addView(titleRow)

        val descText = TextView(this).apply {
            text = tool.description
            setTextColor(0xFF8B949E.toInt())
            textSize = 13f
            setPadding(34, 4, 0, 12)
        }
        layout.addView(descText)

        for (cmd in tool.commands) {
            val btn = android.widget.Button(this).apply {
                text = cmd.name
                setBackgroundColor(0xFF30363D.toInt())
                setTextColor(0xFF58A6FF.toInt())
                textSize = 14f
                isAllCaps = false
                val bLp = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
                bLp.bottomMargin = 8
                layoutParams = bLp
                setPadding(24, 16, 24, 16)

                setOnClickListener { executeTool(tool, cmd) }
            }
            layout.addView(btn)
        }

        return layout
    }

    private fun executeTool(tool: Tool, cmd: ToolCommand) {
        if (tool.name == "custom") {
            showCustomCommandDialog()
            return
        }

        val binaryPath = executor.getToolPath(tool.name)
        if (binaryPath == null) {
            AlertDialog.Builder(this)
                .setTitle("工具未安装")
                .setMessage("${tool.displayName} 未找到。\n\n请通过以下方式安装:\n1. 将二进制文件放到 ${filesDir}/tools/\n2. 或通过Termux安装")
                .setPositiveButton("确定", null)
                .show()
            return
        }

        if (cmd.needsFile) {
            showFileSelectionDialog(tool, cmd, binaryPath)
        } else {
            runCommand(binaryPath, cmd.args)
        }
    }

    private fun showFileSelectionDialog(tool: Tool, cmd: ToolCommand, binaryPath: String) {
        val files = mutableListOf<File>()
        val downloadDir = File("/storage/emulated/0/Download")
        if (downloadDir.exists()) {
            downloadDir.listFiles()?.filter { f ->
                f.name.endsWith(".cap") || f.name.endsWith(".pcap") || f.name.endsWith(".pcapng") ||
                f.name.endsWith(".hccapx") || f.name.endsWith(".22000") || f.name.endsWith(".pmkid")
            }?.let { files.addAll(it) }
        }

        val termuxDir = File("/data/data/com.termux/files/home/storage/downloads")
        if (termuxDir.exists()) {
            termuxDir.listFiles()?.filter { f ->
                f.name.endsWith(".cap") || f.name.endsWith(".pcap") || f.name.endsWith(".pcapng") ||
                f.name.endsWith(".hccapx") || f.name.endsWith(".22000") || f.name.endsWith(".pmkid")
            }?.let { files.addAll(it) }
        }

        if (files.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("未找到抓包文件")
                .setMessage("请将 .cap/.pcap/.hccapx/.22000 文件放到 Download 目录")
                .setPositiveButton("确定", null)
                .show()
            return
        }

        val fileNames = files.map { it.name }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("选择抓包文件")
            .setItems(fileNames) { _, which ->
                if (cmd.needsWordlist) {
                    showWordlistDialog(tool, cmd, binaryPath, files[which])
                } else {
                    val args = cmd.args.toMutableList()
                    args.add(files[which].absolutePath)
                    runCommand(binaryPath, args)
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun showWordlistDialog(tool: Tool, cmd: ToolCommand, binaryPath: String, pcapFile: File) {
        val wordlists = mutableListOf<File>()
        val commonPaths = listOf(
            "/storage/emulated/0/Download",
            "/data/data/com.termux/files/home/storage/downloads",
            "/data/data/com.termux/files/usr/share/wordlists",
            "/usr/share/wordlists"
        )

        for (path in commonPaths) {
            val dir = File(path)
            if (dir.exists()) {
                dir.listFiles()?.filter { f ->
                    f.name.endsWith(".txt") || f.name.endsWith(".lst") || f.name.endsWith(".dic")
                }?.let { wordlists.addAll(it) }
            }
        }

        if (wordlists.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("未找到字典文件")
                .setMessage("请下载字典文件到 Download 目录\n\n推荐字典:\n- rockyou.txt\n- password.lst")
                .setPositiveButton("确定", null)
                .show()
            return
        }

        val wlNames = wordlists.map { it.name }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("选择字典文件")
            .setItems(wlNames) { _, which ->
                val args = cmd.args.toMutableList()
                args.add(pcapFile.absolutePath)
                // 插入 -w 参数和字典路径
                val insertIdx = args.indexOf("-w")
                if (insertIdx >= 0) {
                    args.add(insertIdx + 1, wordlists[which].absolutePath)
                } else {
                    args.add("-w")
                    args.add(wordlists[which].absolutePath)
                }
                runCommand(binaryPath, args)
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun showCustomCommandDialog() {
        val input = EditText(this).apply {
            hint = "输入命令，如: aircrack-ng -a 2 /path/to/file.cap"
            setPadding(32, 32, 32, 32)
        }

        AlertDialog.Builder(this)
            .setTitle("执行自定义命令")
            .setView(input)
            .setPositiveButton("执行") { _, _ ->
                val cmd = input.text.toString().trim()
                if (cmd.isNotEmpty()) {
                    runShellCommand(cmd)
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun runCommand(binaryPath: String, args: List<String>) {
        clearOutput()
        appendOutput("▶ 执行: $binaryPath ${args.joinToString(" ")}\n")
        progressIndicator.visibility = View.VISIBLE

        lifecycleScope.launch {
            val startTime = System.currentTimeMillis()
            executor.runToolAsync(binaryPath, args, object : ToolExecutor.OutputCallback {
                override fun onOutput(line: String) {
                    runOnUiThread { appendOutput(line) }
                }
                override fun onError(line: String) {
                    runOnUiThread { appendOutput("ERR: $line") }
                }
                override fun onComplete(exitCode: Int) {
                    runOnUiThread {
                        progressIndicator.visibility = View.GONE
                        appendOutput("\n───────────────────────")
                        appendOutput("退出码: $exitCode")
                        appendOutput("耗时: ${System.currentTimeMillis() - startTime}ms")
                    }
                }
            })
        }
    }

    private fun runShellCommand(command: String) {
        clearOutput()
        appendOutput("▶ 执行: sh -c \"$command\"\n")
        progressIndicator.visibility = View.VISIBLE

        lifecycleScope.launch {
            val startTime = System.currentTimeMillis()
            executor.runToolAsync("/system/bin/sh", listOf("-c", command), object : ToolExecutor.OutputCallback {
                override fun onOutput(line: String) {
                    runOnUiThread { appendOutput(line) }
                }
                override fun onError(line: String) {
                    runOnUiThread { appendOutput("ERR: $line") }
                }
                override fun onComplete(exitCode: Int) {
                    runOnUiThread {
                        progressIndicator.visibility = View.GONE
                        appendOutput("\n───────────────────────")
                        appendOutput("退出码: $exitCode")
                        appendOutput("耗时: ${System.currentTimeMillis() - startTime}ms")
                    }
                }
            })
        }
    }

    private fun appendOutput(text: String) {
        tvOutput.append(text + "\n")
        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }

    private fun clearOutput() {
        tvOutput.text = ""
    }
}
