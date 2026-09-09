package com.wifianalyzer.tools

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
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
        checkTools()
    }

    private fun checkTools() {
        val hcx = executor.getToolPath("hcxpcapngtool")
        appendOutput("hcxpcapngtool: ${if (hcx != null) "OK" else "NOT FOUND"}")
    }

    private fun runCmd(binary: String, args: List<String>) {
        progressIndicator.visibility = android.view.View.VISIBLE
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { executor.runTool(binary, args) }
            appendOutput(result.output)
            appendOutput("\nexit: ${result.exitCode}")
            progressIndicator.visibility = android.view.View.GONE
        }
    }

    private fun appendOutput(text: String) {
        tvOutput.append(text + "\n")
        scrollView.post { scrollView.fullScroll(android.view.View.FOCUS_DOWN) }
    }
}
