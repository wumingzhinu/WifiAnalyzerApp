package com.wifianalyzer.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.R
import com.wifianalyzer.tools.ToolExecutor
import kotlinx.coroutines.launch
import java.io.File

class ToolOutputFragment : Fragment() {

    private lateinit var executor: ToolExecutor
    private lateinit var tvOutput: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var progress: ProgressBar

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_tool_output, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        executor = ToolExecutor(requireContext())
        tvOutput = view.findViewById(R.id.tvToolOutput)
        scrollView = view.findViewById(R.id.toolScrollView)
        progress = view.findViewById(R.id.toolProgress)

        val filePath = arguments?.getString("file_path") ?: return
        val file = File(filePath)
        if (!file.exists()) {
            append("文件不存在: $filePath")
            return
        }

        runAllTools(file)
    }

    private fun runAllTools(file: File) {
        append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        append("文件: ${file.name}")
        append("大小: ${file.length()} bytes")
        append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

        progress.visibility = View.VISIBLE

        val hcxpcapngtool = executor.getToolPath("hcxpcapngtool")
        val hcxpmktool = executor.getToolPath("hcxpmktool")
        val hcxhashtool = executor.getToolPath("hcxhashtool")
        val hcxpsktool = executor.getToolPath("hcxpsktool")

        if (hcxpcapngtool == null) {
            append("⚠ hcxtools 未安装")
            append("工具目录: ${context?.filesDir}/tools/")
            append("请将 hcxpcapngtool 放到该目录")
            progress.visibility = View.GONE
            return
        }

        append("▶ hcxpcapngtool (握手包分析)\n")
        runTool(hcxpcapngtool, listOf(file.absolutePath), "hcxpcapngtool") {
            if (hcxpmktool != null) {
                append("\n▶ hcxpmktool (PMKID分析)\n")
                runTool(hcxpmktool, listOf("-i", file.absolutePath), "hcxpmktool") {
                    if (hcxpsktool != null) {
                        append("\n▶ hcxpsktool (PSK分析)\n")
                        runTool(hcxpsktool, listOf("-i", file.absolutePath), "hcxpsktool") {
                            progress.visibility = View.GONE
                            append("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                            append("分析完成")
                        }
                    } else {
                        progress.visibility = View.GONE
                    }
                }
            } else {
                progress.visibility = View.GONE
            }
        }
    }

    private fun runTool(binary: String, args: List<String>, name: String, onComplete: () -> Unit = {}) {
        lifecycleScope.launch {
            executor.runToolAsync(binary, args, object : ToolExecutor.OutputCallback {
                override fun onOutput(line: String) { append(line) }
                override fun onError(line: String) { append(line) }
                override fun onComplete(exitCode: Int) {
                    append("\n───────────────────────")
                    append("$name 退出码: $exitCode\n")
                    activity?.runOnUiThread { onComplete() }
                }
            })
        }
    }

    private fun append(text: String) {
        activity?.runOnUiThread {
            tvOutput.append(text + "\n")
            scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
        }
    }

    companion object {
        fun newInstance(filePath: String): ToolOutputFragment {
            return ToolOutputFragment().apply {
                arguments = Bundle().apply { putString("file_path", filePath) }
            }
        }
    }
}
