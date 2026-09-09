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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class HandshakeInfoFragment : Fragment() {

    private var tvOutput: TextView? = null
    private var scrollView: ScrollView? = null
    private var progress: ProgressBar? = null
    private var executor: ToolExecutor? = null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_handshake_info, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        tvOutput = view.findViewById(R.id.tvHandshakeOutput)
        scrollView = view.findViewById(R.id.handshakeScrollView)
        progress = view.findViewById(R.id.handshakeProgress)
        executor = ToolExecutor(requireContext())

        val filePath = arguments?.getString("file_path") ?: return
        val file = File(filePath)
        if (!file.exists()) {
            append("文件不存在: $filePath")
            return
        }
        runHcxpcapngtool(file)
    }

    private fun runHcxpcapngtool(file: File) {
        append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        append("文件: ${file.name}")
        append("大小: ${file.length()} bytes")
        append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

        progress?.visibility = View.VISIBLE

        val hcxPath = executor?.getToolPath("hcxpcapngtool")
        if (hcxPath == null) {
            append("⚠ hcxpcapngtool 未找到")
            append("正在尝试释放工具...")
            lifecycleScope.launch {
                val extracted = withContext(Dispatchers.IO) {
                    executor?.extractBinary("hcxpcapngtool", "hcxpcapngtool")
                }
                if (extracted != null) {
                    append("✓ 工具已释放: $extracted\n")
                    runTool(extracted, file)
                } else {
                    append("✗ 工具释放失败")
                    progress?.visibility = View.GONE
                }
            }
            return
        }
        runTool(hcxPath, file)
    }

    private fun runTool(binaryPath: String, file: File) {
        append("▶ hcxpcapngtool ${file.name}\n")
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                executor?.runTool(binaryPath, listOf(file.absolutePath))
            }
            if (result != null) {
                append(result.output)
                append("\n───────────────────────")
                append("退出码: ${result.exitCode}")
            }
            progress?.visibility = View.GONE
        }
    }

    private fun append(text: String) {
        if (activity == null || !isAdded) return
        activity?.runOnUiThread {
            tvOutput?.append(text + "\n")
            scrollView?.post { scrollView?.fullScroll(View.FOCUS_DOWN) }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        tvOutput = null
        scrollView = null
        progress = null
    }

    companion object {
        fun newInstance(filePath: String): HandshakeInfoFragment {
            return HandshakeInfoFragment().apply {
                arguments = Bundle().apply { putString("file_path", filePath) }
            }
        }
    }
}
