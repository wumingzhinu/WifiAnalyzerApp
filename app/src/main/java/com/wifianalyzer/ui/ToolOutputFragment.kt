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
            append("File not found: $filePath")
            return
        }
        runAllTools(file)
    }

    private fun runAllTools(file: File) {
        append("File: ${file.name} (${file.length()} bytes)\n")
        progress.visibility = View.VISIBLE

        lifecycleScope.launch {
            val hcxpcapngtool = executor.getToolPath("hcxpcapngtool")
            if (hcxpcapngtool != null) {
                append(">>> hcxpcapngtool <<<\n")
                val r1 = withContext(Dispatchers.IO) { executor.runTool(hcxpcapngtool, listOf(file.absolutePath)) }
                append(r1.output)
                append("exit: ${r1.exitCode}\n")
            }

            val hcxpmktool = executor.getToolPath("hcxpmktool")
            if (hcxpmktool != null) {
                append("\n>>> hcxpmktool <<<\n")
                val r2 = withContext(Dispatchers.IO) { executor.runTool(hcxpmktool, listOf("-i", file.absolutePath)) }
                append(r2.output)
                append("exit: ${r2.exitCode}\n")
            }

            val hcxpsktool = executor.getToolPath("hcxpsktool")
            if (hcxpsktool != null) {
                append("\n>>> hcxpsktool <<<\n")
                val r3 = withContext(Dispatchers.IO) { executor.runTool(hcxpsktool, listOf("-i", file.absolutePath)) }
                append(r3.output)
                append("exit: ${r3.exitCode}\n")
            }

            progress.visibility = View.GONE
            append("\nDone")
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
