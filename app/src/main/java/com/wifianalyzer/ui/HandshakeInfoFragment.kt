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
import com.wifianalyzer.converters.ConversionEngine
import com.wifianalyzer.tools.ToolExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class HandshakeInfoFragment : Fragment() {

    private var tvOutput: TextView? = null
    private var scrollView: ScrollView? = null
    private var progress: ProgressBar? = null

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_handshake_info, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        tvOutput = view.findViewById(R.id.tvHandshakeOutput)
        scrollView = view.findViewById(R.id.handshakeScrollView)
        progress = view.findViewById(R.id.handshakeProgress)

        val path = arguments?.getString(ARG_PATH) ?: return
        val kind = arguments?.getString(ARG_KIND) ?: "UNKNOWN"
        val note = arguments?.getString(ARG_NOTE) ?: ""
        val file = File(path)

        append("文件: ${file.name} (${file.length()} bytes)")
        append("格式: $kind")
        append("────────────────────────────")
        if (note.isNotBlank()) { append(note); append("") }

        val cmd = ConversionEngine.infoCommand(kind, file)
        if (!file.exists()) {
            append("✗ 文件不存在: $path")
            return
        }
        if (cmd == null) {
            append("✗ 该格式无内置解析器")
            append("PMKID 行格式无法直接解析，请在「格式转换」里转成 CAP 后再查看。")
            progress?.visibility = View.GONE
            return
        }
        progress?.visibility = View.VISIBLE
        val exec = ToolExecutor(requireContext())
        lifecycleScope.launch {
            val r = withContext(Dispatchers.IO) {
                val bin = exec.getToolPath(cmd.tool) ?: return@withContext null
                exec.runTool(bin, cmd.args)
            }
            if (r == null) {
                append("✗ 未找到工具: ${cmd.tool}")
            } else {
                append(r.output.trimEnd().take(4000))
                append("────────────────────────────")
                append("退出码: ${r.exitCode}")
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
        tvOutput = null; scrollView = null; progress = null
    }

    companion object {
        private const val ARG_PATH = "file_path"
        private const val ARG_KIND = "kind"
        private const val ARG_NOTE = "note"

        fun newInstance(path: String, kind: String, note: String = ""): HandshakeInfoFragment {
            return HandshakeInfoFragment().apply {
                arguments = Bundle().apply {
                    putString(ARG_PATH, path)
                    putString(ARG_KIND, kind)
                    putString(ARG_NOTE, note)
                }
            }
        }
    }
}
