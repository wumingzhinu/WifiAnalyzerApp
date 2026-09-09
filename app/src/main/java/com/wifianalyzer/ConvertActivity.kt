package com.wifianalyzer

import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.databinding.ActivityConvertBinding
import com.wifianalyzer.parsers.FileParser
import com.wifianalyzer.parsers.FileType
import com.wifianalyzer.tools.ToolExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class ConvertActivity : AppCompatActivity() {

    private lateinit var binding: ActivityConvertBinding
    private lateinit var executor: ToolExecutor
    private var sourceFile: File? = null

    private val conversions = mapOf(
        FileType.PCAP to listOf("HC22000" to "hc22000", "HCCAPX" to "hccapx"),
        FileType.CAP to listOf("HC22000" to "hc22000", "HCCAPX" to "hccapx"),
        FileType.PCAPNG to listOf("HC22000" to "hc22000", "HCCAPX" to "hccapx"),
        FileType.HCCAPX to listOf("HC22000" to "hc22000"),
        FileType.HASHCAT_22000 to listOf("HCCAPX" to "hccapx")
    )

    private var currentTargets: List<Pair<String, String>> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConvertBinding.inflate(layoutInflater)
        setContentView(binding.root)

        executor = ToolExecutor(this)

        val fileData = intent.getByteArrayExtra("FILE_DATA") ?: run { finish(); return }
        val fileName = intent.getStringExtra("FILE_NAME") ?: "unknown"

        val fileType = FileParser().detectFileType(fileData, fileName)
        val ext = when (fileType) {
            FileType.PCAP, FileType.CAP -> "cap"
            FileType.PCAPNG -> "pcapng"
            FileType.HCCAPX -> "hccapx"
            FileType.HASHCAT_22000 -> "22000"
            else -> "cap"
        }
        sourceFile = File(cacheDir, "convert_source.$ext")
        sourceFile?.writeBytes(fileData)

        binding.tvSourceInfo.text = "源文件: $fileName\n类型: $fileType"

        currentTargets = conversions[fileType] ?: emptyList()
        if (currentTargets.isEmpty()) {
            Toast.makeText(this, "此格式不支持转换", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        binding.spinnerTarget.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, currentTargets.map { it.first }
        )

        binding.btnStartConvert.setOnClickListener {
            val idx = binding.spinnerTarget.selectedItemPosition
            doConvert(currentTargets[idx].second)
        }

        binding.btnBack.setOnClickListener { finish() }
    }

    private fun doConvert(target: String) {
        val src = sourceFile ?: return
        val hcxPath = executor.getToolPath("hcxpcapngtool") ?: run {
            Toast.makeText(this, "hcxpcapngtool 未找到", Toast.LENGTH_SHORT).show()
            return
        }
        binding.tvConvertResult.visibility = View.VISIBLE
        binding.tvConvertResult.text = "转换中..."
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                when (target) {
                    "hc22000" -> {
                        val outFile = File(cacheDir, "converted.22000")
                        executor.runTool(hcxPath, listOf("--ouelist", "-o", outFile.absolutePath, src.absolutePath))
                        if (outFile.exists()) "OK: ${outFile.absolutePath} (${outFile.length()} bytes)" else "FAIL"
                    }
                    "hccapx" -> {
                        val outFile = File(cacheDir, "converted.hccapx")
                        executor.runTool(hcxPath, listOf("--hccapx", "-o", outFile.absolutePath, src.absolutePath))
                        if (outFile.exists()) "OK: ${outFile.absolutePath} (${outFile.length()} bytes)" else "FAIL"
                    }
                    "info" -> {
                        val r = executor.runTool(hcxPath, listOf(src.absolutePath))
                        r.output
                    }
                    else -> "Unknown: $target"
                }
            }
            binding.tvConvertResult.text = result
        }
    }
}
