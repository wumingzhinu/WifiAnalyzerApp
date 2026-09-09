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
    private var sourceType: FileType = FileType.UNKNOWN

    private val conversions = mapOf(
        FileType.PCAP to listOf(
            "HC22000 (hashcat推荐)" to "hc22000",
            "HCCAPX (hashcat旧版)" to "hccapx",
            "握手包信息" to "info"
        ),
        FileType.CAP to listOf(
            "HC22000 (hashcat推荐)" to "hc22000",
            "HCCAPX (hashcat旧版)" to "hccapx",
            "握手包信息" to "info"
        ),
        FileType.PCAPNG to listOf(
            "HC22000 (hashcat推荐)" to "hc22000",
            "HCCAPX (hashcat旧版)" to "hccapx",
            "握手包信息" to "info"
        ),
        FileType.HCCAPX to listOf(
            "HC22000 (hashcat推荐)" to "hc22000"
        ),
        FileType.HASHCAT_22000 to listOf(
            "HCCAPX (hashcat旧版)" to "hccapx"
        )
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConvertBinding.inflate(layoutInflater)
        setContentView(binding.root)

        executor = ToolExecutor(this)

        val fileData = intent.getByteArrayExtra("FILE_DATA") ?: run { finish(); return }
        val fileName = intent.getStringExtra("FILE_NAME") ?: "unknown"

        sourceType = FileParser().detectFileType(fileData, fileName)
        val ext = when(sourceType) {
            FileType.PCAP, FileType.CAP -> "cap"
            FileType.PCAPNG -> "pcapng"
            FileType.HCCAPX -> "hccapx"
            FileType.HASHCAT_22000 -> "22000"
            else -> "cap"
        }
        sourceFile = File(cacheDir, "convert_source.$ext")
        sourceFile?.writeBytes(fileData)

        binding.tvSourceInfo.text = "源文件: $fileName\n类型: $sourceType"

        val targets = conversions[sourceType]
        if (targets.isNullOrEmpty()) {
            Toast.makeText(this, "此格式不支持转换", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        binding.spinnerTarget.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, targets.map { it.first }
        )

        binding.btnStartConvert.setOnClickListener {
            val idx = binding.spinnerTarget.selectedItemPosition
            val target = targets[idx].second
            doConvert(target)
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
                        executor.runTool(hcxPath, listOf(
                            "--ouelist", "-o", outFile.absolutePath, src.absolutePath
                        ))
                        if (outFile.exists()) "✓ 已转换: ${outFile.name} (${outFile.length()} bytes)\n路径: ${outFile.absolutePath}"
                        else "✗ 转换失败"
                    }
                    "hccapx" -> {
                        val outFile = File(cacheDir, "converted.hccapx")
                        executor.runTool(hcxPath, listOf(
                            "--hccapx", "-o", outFile.absolutePath, src.absolutePath
                        ))
                        if (outFile.exists()) "✓ 已转换: ${outFile.name} (${outFile.length()} bytes)\n路径: ${outFile.absolutePath}"
                        else "✗ 转换失败"
                    }
                    "info" -> {
                        val r = executor.runTool(hcxPath, listOf(src.absolutePath))
                        r.output
                    }
                    else -> "不支持的转换: $target"
                }
            }
            binding.tvConvertResult.text = result
        }
    }
}
