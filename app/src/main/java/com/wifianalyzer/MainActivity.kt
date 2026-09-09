package com.wifianalyzer

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.databinding.ActivityMainBinding
import com.wifianalyzer.parsers.FileParser
import com.wifianalyzer.parsers.FileType
import com.wifianalyzer.tools.ToolExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var fileData: ByteArray? = null
    private var fileName: String? = null
    private var fileType: FileType = FileType.UNKNOWN
    private lateinit var executor: ToolExecutor

    private val conversions = mapOf(
        FileType.PCAP to listOf("HC22000" to "hc22000", "HCCAPX" to "hccapx"),
        FileType.CAP to listOf("HC22000" to "hc22000", "HCCAPX" to "hccapx"),
        FileType.PCAPNG to listOf("HC22000" to "hc22000", "HCCAPX" to "hccapx"),
        FileType.HCCAPX to listOf("HC22000" to "hc22000"),
        FileType.HASHCAT_22000 to listOf("HCCAPX" to "hccapx")
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        executor = ToolExecutor(this)

        binding.btnSelectFile.setOnClickListener {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE); type = "*/*"
            }, 1001)
        }

        binding.btnViewFile.setOnClickListener {
            fileData?.let { data ->
                startActivity(Intent(this, FileViewerActivity::class.java).apply {
                    putExtra("FILE_DATA", data); putExtra("FILE_NAME", fileName)
                })
            }
        }

        binding.btnConvert.setOnClickListener {
            if (binding.cardConvert.visibility == View.VISIBLE) {
                binding.cardConvert.visibility = View.GONE
            } else {
                showConvertCard()
            }
        }

        binding.btnStartConvert.setOnClickListener {
            doConvert()
        }
    }

    private fun showConvertCard() {
        val data = fileData ?: return
        fileType = FileParser().detectFileType(data, fileName ?: "")
        val targets = conversions[fileType]
        if (targets.isNullOrEmpty()) {
            Toast.makeText(this, "此格式不支持转换", Toast.LENGTH_SHORT).show()
            return
        }
        binding.cardConvert.visibility = View.VISIBLE
        binding.spinnerTarget.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item, targets.map { it.first }
        )
    }

    private fun doConvert() {
        val data = fileData ?: return
        val targets = conversions[fileType] ?: return
        val idx = binding.spinnerTarget.selectedItemPosition
        val target = targets[idx].second
        val hcxPath = executor.getToolPath("hcxpcapngtool") ?: run {
            Toast.makeText(this, "hcxpcapngtool 未找到", Toast.LENGTH_SHORT).show()
            return
        }

        val srcFile = File(cacheDir, "convert_src.cap")
        srcFile.writeBytes(data)

        binding.tvConvertResult.visibility = View.VISIBLE
        binding.tvConvertResult.text = "转换中..."

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                val outName = if (target == "hc22000") "converted.22000" else "converted.hccapx"
                val outFile = File(cacheDir, outName)
                val flag = if (target == "hc22000") "--ouelist" else "--hccapx"
                executor.runTool(hcxPath, listOf(flag, "-o", outFile.absolutePath, srcFile.absolutePath))
                if (outFile.exists()) "✓ 转换成功\n${outFile.name} (${outFile.length()} bytes)\n${outFile.absolutePath}"
                else "✗ 转换失败"
            }
            binding.tvConvertResult.text = result
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001 && resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                contentResolver.openInputStream(uri)?.use { stream ->
                    fileData = stream.readBytes()
                    fileName = uri.lastPathSegment ?: "unknown"
                    binding.tvSelectedFile.text = "✓ $fileName (${fileData?.size} bytes)"
                    binding.btnViewFile.isEnabled = true
                    binding.btnConvert.isEnabled = true
                    binding.cardConvert.visibility = View.GONE
                }
            }
        }
    }
}
