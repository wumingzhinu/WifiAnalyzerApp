package com.wifianalyzer

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wifianalyzer.converters.ConversionEngine
import com.wifianalyzer.converters.ConversionEngine.Target
import com.wifianalyzer.databinding.ActivityMainBinding
import com.wifianalyzer.parsers.FileParser
import com.wifianalyzer.parsers.FileType
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var fileData: ByteArray? = null
    private var fileName: String? = null
    private var fileType: FileType = FileType.UNKNOWN
    private var targets: List<Target> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnSelectFile.setOnClickListener {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }, 1001)
        }

        binding.btnViewFile.setOnClickListener {
            fileData?.let { data ->
                startActivity(Intent(this, FileViewerActivity::class.java).apply {
                    putExtra("FILE_DATA", data)
                    putExtra("FILE_NAME", fileName)
                })
            }
        }

        binding.btnConvert.setOnClickListener {
            if (binding.cardConvert.visibility == View.VISIBLE) binding.cardConvert.visibility = View.GONE
            else showConvertCard()
        }

        binding.btnStartConvert.setOnClickListener { doConvert() }
    }

    private fun showConvertCard() {
        val data = fileData ?: return
        fileType = FileParser().detectFileType(data, fileName ?: "")
        targets = ConversionEngine.targetsFor(fileType)
        if (targets.isEmpty()) {
            Toast.makeText(this, "格式 ${fileType.name} 不支持互转", Toast.LENGTH_SHORT).show()
            return
        }
        binding.cardConvert.visibility = View.VISIBLE
        binding.spinnerTarget.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item,
            targets.map { it.label })
    }

    private fun doConvert() {
        val data = fileData ?: return
        if (targets.isEmpty()) return
        val target = targets[binding.spinnerTarget.selectedItemPosition]
        val src = File(cacheDir, "src.${ConversionEngine.sourceExt(fileType)}")
        src.writeBytes(data)
        binding.tvConvertResult.visibility = View.VISIBLE
        binding.tvConvertResult.text = "转换中..."
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { ConversionEngine.convert(this@MainActivity, src, fileType, target) }
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
