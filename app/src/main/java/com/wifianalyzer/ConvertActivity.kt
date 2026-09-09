package com.wifianalyzer

import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.databinding.ActivityConvertBinding
import com.wifianalyzer.converters.FormatConverter
import com.wifianalyzer.parsers.FileParser
import com.wifianalyzer.parsers.FileType
import java.io.File

class ConvertActivity : AppCompatActivity() {
    private lateinit var binding: ActivityConvertBinding
    private val converter = FormatConverter()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConvertBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val data = intent.getByteArrayExtra("FILE_DATA") ?: run { finish(); return }
        val fileName = intent.getStringExtra("FILE_NAME") ?: "unknown"
        val sourceType = FileParser().detectFileType(data)

        binding.tvSourceFormat.text = "文件: $fileName\n类型: $sourceType"
        val targets = converter.getSupportedTargets(sourceType)
        if (targets.isEmpty()) { Toast.makeText(this, "不支持转换", Toast.LENGTH_SHORT).show(); finish(); return }

        binding.spinnerTargetFormat.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, targets.map { it.name })
        binding.btnConvert.setOnClickListener {
            val target = targets[binding.spinnerTargetFormat.selectedItemPosition]
            val output = File(cacheDir, "converted.${target.name.lowercase()}")
            val result = converter.convert(data, sourceType, target, output)
            binding.cardResult.visibility = View.VISIBLE
            binding.tvConvertResult.text = result.message
        }
    }
}
