package com.wifianalyzer

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.wifianalyzer.databinding.ActivityMainBinding
import com.wifianalyzer.parsers.FileParser

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private var fileData: ByteArray? = null
    private var fileName: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

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
            fileData?.let { data ->
                startActivity(Intent(this, ConvertActivity::class.java).apply {
                    putExtra("FILE_DATA", data); putExtra("FILE_NAME", fileName)
                })
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1001 && resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                contentResolver.openInputStream(uri)?.use { stream ->
                    fileData = stream.readBytes()
                    fileName = uri.lastPathSegment ?: "unknown"
                    binding.tvSelectedFile.text = "✅ $fileName (${fileData?.size} bytes)"
                    binding.btnViewFile.isEnabled = true
                    binding.btnConvert.isEnabled = true
                }
            }
        }
    }
}
