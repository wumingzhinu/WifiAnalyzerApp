package com.wifianalyzer

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.android.material.tabs.TabLayoutMediator
import com.wifianalyzer.converters.ConversionEngine
import com.wifianalyzer.databinding.ActivityFileViewerBinding
import com.wifianalyzer.parsers.AiAnalyzer
import com.wifianalyzer.parsers.FileParser
import com.wifianalyzer.ui.AiAnalysisFragment
import com.wifianalyzer.ui.HandshakeInfoFragment
import com.wifianalyzer.ui.HexViewFragment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class FileViewerActivity : AppCompatActivity() {
    private lateinit var binding: ActivityFileViewerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }

        val fileData = intent.getByteArrayExtra("FILE_DATA") ?: run { finish(); return }
        val fileName = intent.getStringExtra("FILE_NAME") ?: "unknown"
        val analysis = FileParser().parseFile(fileData, fileName)
        val aiReport = AiAnalyzer().analyze(analysis)

        binding.tvFileInfo.text =
            "${analysis.fileName} | ${analysis.fileSize}B | ${analysis.fileType.name}"

        lifecycleScope.launch {
            val prepared = withContext(Dispatchers.IO) {
                ConversionEngine.prepare(this@FileViewerActivity, fileData, fileName, analysis.fileType)
            }
            val tabs = listOf("握手包信息", "原始内容", "AI分析")
            binding.viewPager.adapter = object : androidx.viewpager2.adapter.FragmentStateAdapter(this) {
                override fun getItemCount() = tabs.size
                override fun createFragment(pos: Int): Fragment = when (pos) {
                    0 -> HandshakeInfoFragment.newInstance(prepared.path.absolutePath, prepared.kind, prepared.note)
                    1 -> HexViewFragment.newInstance(analysis.rawHex.toByteArray())
                    else -> AiAnalysisFragment.newInstance(aiReport)
                }
            }
            TabLayoutMediator(binding.tabLayout, binding.viewPager) { tab, pos ->
                tab.text = tabs[pos]
            }.attach()
        }
    }
}
