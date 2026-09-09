package com.wifianalyzer

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.tabs.TabLayoutMediator
import com.wifianalyzer.databinding.ActivityFileViewerBinding
import com.wifianalyzer.parsers.AiAnalyzer
import com.wifianalyzer.parsers.FileParser
import com.wifianalyzer.ui.AiAnalysisFragment
import com.wifianalyzer.ui.HandshakeInfoFragment
import com.wifianalyzer.ui.HexViewFragment
import com.wifianalyzer.ui.ToolOutputFragment
import java.io.File

class FileViewerActivity : AppCompatActivity() {
    private lateinit var binding: ActivityFileViewerBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityFileViewerBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnBack.setOnClickListener { finish() }

        val fileData = intent.getByteArrayExtra("FILE_DATA") ?: run { finish(); return }
        val fileName = intent.getStringExtra("FILE_NAME") ?: "unknown"
        val parser = FileParser()
        val analysis = parser.parseFile(fileData, fileName)
        val aiReport = AiAnalyzer().analyze(analysis)

        binding.tvFileInfo.text = "${analysis.fileName} | ${analysis.fileSize} bytes | ${analysis.fileType}"

        val ext = when(analysis.fileType) {
            com.wifianalyzer.parsers.FileType.PCAP, com.wifianalyzer.parsers.FileType.CAP -> "cap"
            com.wifianalyzer.parsers.FileType.PCAPNG -> "pcapng"
            com.wifianalyzer.parsers.FileType.HCCAPX -> "hccapx"
            com.wifianalyzer.parsers.FileType.HASHCAT_22000, com.wifianalyzer.parsers.FileType.HC22000 -> "22000"
            else -> "cap"
        }
        val tmpFile = File(cacheDir, "current_capture.$ext")
        tmpFile.writeBytes(fileData)

        binding.viewPager.adapter = object : androidx.viewpager2.adapter.FragmentStateAdapter(this) {
            override fun getItemCount() = 4
            override fun createFragment(pos: Int): Fragment = when (pos) {
                0 -> HandshakeInfoFragment.newInstance(tmpFile.absolutePath)
                1 -> ToolOutputFragment.newInstance(tmpFile.absolutePath)
                2 -> HexViewFragment.newInstance(analysis.rawHex.toByteArray())
                else -> AiAnalysisFragment.newInstance(aiReport)
            }
        }
        TabLayoutMediator(binding.tabLayout, binding.viewPager) { tab, pos ->
            tab.text = when (pos) {
                0 -> "握手包信息"
                1 -> "工具输出"
                2 -> "原始内容"
                else -> "AI分析"
            }
        }.attach()
    }
}
