package com.wifianalyzer.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.wifianalyzer.R
import com.wifianalyzer.parsers.FileAnalysis
import com.wifianalyzer.parsers.HandshakeInfo

class HandshakeInfoFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_handshake_info, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        @Suppress("DEPRECATION")
        val analysis = arguments?.getParcelable<FileAnalysis>("analysis") ?: return

        val container = view.findViewById<LinearLayout>(R.id.container_handshakes)

        if (analysis.handshakes.isEmpty()) {
            val tv = TextView(requireContext()).apply {
                text = "未检测到握手包信息\n\n请确认文件是否为有效的WiFi抓包文件"
                setTextColor(0xFFFF5722.toInt())
                textSize = 16f
                setPadding(24, 24, 24, 24)
            }
            container.addView(tv)
            return
        }

        for ((i, hs) in analysis.handshakes.withIndex()) {
            val card = createHandshakeCard(hs, i)
            container.addView(card)
        }
    }

    private fun createHandshakeCard(hs: HandshakeInfo, index: Int): View {
        val ctx = requireContext()

        val outer = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
            setBackgroundColor(0xFF21262D.toInt())
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
            lp.bottomMargin = 24
            layoutParams = lp
        }

        if (index > 0) {
            val divider = TextView(ctx).apply {
                text = ""
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 2
                ).also { it.topMargin = 16; it.bottomMargin = 16 }
                setBackgroundColor(0xFF30363D.toInt())
            }
            outer.addView(divider)
        }

        val title = TextView(ctx).apply {
            text = if (index > 0) "握手包 #${index + 1}" else "握手包信息"
            setTextColor(0xFF58A6FF.toInt())
            textSize = 20f
            setPadding(0, 0, 0, 16)
        }
        outer.addView(title)

        val fields = listOf(
            "SSID" to hs.ssid,
            "AP MAC" to hs.apMac,
            "客户端 MAC" to hs.clientMac,
            "加密类型" to hs.encryptionType,
            "消息对" to describeMessagePair(hs.messagePair),
            "握手帧数" to hs.handshakeCount.toString(),
            "密钥版本" to "v${hs.keyVersion}"
        )

        for ((label, value) in fields) {
            outer.addView(createFieldRow(label, value))
        }

        if (hs.pmkid != null) {
            outer.addView(createFieldRow("PMKID", hs.pmkid, 0xFFFF5722.toInt()))
        }
        if (hs.mic != null) {
            outer.addView(createFieldRow("MIC", hs.mic))
        }
        if (hs.nonceAp != null) {
            outer.addView(createFieldRow("AP Nonce", hs.nonceAp, 0xFF8B949E.toInt()))
        }
        if (hs.nonceClient != null) {
            outer.addView(createFieldRow("客户端 Nonce", hs.nonceClient, 0xFF8B949E.toInt()))
        }
        if (hs.eapolLength > 0) {
            outer.addView(createFieldRow("EAPOL长度", "${hs.eapolLength} bytes"))
        }
        if (hs.timestamp != "N/A") {
            outer.addView(createFieldRow("捕获时间", hs.timestamp))
        }

        return outer
    }

    private fun createFieldRow(label: String, value: String, valueColor: Int = 0xFFC9D1D9.toInt()): LinearLayout {
        val ctx = requireContext()
        return LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 6, 0, 6)
            addView(TextView(ctx).apply {
                text = "$label:"
                setTextColor(0xFF8B949E.toInt())
                textSize = 14f
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            })
            addView(TextView(ctx).apply {
                text = value
                setTextColor(valueColor)
                textSize = 14f
                isSingleLine = false
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f)
            })
        }
    }

    private fun describeMessagePair(mp: Int): String = when (mp) {
        0 -> "M1+M2 (基本握手)"
        1 -> "M1+M4"
        2 -> "M2+M3 (标准)"
        3 -> "M2+M3+M4"
        4 -> "M3+M4"
        5 -> "M3+M4+PMKID"
        else -> "类型 $mp"
    }

    companion object {
        fun newInstance(analysis: FileAnalysis): HandshakeInfoFragment {
            return HandshakeInfoFragment().apply {
                arguments = Bundle().apply {
                    putParcelable("analysis", analysis)
                }
            }
        }
    }
}
