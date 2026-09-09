package com.wifianalyzer.parsers

class AiAnalyzer {

    fun analyze(analysis: FileAnalysis): AiReport {
        val overview = buildOverview(analysis)
        val handshakeSummary = buildHandshakeSummary(analysis.handshakes)
        val securityAnalysis = buildSecurityAnalysis(analysis.handshakes)
        val crackableInfo = buildCrackableInfo(analysis)
        val recommendations = buildRecommendations(analysis)

        return AiReport(overview, handshakeSummary, securityAnalysis, crackableInfo, recommendations)
    }

    private fun buildOverview(analysis: FileAnalysis): String {
        return buildString {
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            appendLine("文件信息")
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            appendLine("文件名: ${analysis.fileName}")
            appendLine("大小: ${analysis.fileSize} 字节")
            appendLine("类型: ${analysis.fileType.name}")
            appendLine("握手包数量: ${analysis.handshakes.size}")
            if (analysis.packets.isNotEmpty()) appendLine("数据包数量: ${analysis.packets.size}")
            appendLine()
            appendLine("支持状态: ${when(analysis.fileType) {
                FileType.PCAP, FileType.CAP -> "标准抓包格式，可用Wireshark/Hashcat直接处理"
                FileType.HCCAPX -> "Hashcat HCCAPX格式，可直接用于密码破解"
                FileType.HASHCAT_22000, FileType.HC22000 -> "Hashcat 22000模式，最新推荐格式"
                FileType.PMKID -> "PMKID 格式，被动捕获获取"
                else -> "未知格式"
            }}")
        }
    }

    private fun buildHandshakeSummary(handshakes: List<HandshakeInfo>): String {
        if (handshakes.isEmpty()) {
            return "未检测到有效握手包\n\n可能原因:\n- 文件为空或格式损坏\n- 不是WiFi抓包文件\n- 未捕获到完整握手过程"
        }

        return buildString {
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            appendLine("握手包详情")
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            for ((i, hs) in handshakes.withIndex()) {
                if (handshakes.size > 1) {
                    appendLine("─ 第 ${i + 1} 个握手包 ─")
                }
                appendLine()
                appendLine("SSID (网络名称): ${hs.ssid}")
                appendLine("AP MAC (路由器): ${hs.apMac}")
                appendLine("客户端 MAC:      ${hs.clientMac}")
                appendLine("加密类型:        ${hs.encryptionType}")
                if (hs.timestamp != "N/A") appendLine("捕获时间:        ${hs.timestamp}")
                if (hs.pmkid != null) appendLine("PMKID:           ${hs.pmkid}")
                if (hs.mic != null) appendLine("MIC:             ${hs.mic}")
                if (hs.nonceAp != null) appendLine("AP Nonce:        ${hs.nonceAp}")
                if (hs.nonceClient != null) appendLine("客户端 Nonce:    ${hs.nonceClient}")
                appendLine("消息对类型:      ${describeMessagePair(hs.messagePair)}")
                appendLine("密钥版本:        ${hs.keyVersion}")
                appendLine("握手帧数量:      ${hs.handshakeCount}")
                appendLine()
            }
        }
    }

    private fun buildSecurityAnalysis(handshakes: List<HandshakeInfo>): String {
        if (handshakes.isEmpty()) return "无握手包可供安全分析"

        return buildString {
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            appendLine("安全分析")
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            for (hs in handshakes) {
                appendLine("网络: ${hs.ssid}")
                when (hs.encryptionType) {
                    "PMKID" -> {
                        appendLine("  ⚠️ PMKID攻击 - 仅需AP广播即可获取")
                        appendLine("  无需客户端在线，无需deauth攻击")
                        appendLine("  Hashcat命令: hashcat -m 22000 file.22000 wordlist.txt")
                    }
                    "WPA2 EAPOL" -> {
                        appendLine("  ⚠️ WPA2四次握手 - 需完整握手包")
                        appendLine("  Hashcat命令: hashcat -m 22000 file.22000 wordlist.txt")
                    }
                    "WPA" -> {
                        appendLine("  ⚠️ WPA - 使用较弱的密钥派生")
                        appendLine("  Hashcat命令: hashcat -m 2500 file.hccapx wordlist.txt")
                    }
                    "WPA2" -> {
                        appendLine("  ⚠️ WPA2 - 可通过字典/暴力破解")
                        appendLine("  Hashcat命令: hashcat -m 2500 file.hccapx wordlist.txt")
                    }
                    else -> appendLine("  加密: ${hs.encryptionType}")
                }
                appendLine()
            }
        }
    }

    private fun buildCrackableInfo(analysis: FileAnalysis): String {
        val hs = analysis.handshakes
        if (hs.isEmpty()) return "无可用破解信息"

        return buildString {
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            appendLine("破解可行性")
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            for (h in hs) {
                appendLine("目标: ${h.ssid} (${h.apMac})")
                appendLine()

                val hasPmkid = h.pmkid != null
                val hasFullHandshake = h.handshakeCount >= 3
                val hasMic = h.mic != null

                appendLine("攻击向量:")
                if (hasPmkid) {
                    appendLine("  ✅ PMKID (最快, 无需客户端)")
                }
                if (hasFullHandshake || hasMic) {
                    appendLine("  ✅ EAPOL字典攻击")
                    appendLine("  ✅ EAPOL暴力破解")
                }
                if (!hasPmkid && !hasFullHandshake && !hasMic) {
                    appendLine("  ❌ 握手包不完整，可能无法破解")
                }
                appendLine()

                appendLine("推荐工具:")
                appendLine("  Hashcat: hashcat -m 22000 <file> <wordlist>")
                appendLine("  Aircrack: aircrack-ng -w <wordlist> <file>")
                appendLine()
            }
        }
    }

    private fun buildRecommendations(analysis: FileAnalysis): String {
        val hs = analysis.handshakes
        return buildString {
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            appendLine("建议")
            appendLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            if (hs.isEmpty()) {
                appendLine("1. 确认文件是有效的WiFi抓包文件")
                appendLine("2. 尝试重新抓取握手包")
                appendLine("3. 使用aircrack-ng验证: aircrack-ng <file>")
            } else {
                appendLine("1. 使用Hashcat 22000模式处理此文件")
                appendLine("2. 选择合适字典: 常用密码/手机号/生日")
                appendLine("3. SSID可能暗示密码规律: ${hs.firstOrNull()?.ssid ?: "无"}")
                if (hs.any { it.ssid.matches(Regex(".*[0-9]{4,}.*")) }) {
                    appendLine("4. ⚠️ SSID含数字，建议尝试纯数字/年份密码")
                }
                if (hs.any { it.ssid.length <= 4 }) {
                    appendLine("4. ⚠️ SSID很短，密码可能也很简单")
                }
            }
        }
    }

    private fun describeMessagePair(mp: Int): String {
        return when (mp) {
            0 -> "M1+M2 (基本握手)"
            1 -> "M1+M4 (完整四次握手)"
            2 -> "M2+M3 (标准四次握手)"
            3 -> "M2+M3+M4 (完整四次握手)"
            4 -> "M3+M4 (四次握手第3/4包)"
            5 -> "M3+M4 (四次握手,含PMKID)"
            else -> "未知 ($mp)"
        }
    }
}
