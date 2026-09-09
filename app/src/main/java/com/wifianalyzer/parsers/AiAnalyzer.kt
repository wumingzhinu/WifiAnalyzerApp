package com.wifianalyzer.parsers

class AiAnalyzer {
    fun analyze(analysis: FileAnalysis): AiReport {
        val overview = "文件: ${analysis.fileName}\n大小: ${analysis.fileSize} bytes\n类型: ${analysis.fileType}"
        val structure = when(analysis.fileType) {
            FileType.PCAP -> "PCAP: Global Header + Packet Records"
            FileType.HCCAPX -> "HCCAPX: Magic + Handshake Records"
            FileType.HASHCAT_22000 -> "HC22000: Magic + PMKID/EAPOL"
            else -> "结构分析中..."
        }
        val conclusion = when(analysis.fileType) {
            FileType.PCAP -> "标准抓包文件，可用Wireshark分析"
            FileType.HCCAPX -> "握手包文件，可用于密码破解"
            FileType.HASHCAT_22000 -> "最新Hashcat格式，支持PMKID攻击"
            else -> "需要进一步分析"
        }
        return AiReport(overview, structure, conclusion)
    }
}
