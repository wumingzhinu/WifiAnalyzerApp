package com.wifianalyzer.parsers

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

enum class FileType { PCAP, PCAPNG, CAP, HCCAP, HCCAPX, PMKID, HASHCAT_22000, UNKNOWN }

data class FileAnalysis(val fileType: FileType, val fileName: String, val fileSize: Long, val description: String, val rawHex: String)

@Parcelize
data class AiReport(val fileOverview: String, val structureAnalysis: String, val aiConclusion: String) : Parcelable

class FileParser {
    fun detectFileType(data: ByteArray): FileType {
        if (data.size < 4) return FileType.UNKNOWN
        val header = String(data, 0, minOf(data.size, 8))
        return when {
            header.startsWith("HCPX") -> FileType.HCCAPX
            header.startsWith("PMKID") -> FileType.PMKID
            header.startsWith("WPA*") -> FileType.HASHCAT_22000
            data[0] == 0x0A.toByte() && data[1] == 0x0D.toByte() -> FileType.PCAPNG
            data[0] == 0xD4.toByte() && data[1] == 0xC3.toByte() -> FileType.PCAP
            else -> FileType.CAP
        }
    }

    fun parseFile(data: ByteArray, fileName: String): FileAnalysis {
        val fileType = detectFileType(data)
        val desc = when(fileType) {
            FileType.PCAP -> "标准tcpdump/libpcap抓包文件"
            FileType.PCAPNG -> "下一代PCAP格式"
            FileType.HCCAPX -> "Hashcat HCCAPX握手包"
            FileType.HASHCAT_22000 -> "Hashcat 22000模式格式"
            FileType.PMKID -> "PMKID攻击格式"
            else -> "通用抓包文件"
        }
        return FileAnalysis(fileType, fileName, data.size.toLong(), desc, bytesToHex(data, 512))
    }

    fun bytesToHex(bytes: ByteArray, maxLen: Int = bytes.size): String {
        val sb = StringBuilder()
        val limit = minOf(bytes.size, maxLen)
        for (i in 0 until limit step 16) {
            sb.append(String.format("%04X: ", i))
            for (j in i until minOf(i + 16, limit)) sb.append(String.format("%02X ", bytes[j]))
            sb.append(" | ")
            for (j in i until minOf(i + 16, limit)) {
                val b = bytes[j].toInt() and 0xFF
                sb.append(if (b in 32..126) b.toChar() else '.')
            }
            sb.append("\n")
        }
        return sb.toString()
    }
}
