package com.wifianalyzer.parsers

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.text.SimpleDateFormat
import java.util.*

enum class FileType { PCAP, PCAPNG, CAP, HCCAPX, HCCAP, PMKID, HASHCAT_22000, HC22000, HC22001, WKP, UNKNOWN }

@Parcelize
data class HandshakeInfo(
    val ssid: String,
    val apMac: String,
    val clientMac: String,
    val timestamp: String,
    val encryptionType: String,
    val keyVersion: Int,
    val pmkid: String?,
    val nonceAp: String?,
    val nonceClient: String?,
    val mic: String?,
    val eapolLength: Int,
    val messagePair: Int,
    val handshakeCount: Int
) : Parcelable

@Parcelize
data class PacketInfo(
    val index: Int,
    val timestamp: String,
    val srcMac: String,
    val dstMac: String,
    val frameType: String,
    val ssid: String?,
    val detail: String,
    val rawData: String
) : Parcelable

@Parcelize
data class FileAnalysis(
    val fileType: FileType,
    val fileName: String,
    val fileSize: Long,
    val fileOverview: String,
    val handshakes: List<HandshakeInfo>,
    val packets: List<PacketInfo>,
    val rawHex: String
) : Parcelable

@Parcelize
data class AiReport(
    val fileOverview: String,
    val handshakeSummary: String,
    val securityAnalysis: String,
    val crackableInfo: String,
    val recommendations: String
) : Parcelable

class FileParser {

    fun detectFileType(data: ByteArray, name: String = ""): FileType {
        if (data.isEmpty()) return FileType.UNKNOWN
        val len = data.size

        if (len >= 4) {
            val magic = String(data, 0, minOf(4, len))
            if (magic == "HCPX") return FileType.HCCAPX
            if (magic == "WPA*") return if (data.size > 5 && data[5] == '0'.code.toByte()) FileType.HASHCAT_22000 else FileType.HASHCAT_22000
            if (magic.startsWith("HCCAP")) return FileType.HCCAP
        }

        if (len >= 2) {
            if (data[0] == 0xD4.toByte() && data[1] == 0xC3.toByte()) return FileType.PCAP
            if (data[0] == 0xC3.toByte() && data[1] == 0xD4.toByte()) return FileType.PCAP
            if (data[0] == 0x0A.toByte() && data[1] == 0x0D.toByte() && len >= 4 &&
                data[2] == 0x0D.toByte() && data[3] == 0x0A.toByte()) return FileType.PCAPNG
        }

        val text = String(data, 0, minOf(data.size, 20), Charsets.US_ASCII)
        if (text.startsWith("WPA*01*") || text.startsWith("WPA*02*")) return FileType.HC22000

        if (data.size == 393 && len > 4 && String(data, 0, 4) != "HCPX") return FileType.HCCAPX
        if (len == 393) return FileType.HCCAPX

        if (name.contains(".cap", ignoreCase = true) && len < 1000) return FileType.CAP

        return FileType.UNKNOWN
    }

    private var fileName = ""

    fun parseFile(data: ByteArray, name: String): FileAnalysis {
        val fileType = detectFileType(data, name)
        val hex = bytesToHex(data, 1024)

        val handshakes: List<HandshakeInfo>
        val packets: List<PacketInfo>

        when (fileType) {
            FileType.PCAP, FileType.CAP -> {
                val result = parsePcap(data)
                handshakes = result.second
                packets = result.first
            }
            FileType.HCCAPX -> {
                handshakes = parseHccapx(data)
                packets = emptyList()
            }
            FileType.HASHCAT_22000, FileType.HC22000 -> {
                handshakes = parseHc22000(data)
                packets = emptyList()
            }
            FileType.PMKID -> {
                handshakes = parsePmkid(data)
                packets = emptyList()
            }
            else -> {
                handshakes = emptyList()
                packets = emptyList()
            }
        }

        val overview = buildString {
            append("文件名: $name\n")
            append("大小: ${data.size} 字节\n")
            append("类型: ${fileType.name}\n")
            append("握手包数量: ${handshakes.size}\n")
            if (packets.isNotEmpty()) append("数据包数量: ${packets.size}")
        }

        return FileAnalysis(fileType, name, data.size.toLong(), overview, handshakes, packets, hex)
    }

    private fun parsePcap(data: ByteArray): Pair<List<PacketInfo>, List<HandshakeInfo>> {
        if (data.size < 24) return Pair(emptyList(), emptyList())

        val packets = mutableListOf<PacketInfo>()
        val handshakes = mutableListOf<HandshakeInfo>()

        val magic = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8) or
                ((data[2].toInt() and 0xFF) shl 16) or ((data[3].toInt() and 0xFF) shl 24)

        val isLittleEndian = magic == 0xA1B2C3D4.toInt()
        val order = if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN

        val sigfigs = readInt32(data, 4, order)
        val snaplen = readInt32(data, 8, order)
        val network = readInt32(data, 12, order)

        var offset = 24
        var index = 0
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())

        val eapolFrames = mutableListOf<ByteArray>()

        while (offset + 16 <= data.size) {
            val tsSec = readInt32(data, offset, order)
            val tsUsec = readInt32(data, offset + 4, order)
            val inclLen = readInt32(data, offset + 8, order)
            val origLen = readInt32(data, offset + 12, order)

            if (inclLen < 0 || inclLen > 100000 || offset + 16 + inclLen > data.size) break

            val pktData = data.copyOfRange(offset + 16, offset + 16 + inclLen)
            val ts = sdf.format(Date(tsSec.toLong() * 1000 + tsUsec / 1000))

            val frameType = detectFrameType(pktData)
            val srcMac = extractMac(pktData, if (network == 113) 2 else 10)
            val dstMac = extractMac(pktData, if (network == 113) 8 else 4)

            var ssid: String? = null
            var detail = ""
            var rawData = ""

            when (frameType) {
                "Beacon" -> {
                    ssid = extractSsidFromBeacon(pktData, network)
                    detail = "SSID: ${ssid ?: "隐藏"}, BSSID: $srcMac"
                }
                "Probe Request" -> {
                    ssid = extractSsidFromProbe(pktData, network)
                    detail = "请求SSID: ${ssid ?: "任意"}"
                }
                "Probe Response" -> {
                    ssid = extractSsidFromBeacon(pktData, network)
                    detail = "回复SSID: $ssid"
                }
                "EAPOL" -> {
                    detail = "EAPOL帧, 客户端: $srcMac, AP: $dstMac"
                    eapolFrames.add(pktData)
                }
                else -> {
                    detail = "类型: $frameType"
                }
            }

            rawData = bytesToHex(pktData, 128)

            packets.add(PacketInfo(index, ts, srcMac, dstMac, frameType, ssid, detail, rawData))
            offset += 16 + inclLen
            index++
        }

        val ssidMap = mutableMapOf<String, String>()
        packets.filter { it.frameType == "Beacon" && it.ssid != null }.forEach {
            ssidMap[it.srcMac] = it.ssid!!
        }

        val eapolGroups = groupEapolByPair(packets)

        for ((pairKey, frames) in eapolGroups) {
            if (frames.size >= 3) {
                val apMac = frames.first().dstMac
                val clientMac = frames.first().srcMac
                val ssid = ssidMap[apMac] ?: ssidMap[clientMac] ?: "未知"

                handshakes.add(
                    HandshakeInfo(
                        ssid = ssid,
                        apMac = apMac,
                        clientMac = clientMac,
                        timestamp = frames.first().timestamp,
                        encryptionType = "WPA2",
                        keyVersion = 2,
                        pmkid = null,
                        nonceAp = null,
                        nonceClient = null,
                        mic = null,
                        eapolLength = 0,
                        messagePair = 2,
                        handshakeCount = frames.size
                    )
                )
            }
        }

        return Pair(packets, handshakes)
    }

    private fun groupEapolByPair(packets: List<PacketInfo>): Map<String, List<PacketInfo>> {
        val eapolPackets = packets.filter { it.frameType == "EAPOL" }
        val groups = mutableMapOf<String, MutableList<PacketInfo>>()
        for (pkt in eapolPackets) {
            val key = "${pkt.srcMac}_${pkt.dstMac}"
            groups.getOrPut(key) { mutableListOf() }.add(pkt)
        }
        return groups
    }

    private fun parseHccapx(data: ByteArray): List<HandshakeInfo> {
        if (data.size < 393) return emptyList()

        val magic = String(data, 0, 4)
        if (magic != "HCPX") return emptyList()

        val version = (data[4].toInt() and 0xFF) or ((data[5].toInt() and 0xFF) shl 8)
        val messagePair = data[8].toInt() and 0xFF
        val essidLen = data[9].toInt() and 0xFF
        val essid = String(data, 10, minOf(essidLen, 32)).trim('\u0000')

        val keyver = data[383].toInt() and 0xFF

        val pmkid = bytesToHexClean(data, 10, 26)
        val macAp = formatMac(data, 44)
        val macClient = formatMac(data, 50)
        val mic = bytesToHexClean(data, 56, 72)
        val nonceAp = bytesToHexClean(data, 72, 104)
        val nonceClient = bytesToHexClean(data, 104, 136)
        val eapolLen = readInt16LE(data, 381)

        val encryption = when (keyver) {
            1 -> "WPA"
            2 -> "WPA2"
            3 -> "WPA2 Key Version 3"
            else -> "Unknown"
        }

        return listOf(
            HandshakeInfo(
                ssid = essid,
                apMac = macAp,
                clientMac = macClient,
                timestamp = "N/A",
                encryptionType = encryption,
                keyVersion = keyver,
                pmkid = pmkid,
                nonceAp = nonceAp,
                nonceClient = nonceClient,
                mic = mic,
                eapolLength = eapolLen,
                messagePair = messagePair,
                handshakeCount = 1
            )
        )
    }

    private fun parseHc22000(data: ByteArray): List<HandshakeInfo> {
        val text = String(data, Charsets.UTF_8).trim()
        val lines = text.lines().filter { it.isNotBlank() }

        return lines.mapNotNull { line ->
            if (!line.startsWith("WPA*")) return@mapNotNull null
            val parts = line.split("*")
            if (parts.size < 5) return@mapNotNull null

            val type = parts[1].toIntOrNull() ?: 0
            val pmkidOrMic = parts[2]
            val macAp = insertColons(parts[3])
            val macClient = insertColons(parts[4])
            val essid = if (parts.size > 5) hexToString(parts[5]) else "未知"
            val pmkid = if (type == 1) pmkidOrMic else null
            val mic = if (type == 2) pmkidOrMic else null
            val messagePair = if (type == 2 && parts.size > 6) parts[6].toIntOrNull() ?: 0 else 0

            HandshakeInfo(
                ssid = essid,
                apMac = macAp,
                clientMac = macClient,
                timestamp = "N/A",
                encryptionType = if (type == 1) "PMKID" else "WPA2 EAPOL",
                keyVersion = 2,
                pmkid = pmkid,
                nonceAp = null,
                nonceClient = null,
                mic = mic,
                eapolLength = 0,
                messagePair = messagePair,
                handshakeCount = 1
            )
        }
    }

    private fun parsePmkid(data: ByteArray): List<HandshakeInfo> {
        val text = String(data, Charsets.UTF_8).trim()
        return parseHc22000(text.toByteArray())
    }

    private fun detectFrameType(data: ByteArray): String {
        if (data.size < 2) return "Unknown"
        val fc = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
        val type = (fc shr 2) and 0x3
        val subtype = (fc shr 4) and 0xF

        return when (type) {
            0 -> when (subtype) {
                4 -> "Probe Request"
                5 -> "Probe Response"
                8 -> "Beacon"
                else -> "Mgmt/$subtype"
            }
            1 -> "Control/$subtype"
            2 -> when (subtype) {
                0 -> {
                    if (data.size >= 36) {
                        val ethType = ((data[32].toInt() and 0xFF) shl 8) or (data[33].toInt() and 0xFF)
                        if (ethType == 0x888E) "EAPOL" else "Data"
                    } else "Data"
                }
                else -> "Data/$subtype"
            }
            else -> "Unknown"
        }
    }

    private fun extractSsidFromBeacon(data: ByteArray, network: Int): String? {
        try {
            val offset = if (network == 113) 24 else 36
            var pos = offset + 12
            while (pos + 2 <= data.size) {
                val tagId = data[pos].toInt() and 0xFF
                val tagLen = data[pos + 1].toInt() and 0xFF
                if (tagLen == 0) { pos += 2; continue }
                if (pos + 2 + tagLen > data.size) break
                if (tagId == 0) {
                    return String(data, pos + 2, tagLen, Charsets.UTF_8).trim('\u0000')
                }
                pos += 2 + tagLen
            }
        } catch (_: Exception) {}
        return null
    }

    private fun extractSsidFromProbe(data: ByteArray, network: Int): String? {
        try {
            val offset = if (network == 113) 24 else 24
            var pos = offset + 4
            while (pos + 2 <= data.size) {
                val tagId = data[pos].toInt() and 0xFF
                val tagLen = data[pos + 1].toInt() and 0xFF
                if (pos + 2 + tagLen > data.size) break
                if (tagId == 0) {
                    if (tagLen == 0) return null
                    return String(data, pos + 2, tagLen, Charsets.UTF_8)
                }
                pos += 2 + tagLen
            }
        } catch (_: Exception) {}
        return null
    }

    private fun extractMac(data: ByteArray, offset: Int): String {
        if (offset + 6 > data.size) return "??:??:??:??:??:??"
        return formatMac(data, offset)
    }

    private fun formatMac(data: ByteArray, offset: Int): String {
        if (offset + 6 > data.size) return "??:??:??:??:??:??"
        return (0 until 5).joinToString(":") { String.format("%02X", data[offset + it].toInt() and 0xFF) } +
                String.format(":%02X", data[offset + 5].toInt() and 0xFF)
    }

    private fun insertColons(hex: String): String {
        val clean = hex.replace(":", "")
        if (clean.length != 12) return hex
        return (0 until 10 step 2).joinToString(":") { clean.substring(it, it + 2) } + clean.substring(10)
    }

    private fun hexToString(hex: String): String {
        return try {
            val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            String(bytes, Charsets.UTF_8)
        } catch (_: Exception) { hex }
    }

    private fun readInt32(data: ByteArray, offset: Int, order: ByteOrder): Int {
        if (offset + 4 > data.size) return 0
        val buf = ByteBuffer.wrap(data, offset, 4).order(order)
        return buf.int
    }

    private fun readInt16LE(data: ByteArray, offset: Int): Int {
        if (offset + 2 > data.size) return 0
        return (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)
    }

    fun bytesToHex(bytes: ByteArray, maxLen: Int = bytes.size): String {
        val sb = StringBuilder()
        val limit = minOf(bytes.size, maxLen)
        for (i in 0 until limit step 16) {
            sb.append(String.format("%04X: ", i))
            for (j in i until minOf(i + 16, limit)) sb.append(String.format("%02X ", bytes[j].toInt() and 0xFF))
            if (i + 16 > limit) for (j in 0 until (16 - (limit - i))) sb.append("   ")
            sb.append(" | ")
            for (j in i until minOf(i + 16, limit)) {
                val b = bytes[j].toInt() and 0xFF
                sb.append(if (b in 32..126) b.toChar() else '.')
            }
            sb.append("\n")
        }
        if (bytes.size > maxLen) sb.append("... (已截断，共 ${bytes.size} 字节)")
        return sb.toString()
    }

    private fun bytesToHexClean(data: ByteArray, from: Int, to: Int): String {
        val sb = StringBuilder()
        for (i in from until minOf(to, data.size)) sb.append(String.format("%02X", data[i].toInt() and 0xFF))
        return sb.toString()
    }
}
