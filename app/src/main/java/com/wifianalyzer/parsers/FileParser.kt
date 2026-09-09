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

    companion object {
        const val HCCAPX_SIZE = 393      // packed struct, 含 HCPX magic
        const val HCCAP_SIZE = 392       // 旧格式 struct (hcxhashtool 读写同尺寸)
        // PMKID 16800 行：pmkid(32)*AP(12)*STA(12)*ESSID_HEX
        val PMKID_RE = Regex("^[0-9a-fA-F]{32}[*:][0-9a-fA-F]{12}[*:][0-9a-fA-F]{12}[*:]")
    }

    // ================= 类型识别 =================

    fun detectFileType(data: ByteArray, name: String = ""): FileType {
        if (data.isEmpty()) return FileType.UNKNOWN
        val n = data.size
        val lower = name.lowercase()
        val ext = when {
            lower.endsWith(".wkp") -> return FileType.WKP
            lower.endsWith(".hccapx") -> return FileType.HCCAPX
            lower.endsWith(".hccap") -> return FileType.HCCAP
            lower.endsWith(".pmkid") || lower.endsWith(".16800") -> return FileType.PMKID
            lower.endsWith(".22000") || lower.endsWith("hc22000") -> return FileType.HC22000
            lower.endsWith(".22001") || lower.endsWith("hc22001") -> FileType.HC22001
            lower.endsWith(".pcapng") -> FileType.PCAPNG
            lower.endsWith(".cap") -> FileType.CAP
            lower.endsWith(".pcap") -> FileType.PCAP
            else -> null
        }

        // ---- magic 优先 ----
        if (n >= 4) {
            if (String(data, 0, 4, Charsets.US_ASCII) == "HCPX") return FileType.HCCAPX
            if (String(data, 0, 4, Charsets.US_ASCII) == "HCCAP") return FileType.HCCAP
            val pcapMagics = setOf(
                0xA1B2C3D4.toInt(), 0xA1B23C4D.toInt(),
                0xD4C3B2A1.toInt(), 0x4D3CB2A1.toInt()
            )
            if (n >= 4 && pcapMagics.contains(readInt32LE(data, 0))) {
                return if (lower.endsWith(".pcapng")) FileType.PCAPNG
                       else if (ext == FileType.CAP) FileType.CAP
                       else if (ext == FileType.PCAP) FileType.PCAP
                       else FileType.CAP
            }
            if (data[0].toInt() and 0xFF == 0x0A && n >= 4 &&
                data[1].toInt() and 0xFF == 0x0D &&
                data[2].toInt() and 0xFF == 0x0D &&
                data[3].toInt() and 0xFF == 0x0A) return FileType.PCAPNG
        }

        // ---- 文本哈希格式 ----
        if (isText(data)) {
            val head = firstNonBlankLine(data)
            if (head.startsWith("WPA*01*") || head.startsWith("WPA*02*")) {
                return if (lower.endsWith(".22001") || lower.endsWith("hc22001")) FileType.HC22001
                       else FileType.HC22000
            }
            if (PMKID_RE.matches(head) ||
                (head.length >= 34 && head.substring(0, 32).all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
                    && (head[32] == '*' || head[32] == ':'))) return FileType.PMKID
            if (ext == FileType.HCCAP) return FileType.HCCAP
        }

        // ---- 固定记录长格式 ----
        if (n >= HCCAP_SIZE && n % HCCAP_SIZE == 0) return FileType.HCCAP
        if (n >= HCCAPX_SIZE && n % HCCAPX_SIZE == 0) return FileType.HCCAPX

        return ext ?: FileType.UNKNOWN
    }

    // ================= 总入口 =================

    fun parseFile(data: ByteArray, name: String): FileAnalysis {
        val fileType = detectFileType(data, name)
        val hex = bytesToHex(data, 2048)
        var handshakes: List<HandshakeInfo> = emptyList()
        var packets: List<PacketInfo> = emptyList()

        when (fileType) {
            FileType.PCAP, FileType.CAP, FileType.PCAPNG -> {
                val r = parsePcap(data)
                packets = r.first
                handshakes = r.second
            }
            FileType.HCCAPX -> handshakes = parseHccapx(data)
            FileType.HCCAP -> handshakes = parseHccap(data)
            FileType.HASHCAT_22000, FileType.HC22000, FileType.HC22001 -> handshakes = parseHc22000(data)
            FileType.PMKID -> handshakes = parsePmkid16800(data)
            else -> {}
        }

        val overview = buildString {
            append("文件名: $name\n")
            append("大小: ${data.size} 字节\n")
            append("类型: ${fileType.name}\n")
            append("握手记录: ${handshakes.size}\n")
            if (packets.isNotEmpty()) append("数据帧: ${packets.size}")
        }
        return FileAnalysis(fileType, name, data.size.toLong(), overview, handshakes, packets, hex)
    }

    // ================= 抓包族 =================

    private fun parsePcap(data: ByteArray): Pair<List<PacketInfo>, List<HandshakeInfo>> {
        if (data.size < 24) return Pair(emptyList(), emptyList())
        val packets = mutableListOf<PacketInfo>()
        val handshakes = mutableListOf<HandshakeInfo>()

        val magic = readInt32LE(data, 0)
        val order = if (magic == 0xA1B2C3D4.toInt() || magic == 0xA1B23C4D.toInt())
            ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        val network = readInt32(data, 20, order)   // pcap 全局头: magic4 ver4 thiszone4 sigfigs4 snaplen4 network4

        fun frameBase(pkt: ByteArray): Int {
            if (network != 113 || pkt.size < 10) return 0
            val hlen = readInt32(pkt, 8, order)    // radiotap header 长度(8 字节对齐)
            return if (hlen in 8..64 && hlen % 8 == 0) hlen else 0
        }

        var offset = 24
        var index = 0
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault())

        while (offset + 16 <= data.size) {
            val tsSec = readInt32(data, offset, order)
            val tsUsec = readInt32(data, offset + 4, order)
            val inclLen = readInt32(data, offset + 8, order)
            if (inclLen < 0 || inclLen > 100000 || offset + 16 + inclLen > data.size) break

            val pkt = data.copyOfRange(offset + 16, offset + 16 + inclLen)
            val ts = sdf.format(Date(tsSec.toLong() * 1000 + tsUsec / 1000))
            val ft = detectFrameType(pkt)
            val base = frameBase(pkt)
            val srcMac = extractMac(pkt, base + 10)
            val dstMac = extractMac(pkt, base + 4)

            var ssid: String? = null
            var detail = "类型: $ft"
            when (ft) {
                "Beacon" -> {
                    ssid = extractSsid(pkt, base)
                    detail = "SSID: ${ssid ?: "隐藏"}, BSSID: $srcMac"
                }
                "Probe Request" -> {
                    ssid = extractSsid(pkt, base)
                    detail = "请求 SSID: ${ssid ?: "任意"}"
                }
                "Probe Response" -> {
                    ssid = extractSsid(pkt, base)
                    detail = "SSID: $ssid"
                }
                "EAPOL" -> detail = "EAPOL 帧, STA: $srcMac, AP: $dstMac"
            }

            packets.add(PacketInfo(index, ts, srcMac, dstMac, ft, ssid, detail, bytesToHex(pkt, 128)))
            offset += 16 + inclLen
            index++
        }

        val ssidMap = mutableMapOf<String, String>()
        packets.filter { it.frameType == "Beacon" && it.ssid != null }.forEach { ssidMap[it.srcMac] = it.ssid!! }
        for ((key, frames) in groupEapolByPair(packets)) {
            if (frames.size < 2) continue
            val apMac = frames.first().dstMac
            val clientMac = frames.first().srcMac
            val ssid = ssidMap[apMac] ?: ssidMap[clientMac] ?: "未知"
            handshakes.add(HandshakeInfo(
                ssid = ssid, apMac = apMac, clientMac = clientMac,
                timestamp = frames.first().timestamp,
                encryptionType = "WPA2 4 次握手", keyVersion = 2,
                pmkid = null, nonceAp = null, nonceClient = null, mic = null,
                eapolLength = 0, messagePair = frames.size, handshakeCount = frames.size
            ))
        }
        return Pair(packets, handshakes)
    }

    private fun groupEapolByPair(packets: List<PacketInfo>): Map<String, List<PacketInfo>> {
        val groups = mutableMapOf<String, MutableList<PacketInfo>>()
        for (p in packets) if (p.frameType == "EAPOL") groups.getOrPut("${p.srcMac}_${p.dstMac}") { mutableListOf() }.add(p)
        return groups
    }

    // ================= HCCAPX (393 bytes/record, packed) =================
    // 0:sig "HCPX" 4:version 8:msg_pair 9:essid_len 10:essid[32] 42:keyver
    // 43:keymic[16] 59:ap[6] 65:anonce[32] 97:client[6] 103:snonce[32]
    // 135:eapol_len(u16 LE) 137:eapol[256]

    private fun parseHccapx(data: ByteArray): List<HandshakeInfo> {
        val out = mutableListOf<HandshakeInfo>()
        var off = 0
        while (off + HCCAPX_SIZE <= data.size) {
            if (String(data, off, 4, Charsets.US_ASCII) != "HCPX") break
            val msgPair = data[off + 8].toInt() and 0xFF
            val essidLen = data[off + 9].toInt() and 0xFF
            val essid = String(data, off + 10, minOf(essidLen, 32), Charsets.UTF_8).trim('\u0000')
            val keyver = data[off + 42].toInt() and 0xFF
            val ap = formatMac(data, off + 59)
            val anonce = hexClean(data, off + 65, off + 97)
            val client = formatMac(data, off + 97)
            val snonce = hexClean(data, off + 103, off + 135)
            val eapolLen = readInt16LE(data, off + 135)
            val mic = hexClean(data, off + 43, off + 59)
            out.add(HandshakeInfo(
                essid.ifBlank { "未知" }, ap, client, "N/A",
                when (keyver) { 1 -> "WPA" 2 -> "WPA2" 3 -> "WPA2 (Kv3)" else -> "未知" },
                keyver, pmkid = null, nonceAp = anonce, nonceClient = snonce, mic = mic,
                eapolLength = eapolLen, messagePair = msgPair, handshakeCount = 1
            ))
            off += HCCAPX_SIZE
        }
        return out
    }

    // ================= HCCAP (392 bytes/record, ancient) =================
    // 0:essid[36] 36:ap[6] 42:client[6] 48:snonce[32] 80:anonce[32]
    // 112:eapol[256] 368:eapol_size 372:keyver 376:keymic[16]

    private fun parseHccap(data: ByteArray): List<HandshakeInfo> {
        val out = mutableListOf<HandshakeInfo>()
        var off = 0
        while (off + HCCAP_SIZE <= data.size) {
            val essidRaw = data.copyOfRange(off, off + 36)
            val cut = essidRaw.indexOf(0).let { if (it < 0) 36 else it }
            val essid = String(essidRaw, 0, cut, Charsets.UTF_8).trim('\u0000')
            val ap = formatMac(data, off + 36)
            val client = formatMac(data, off + 42)
            val keyver = readInt32LE(data, off + 372)
            val eapolLen = readInt32LE(data, off + 368)
            val mic = hexClean(data, off + 376, off + 392)
            out.add(HandshakeInfo(
                essid.ifBlank { "未知" }, ap, client, "N/A",
                when (keyver) { 1 -> "WPA" 2 -> "WPA2" else -> "未知" },
                keyver, pmkid = null, nonceAp = hexClean(data, off + 80, off + 112),
                nonceClient = hexClean(data, off + 48, off + 80), mic = mic,
                eapolLength = eapolLen, messagePair = 0, handshakeCount = 1
            ))
            off += HCCAP_SIZE
        }
        return out
    }

    // ================= hashcat 22000 (WPA*0x 文本行) =================

    private fun parseHc22000(data: ByteArray): List<HandshakeInfo> {
        val out = mutableListOf<HandshakeInfo>()
        for (line in String(data, Charsets.UTF_8).lines()) {
            if (!line.startsWith("WPA*")) continue
            val p = line.split("*")
            if (p.size < 6) continue
            val type = p[1].toIntOrNull() ?: 0
            val essidHex = p[5]
            val essid = if (essidHex.length % 2 == 0 && isHex(essidHex)) hexToText(essidHex) else essidHex
            val messagePair = if (p.size > 6 && p[6].length == 1) p[6].toIntOrNull() ?: 0 else 0
            out.add(HandshakeInfo(
                essid.ifBlank { "未知" }, insertColons(p[3]), insertColons(p[4]), "N/A",
                if (type == 1) "WPA2 PMKID" else "WPA2 EAPOL", 2,
                pmkid = if (type == 1) p[2] else null,
                nonceAp = null, nonceClient = null,
                mic = if (type == 2) p[2] else null,
                eapolLength = 0, messagePair = messagePair, handshakeCount = 1
            ))
        }
        return out
    }

    // ================= PMKID 16800 =================

    private fun parsePmkid16800(data: ByteArray): List<HandshakeInfo> {
        val out = mutableListOf<HandshakeInfo>()
        for (raw in String(data, Charsets.UTF_8).lines()) {
            val line = raw.trim()
            if (line.isEmpty() || !PMKID_RE.matches(line)) continue
            val p = line.split(Regex("[*:]"))
            if (p.size < 4) continue
            val essidHex = p[3].trimEnd()
            val essid = if (essidHex.isNotEmpty() && essidHex.length % 2 == 0 && isHex(essidHex))
                hexToText(essidHex) else essidHex
            out.add(HandshakeInfo(
                essid.ifBlank { "未知" }, insertColons(p[1]), insertColons(p[2]), "N/A",
                "WPA2 PMKID", 2, pmkid = p[0], nonceAp = null, nonceClient = null,
                mic = null, eapolLength = 0, messagePair = 0, handshakeCount = 1
            ))
        }
        return out
    }

    // ================= 帧级辅助 =================

    private fun detectFrameType(d: ByteArray): String {
        if (d.size < 2) return "Unknown"
        val fc = (d[0].toInt() and 0xFF) or ((d[1].toInt() and 0xFF) shl 8)
        return when ((fc shr 2) and 3) {
            0 -> when ((fc shr 4) and 0xF) {
                4 -> "Probe Request"; 5 -> "Probe Response"; 8 -> "Beacon"; else -> "Mgmt"
            }
            1 -> "Control"
            2 -> if (d.size >= 34) {
                val t = ((d[32].toInt() and 0xFF) shl 8) or (d[33].toInt() and 0xFF)
                if (t == 0x888E) "EAPOL" else "Data"
            } else "Data"
            else -> "Unknown"
        }
    }

    /** 元素区起点在不同抓包工具里是 26/34/36/40/42/44，逐个尝试找 SSID IE */
    private fun extractSsid(d: ByteArray, base: Int): String? {
        for (start in intArrayOf(26, 34, 36, 40, 42, 44, 48)) {
            val p = base + start
            if (p + 2 > d.size) continue
            val tag = d[p].toInt() and 0xFF
            val len = d[p + 1].toInt() and 0xFF
            if (tag != 0x00 || len == 0 || len > 32) continue
            if (p + 2 + len > d.size) continue
            val t = String(d, p + 2, len, Charsets.UTF_8).trim('\u0000')
            if (t.isNotEmpty() && t.all { it in '\u0020'..'\u007E' }) return t
        }
        return null
    }

    private fun extractMac(d: ByteArray, off: Int): String =
        if (off + 6 <= d.size) formatMac(d, off) else "??:??:??:??:??:??"

    private fun formatMac(d: ByteArray, off: Int): String {
        if (off + 6 > d.size) return "??:??:??:??:??:??"
        return (0 until 6).joinToString(":") { "%02X".format(d[off + it].toInt() and 0xFF) }
    }

    private fun insertColons(hex: String): String {
        val c = hex.replace(":", "")
        return if (c.length != 12) hex
        else (0 until 12 step 2).joinToString(":") { c.substring(it, it + 2) }
    }

    private fun hexToText(hex: String): String = try {
        String(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), Charsets.UTF_8)
    } catch (_: Exception) { hex }

    private fun isHex(s: String): Boolean =
        s.isNotEmpty() && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun readInt32(d: ByteArray, off: Int, order: ByteOrder): Int {
        if (off + 4 > d.size) return 0
        return ByteBuffer.wrap(d, off, 4).order(order).int
    }

    private fun readInt32LE(d: ByteArray, off: Int): Int =
        if (off + 4 > d.size) 0 else readInt32(d, off, ByteOrder.LITTLE_ENDIAN)

    private fun readInt16LE(d: ByteArray, off: Int): Int {
        if (off + 2 > d.size) return 0
        return (d[off].toInt() and 0xFF) or ((d[off + 1].toInt() and 0xFF) shl 8)
    }

    private fun hexClean(d: ByteArray, from: Int, to: Int): String =
        buildString { for (i in from until minOf(to, d.size)) append("%02X".format(d[i].toInt() and 0xFF)) }

    private fun isText(data: ByteArray): Boolean {
        val n = minOf(data.size, 512)
        if (n == 0) return false
        var bad = 0
        for (i in 0 until n) {
            val b = data[i].toInt() and 0xFF
            if (b != '\n'.code && b != '\r'.code && (b < 0x20 || b == 0x7F)) bad++
        }
        return bad * 100 / n < 20
    }

    private fun firstNonBlankLine(data: ByteArray): String {
        val n = minOf(data.size, 2048)
        for (line in String(data, 0, n, Charsets.US_ASCII).lines()) if (line.isNotBlank()) return line
        return ""
    }

    fun bytesToHex(bytes: ByteArray, maxLen: Int = bytes.size): String {
        val sb = StringBuilder()
        val limit = minOf(bytes.size, maxLen)
        for (i in 0 until limit step 16) {
            sb.append("%04X: ".format(i))
            for (j in i until minOf(i + 16, limit)) sb.append("%02X ".format(bytes[j].toInt() and 0xFF))
            if (i + 16 > limit) for (j in 0 until (16 - (limit - i))) sb.append("   ")
            sb.append(" | ")
            for (j in i until minOf(i + 16, limit)) {
                val b = bytes[j].toInt() and 0xFF
                sb.append(if (b in 32..126) b.toChar() else '.')
            }
            sb.append("\n")
        }
        if (bytes.size > maxLen) sb.append("... (截断，共 ${bytes.size} 字节)")
        return sb.toString()
    }
}
