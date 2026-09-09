package com.wifianalyzer.converters

import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * WKP = Elcomsoft Wireless Security Auditor 私有项目格式，无公开规范。
 * 锚点优先雕刻：
 *   1) 以 LLC/SNAP 的 `88 8E` 紧接 EAPOL `02 03` 为唯一锚（EAPOL 起点 = 锚+2），向前校验 LLC 前缀与
 *      802.11 头（fc/单播 SA+RA）确定帧起点，得到 EAPOL 握手帧；
 *   2) 在握手帧之间的空隙里扫管理帧，要求元素序列首元素就是 SSID IE。
 * 结果重组为 libpcap(DLT 105)，交给 hcxpcapngtool 走标准链路。
 *
 * 已知事实：
 *  - EAPOL length 是网络序(大端)且不含 version/type/len 这 4 字节
 *    (hcxhash2cap.c:865 `ntohs(eapa->len) + 4`)
 *  - LLC 有完整 14 字节形式与 hcxtools 的 8 字节简写
 *  - 帧头长有 22(无 seq/fc)、26、28(带 QoS ctrl) 三种
 *  - 管理帧元素起点可能是标准 40/34，也可能是 36/30
 */
object WkpCarver {

    // (头长, LLC 长)
    private val HDR_LLC = arrayOf(
        intArrayOf(26, 8), intArrayOf(22, 8), intArrayOf(28, 8),
        intArrayOf(26, 13), intArrayOf(22, 13), intArrayOf(28, 13)
    )
    private val MGMT_BASES = intArrayOf(40, 36, 34, 30)

    data class Frame(val type: String, val ssid: String?, val bssid: String?, val data: ByteArray,
                    val pos: Int)

    private class EapolHit(val start: Int, val end: Int)

    fun carve(data: ByteArray): List<Frame> {
        val hits = scanEapol(data)
        if (hits.isEmpty()) return emptyList()

        val frames = ArrayList<Frame>()
        val eapols = ArrayList<Frame>()
        val spans = ArrayList<IntArray>()
        for (h in hits) {
            val f = buildDataFrame(data, h.start, h.end)
            frames.add(f); eapols.add(f)
            spans.add(intArrayOf(h.start, h.end))
        }

        // 握手帧之间的空隙里找管理帧
        fun occupied(i: Int): Boolean = spans.any { sp -> i in sp[0] until sp[1] }
        var o = 0
        while (o < data.size) {
            if (occupied(o)) { o++; continue }
            val ml = mgmtSpan(data, o)
            if (ml != null && (o until o + ml).none { occupied(it) }) {
                frames.add(buildMgmtFrame(data, o, ml))
                o += ml
            } else o++
        }

        // 只保留 BSSID 与握手帧一致的管理帧
        val bssids = eapols.mapNotNull { it.bssid }.toHashSet()
        val kept = ArrayList<Frame>()
        for (f in frames) {
            if (f.type == "EAPOL") kept.add(f)
            else if (f.bssid != null && bssids.contains(f.bssid)) kept.add(f)
        }
        if (kept.isEmpty()) return eapols
        // 必须保持抓包原始顺序：hcxpcapngtool 按顺序把 M1 配给 M2
        kept.sortBy { it.pos }
        return kept
    }

    /** 写出 libpcap 抓包文件；false 表示未雕到可用帧 */
    fun writePcap(frames: List<Frame>, out: File): Boolean {
        if (frames.isEmpty()) return false
        FileOutputStream(out).use { fos ->
            val header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
            header.putInt(0xA1B2C3D4.toInt())
            header.putShort(2).putShort(4)
            header.putInt(0)
            header.putInt(0)
            header.putInt(65535)
            header.putInt(105)                   // LINKTYPE_IEEE802_11
            fos.write(header.array())
            for (f in frames) {
                val rec = ByteBuffer.allocate(16 + f.data.size).order(ByteOrder.LITTLE_ENDIAN)
                rec.putInt(0); rec.putInt(0)
                rec.putInt(f.data.size)
                rec.putInt(f.data.size)
                rec.put(f.data)
                fos.write(rec.array())
            }
        }
        return true
    }

    // ---------- EAPOL 数据帧 ----------

    private fun scanEapol(data: ByteArray): List<EapolHit> {
        val hits = ArrayList<EapolHit>()
        var a = 3
        while (a + 4 < data.size) {
            if ((data[a].toInt() and 0xFF) != 0x88 || (data[a + 1].toInt() and 0xFF) != 0x8E ||
                (data[a + 2].toInt() and 0xFF) != 0x02 || (data[a + 3].toInt() and 0xFF) != 0x03) {
                a++; continue
            }
            val e = a + 2                                   // 88 8E 之后紧接 EAPOL 头
            if (e + 4 > data.size) { a++; continue }
            val eapolLen = be16(data, e + 2)
            if (eapolLen < 24 || eapolLen > 508) { a++; continue }
            for (c in HDR_LLC) {
                val h = c[0]; val llc = c[1]
                val o = e - h - llc
                if (o < 0) continue
                if (!llcOk(data, o + h, llc)) continue
                if (!headerOk(data, o)) continue
                val end = o + h + llc + 4 + eapolLen
                if (end - o > 1024 || end > data.size) continue
                hits.add(EapolHit(o, end))
                break
            }
            a++
        }
        hits.sortBy { it.start }
        return hits
    }

    private fun buildDataFrame(data: ByteArray, o: Int, end: Int): Frame =
        Frame("EAPOL", null, validMac(data, o + 16) ?: validMac(data, o + 10),
            data.copyOfRange(o, end), o)

    /** LLC 前缀：8 字节简写 AA AA 03 00 00 00 88 8E；13 字节完整 DSAP×6+SSAP+ctrl+org×3+type */
    private fun llcOk(data: ByteArray, l: Int, llc: Int): Boolean {
        if (l < 0 || l + llc > data.size) return false
        if (llc == 8) {
            return b(data, l) == 0xAA && b(data, l + 1) == 0xAA && b(data, l + 2) == 0x03 &&
                b(data, l + 6) == 0x88 && b(data, l + 7) == 0x8E
        }
        for (i in 0 until 6) if (b(data, l + i) != 0xAA) return false
        return b(data, l + 6) == 0x03 && b(data, l + 7) == 0x00 &&
            b(data, l + 11) == 0x88 && b(data, l + 12) == 0x8E
    }

    /** 802.11 头校验：fc 高字节带控制位，SA/RA 均为单播 */
    private fun headerOk(data: ByteArray, o: Int): Boolean {
        if (o + 22 > data.size) return false
        return b(data, o) >= 0x80 && validMac(data, o + 10) != null && validMac(data, o + 16) != null
    }

    // ---------- 管理帧(Beacon / Probe Response) ----------

    private fun mgmtSpan(data: ByteArray, o: Int): Int? {
        val f0 = b(data, o)
        if (f0 != 0x80 && f0 != 0x88 && f0 != 0x50) return null
        var best = Int.MAX_VALUE
        var bestBase = -1
        for (base in MGMT_BASES) {
            if (o + base + 4 > data.size) continue
            if (!ssidFirst(data, o + base)) continue
            val end = walkElements(data, o + base) ?: continue
            val span = end - o
            if (span < base + 5 || span > 400) continue
            if (span < best) { best = span; bestBase = base }
        }
        return if (bestBase >= 0) best else null
    }

    /** 元素序列首元素必须是 SSID IE 且内容可打印 */
    private fun ssidFirst(data: ByteArray, s: Int): Boolean {
        if (s + 2 > data.size) return false
        val len = b(data, s + 1)
        if (b(data, s) != 0x00 || len == 0 || len > 32) return false
        if (s + 2 + len > data.size) return false
        for (i in s + 2 until s + 2 + len) {
            val c = data[i].toInt()
            if (c < 0x20 || c > 0x7E) return false
        }
        return true
    }

    private fun buildMgmtFrame(data: ByteArray, o: Int, total: Int): Frame {
        var type = "Mgmt"; var ssid: String? = null; var end = o + total
        for (base in MGMT_BASES) {
            if (!ssidFirst(data, o + base)) continue
            val e = walkElements(data, o + base)
            if (e != null && e - o == total) {
                type = if (base == 40) "Beacon" else "Mgmt"
                ssid = ssidAt(data, o + base)
                end = e
                break
            }
        }
        return Frame(type, ssid, validMac(data, o + 10) ?: validMac(data, o + 6),
            data.copyOfRange(o, end), o)
    }

    /** 元素序列：tag(1)+len(1)+value。返回最后一个元素之后的 offset */
    private fun walkElements(data: ByteArray, start: Int): Int? {
        var pos = start
        var count = 0
        while (pos + 2 <= data.size && count < 60) {
            val tag = b(data, pos)
            val len = b(data, pos + 1)
            if (len == 0 || tag > 224) break
            if (pos + 2 + len > data.size) break
            pos += 2 + len
            count++
        }
        return if (count >= 1) pos else null
    }

    private fun ssidAt(data: ByteArray, s: Int): String? {
        if (s + 2 > data.size) return null
        val len = b(data, s + 1)
        if (b(data, s) != 0x00 || len == 0 || len > 32 || s + 2 + len > data.size) return null
        return String(data, s + 2, len, Charsets.UTF_8).trim('\u0000')
    }

    // ---------- 工具 ----------

    private fun b(data: ByteArray, i: Int): Int = data[i].toInt() and 0xFF

    private fun be16(d: ByteArray, off: Int): Int = (b(d, off) shl 8) or b(d, off + 1)

    /** 单播 MAC：非全 0、非全 ff */
    private fun validMac(data: ByteArray, off: Int): String? {
        if (off < 0 || off + 6 > data.size) return null
        var v = 0L
        for (i in 0 until 6) {
            val x = b(data, off + i)
            if (x == 0xFF) return null
            v = (v shl 8) or x.toLong()
        }
        if (v == 0L) return null
        return (0 until 6).joinToString(":") { "%02X".format(b(data, off + it)) }
    }
}
