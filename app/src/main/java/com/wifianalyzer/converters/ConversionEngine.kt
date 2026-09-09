package com.wifianalyzer.converters

import android.content.Context
import com.wifianalyzer.parsers.FileType
import com.wifianalyzer.tools.ToolExecutor
import java.io.File

/**
 * 握手包格式互转。命令组合均经 hcxtools 6.3.4 本机实测。
 * 输出路径统一用占位符 OUT 表示，避免长参数拼接错误。
 */
object ConversionEngine {

    const val OUT = "<OUT>"
    data class Target(val label: String, val ext: String, val kind: String)

    const val K_CAPTURE = "CAPTURE"   // pcap / cap / pcapng
    const val K_22000 = "HC22000"     // hashcat 22000, WPA*0x 文本行
    const val K_HCCAPX = "HCCAPX"     // 393 bytes/record, HCPX magic
    const val K_HCCAP = "HCCAP"       // 392 bytes/record, ancient 2500
    const val K_16800 = "PMKID16800"  // pmkid*AP*STA*ESSID_HEX

    // ---------- 类型归一化 ----------

    fun kindOf(type: FileType): String = when (type) {
        FileType.PCAP, FileType.CAP, FileType.PCAPNG -> K_CAPTURE
        FileType.HC22000, FileType.HC22001, FileType.HASHCAT_22000 -> K_22000
        FileType.HCCAPX -> K_HCCAPX
        FileType.HCCAP -> K_HCCAP
        FileType.PMKID -> K_16800
        else -> type.name
    }

    private fun extOf(type: FileType): String = when (type) {
        FileType.PCAP -> "pcap"
        FileType.CAP -> "cap"
        FileType.PCAPNG -> "pcapng"
        FileType.HC22001 -> "hc22001"
        FileType.HASHCAT_22000, FileType.HC22000 -> "22000"
        FileType.HCCAPX -> "hccapx"
        FileType.HCCAP -> "hccap"
        FileType.PMKID -> "16800"
        FileType.WKP -> "wkp"
        else -> "bin"
    }

    fun sourceExt(type: FileType): String = extOf(type)

    // ---------- 目标列表 ----------

    fun targetsFor(type: FileType): List<Target> = when (kindOf(type)) {
        K_CAPTURE -> listOf(
            Target("HC22000 (hashcat 22000)", "22000", K_22000),
            Target("HCCAPX (2500, 393B)", "hccapx", K_HCCAPX),
            Target("HCCAP (2500 旧版, 392B)", "hccap", K_HCCAP),
            Target("CAP", "cap", K_CAPTURE)
        )
        K_HCCAPX -> listOf(
            Target("HC22000", "22000", K_22000),
            Target("HCCAP", "hccap", K_HCCAP),
            Target("CAP", "cap", K_CAPTURE)
        )
        K_HCCAP -> listOf(
            Target("HC22000", "22000", K_22000),
            Target("HCCAPX", "hccapx", K_HCCAPX),
            Target("CAP", "cap", K_CAPTURE)
        )
        K_22000 -> listOf(
            Target("HCCAPX (需含 EAPOL)", "hccapx", K_HCCAPX),
            Target("HCCAP (需含 EAPOL)", "hccap", K_HCCAP),
            Target("CAP", "cap", K_CAPTURE),
            Target("PMKID 16800", "16800", K_16800)
        )
        K_16800 -> listOf(
            Target("CAP (仅 PMKID 帧)", "cap", K_CAPTURE),
            Target("HC22000", "22000", K_22000)
        )
        else -> emptyList()
    }

    // ---------- 转换主入口 ----------

    fun convert(ctx: Context, src: File, srcType: FileType, target: Target): String {
        val ex = ToolExecutor(ctx)
        val srcKind = kindOf(srcType)
        val tmp = File(ctx.cacheDir, "cv_${System.currentTimeMillis()}")
        tmp.mkdirs()

        return try {
            when {
                srcKind == "WKP" -> {
                    val frames = WkpCarver.carve(src.readBytes())
                    val pcap = File(tmp, "carved.pcap")
                    if (!WkpCarver.writePcap(frames, pcap))
                        return "✗ 未从 WKP 雕出可用 802.11 帧\n(WKP 是 Elcomsoft 私有格式，无公开规范；建议先在 EWSA 里导出为 cap/pcap)"
                    convertCapture(ex, pcap, tmp, target)
                }
                srcKind == K_CAPTURE -> convertCapture(ex, src, tmp, target)
                srcKind == K_HCCAPX -> when (target.kind) {
                    K_22000 -> run(ex, "hcxhashtool", tmp, "22000",
                            listOf("--hccapx-in=${src.absolutePath}", "-o", OUT))
                    K_HCCAP -> run(ex, "hcxhashtool", tmp, "hccap",
                            listOf("--hccapx-in=${src.absolutePath}", "--hccap-out=$OUT"))
                    K_CAPTURE -> run(ex, "hcxhash2cap", tmp, "cap",
                            listOf("--hccapx=${src.absolutePath}", "-c", OUT))
                    else -> fail(target)
                }
                srcKind == K_HCCAP -> when (target.kind) {
                    K_22000 -> run(ex, "hcxhashtool", tmp, "22000",
                            listOf("--hccap-in=${src.absolutePath}", "-o", OUT))
                    K_HCCAPX -> run(ex, "hcxhashtool", tmp, "hccapx",
                            listOf("--hccap-in=${src.absolutePath}", "--hccapx-out=$OUT"))
                    K_CAPTURE -> run(ex, "hcxhash2cap", tmp, "cap",
                            listOf("--hccap=${src.absolutePath}", "-c", OUT))
                    else -> fail(target)
                }
                srcKind == K_22000 -> when (target.kind) {
                    K_HCCAPX, K_HCCAP -> hccapxHccapFrom22000(ex, src, tmp, target)
                    K_CAPTURE -> run(ex, "hcxhash2cap", tmp, "cap",
                            listOf("--pmkid-eapol=${src.absolutePath}", "-c", OUT))
                    K_16800 -> writeHc22000To16800(src, File(tmp, "out.16800"))
                    else -> fail(target)
                }
                srcKind == K_16800 -> when (target.kind) {
                    K_CAPTURE -> run(ex, "hcxhash2cap", tmp, "cap",
                            listOf("--pmkid=${src.absolutePath}", "-c", OUT))
                    K_22000 -> {
                        val cap = File(tmp, "pmkid.cap")
                        val r = run(ex, "hcxhash2cap", tmp, "cap",
                                listOf("--pmkid=${src.absolutePath}", "-c", cap.absolutePath), cap)
                        if (cap.exists()) run(ex, "hcxpcapngtool", tmp, "22000",
                                listOf("-o", OUT, cap.absolutePath)) else r
                    }
                    else -> fail(target)
                }
                else -> fail(target)
            }
        } catch (e: Exception) {
            "✗ 转换异常: ${e.message}"
        } finally {
            File(tmp, "pmkid.cap").delete()
            File(tmp, "carved.pcap").delete()
        }
    }

    private fun convertCapture(ex: ToolExecutor, src: File, tmp: File, target: Target): String {
        return when (target.kind) {
            K_22000 -> run(ex, "hcxpcapngtool", tmp, "22000", listOf("-o", OUT, src.absolutePath))
            K_HCCAPX -> run(ex, "hcxpcapngtool", tmp, "hccapx",
                    listOf("--hccapx=$OUT", src.absolutePath))
            K_HCCAP -> run(ex, "hcxpcapngtool", tmp, "hccap",
                    listOf("--hccap=$OUT", src.absolutePath))
            K_CAPTURE -> {
                val out = File(tmp, "out.cap")
                src.copyTo(out, overwrite = true)
                ok(out)
            }
            else -> fail(target)
        }
    }

    /** HCCAPX/HCCAP 只装 EAPOL 握手；纯 PMKID 的 22000 文件转不了 */
    private fun hccapxHccapFrom22000(ex: ToolExecutor, src: File, tmp: File, target: Target): String {
        val hasEapol = try {
            src.readText().lineSequence().any { it.startsWith("WPA*02*") }
        } catch (_: Exception) { false }
        if (!hasEapol) return "✗ 该 22000 文件只有 PMKID 行，没有 EAPOL 帧\n" +
                "HCCAPX/HCCAP 只能装 4 次握手，请先转「CAP」再查看，或直接转 PMKID 16800"
        return when (target.kind) {
            K_HCCAPX -> run(ex, "hcxhashtool", tmp, "hccapx",
                    listOf("-i", src.absolutePath, "--hccapx-out=$OUT"))
            K_HCCAP -> run(ex, "hcxhashtool", tmp, "hccap",
                    listOf("-i", src.absolutePath, "--hccap-out=$OUT"))
            else -> fail(target)
        }
    }

    /** 执行工具：args 中的 OUT 占位符替换成输出文件绝对路径 */
    private fun run(ex: ToolExecutor, tool: String, tmp: File, outExt: String,
                    args: List<String>, outOverride: File? = null): String {
        val bin = ex.getToolPath(tool) ?: return "✗ 未找到工具: $tool"
        val out = outOverride ?: File(tmp, "out.$outExt")
        val full = args.map { it.replace(OUT, out.absolutePath) }
        val r = ex.runTool(bin, full)
        if (out.exists() && out.length() > 0) {
            if (outOverride != null) return ok(out)
            val final = File(tmp, "converted_$outExt")
            if (out.absolutePath != final.absolutePath) out.renameTo(final)
            return ok(final)
        }
        val tail = r.output.trim().take(400)
        return "✗ 转换失败 (exit=${r.exitCode})\n$tail"
    }

    private fun ok(f: File): String = "✓ 已转换\n${f.absolutePath}\n(${f.length()} bytes)"

    private fun fail(t: Target): String = "✗ 不支持: → ${t.label}"

    // ---------- 信息查看 ----------

    data class InfoCmd(val tool: String, val args: List<String>)

    fun infoCommand(kind: String, path: File): InfoCmd? = when (kind) {
        K_CAPTURE -> InfoCmd("hcxpcapngtool", listOf(path.absolutePath))
        K_22000 -> InfoCmd("hcxhashtool", listOf("-i", path.absolutePath, "--info=stdout"))
        K_HCCAPX -> InfoCmd("hcxhashtool",
                listOf("--hccapx-in=${path.absolutePath}", "--info=stdout"))
        K_HCCAP -> InfoCmd("hcxhashtool",
                listOf("--hccap-in=${path.absolutePath}", "--info=stdout"))
        K_16800 -> null
        else -> null
    }

    // ---------- 22000 → PMKID16800 ----------

    private fun writeHc22000To16800(src: File, out: File): String {
        val lines = src.readText().lineSequence().mapNotNull { line ->
            if (!line.startsWith("WPA*")) return@mapNotNull null
            val p = line.split("*")
            if (p.size < 6) return@mapNotNull null
            val pmkid = p[2]
            if (pmkid.length != 32 || !isHex(pmkid) || pmkid.all { it == '0' }) return@mapNotNull null
            val essidHex = if (isHex(p[5]) && p[5].length % 2 == 0) p[5] else p[5].encodeToHex()
            "$pmkid*${p[3]}*${p[4]}*$essidHex"
        }.toList()
        if (lines.isEmpty()) return "✗ 未找到有效 PMKID 行"
        out.writeText(lines.joinToString("\n") + "\n")
        return "✓ 已导出 ${lines.size} 条 PMKID\n${out.absolutePath}\n(${out.length()} bytes)"
    }

    private fun isHex(s: String): Boolean =
        s.isNotEmpty() && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun String.encodeToHex(): String = buildString {
        for (x in toByteArray()) append("%02x".format(x.toInt() and 0xFF))
    }

    // ---------- 预处理：任意格式 → 工具可识别文件 ----------

    data class Prepared(val path: File, val kind: String, val note: String)

    fun prepare(ctx: Context, data: ByteArray, name: String, type: FileType): Prepared {
        val tmp = File(ctx.cacheDir, "cur")
        tmp.mkdirs()
        when (kindOf(type)) {
            K_CAPTURE -> {
                val f = File(tmp, "cur.${extOf(type)}")
                f.writeBytes(data)
                return Prepared(f, K_CAPTURE, "")
            }
            "WKP" -> {
                val frames = WkpCarver.carve(data)
                val f = File(tmp, "cur_carved.pcap")
                if (WkpCarver.writePcap(frames, f))
                    return Prepared(f, K_CAPTURE,
                            "WKP = Elcomsoft 私有格式，已雕出 ${frames.size} 帧 802.11 后解析")
                val raw = File(tmp, "cur.wkp"); raw.writeBytes(data)
                return Prepared(raw, "WKP", "未雕到可用帧，WKP 为 Elcomsoft 私有格式")
            }
            K_16800 -> {
                val src = File(tmp, "cur.16800"); src.writeBytes(data)
                val cap = File(tmp, "cur_pmkid.cap")
                val ex = ToolExecutor(ctx)
                val bin = ex.getToolPath("hcxhash2cap")
                if (bin != null) {
                    ex.runTool(bin, listOf("--pmkid=${src.absolutePath}", "-c", cap.absolutePath))
                    if (cap.exists())
                        return Prepared(cap, K_CAPTURE, "PMKID 已重建为 CAP（只含 PMKID 帧，无 4 次握手）")
                }
                return Prepared(src, K_16800, "")
            }
            else -> {
                val f = File(tmp, "cur.${extOf(type)}")
                f.writeBytes(data)
                return Prepared(f, kindOf(type), "")
            }
        }
    }
}
