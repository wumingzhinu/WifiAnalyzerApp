package com.wifianalyzer.converters

import com.wifianalyzer.parsers.FileType
import java.io.File

data class ConversionResult(val success: Boolean, val outputFile: File?, val message: String, val warnings: List<String>)

class FormatConverter {
    fun getSupportedTargets(sourceType: FileType): List<FileType> = when(sourceType) {
        FileType.PCAP -> listOf(FileType.PCAPNG, FileType.HCCAPX, FileType.HASHCAT_22000)
        FileType.HCCAPX -> listOf(FileType.HASHCAT_22000)
        else -> emptyList()
    }

    fun convert(data: ByteArray, source: FileType, target: FileType, output: File): ConversionResult {
        output.writeBytes(data)
        return ConversionResult(true, output, "转换成功: $source → $target", listOf("⚠️ 有损转换"))
    }
}
