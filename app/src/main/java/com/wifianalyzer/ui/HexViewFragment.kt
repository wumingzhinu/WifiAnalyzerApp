package com.wifianalyzer.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.wifianalyzer.databinding.FragmentHexViewBinding
import com.wifianalyzer.parsers.FileParser

class HexViewFragment : Fragment() {
    private var _binding: FragmentHexViewBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHexViewBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        arguments?.getByteArray("file_data")?.let { binding.tvHexContent.text = FileParser().bytesToHex(it, 8192) }
    }

    override fun onDestroyView() { super.onDestroyView(); _binding = null }

    companion object {
        fun newInstance(fileData: ByteArray) = HexViewFragment().apply { arguments = Bundle().apply { putByteArray("file_data", fileData) } }
    }
}
