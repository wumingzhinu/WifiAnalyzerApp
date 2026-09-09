package com.wifianalyzer.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.wifianalyzer.databinding.FragmentAiAnalysisBinding
import com.wifianalyzer.parsers.AiReport

class AiAnalysisFragment : Fragment() {
    private var _binding: FragmentAiAnalysisBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentAiAnalysisBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        @Suppress("DEPRECATION") arguments?.getParcelable<AiReport>("ai_report")?.let { report ->
            binding.tvFileOverview.text = report.fileOverview
            binding.tvStructureAnalysis.text = report.structureAnalysis
            binding.tvAiConclusion.text = report.aiConclusion
        }
    }

    override fun onDestroyView() { super.onDestroyView(); _binding = null }

    companion object {
        fun newInstance(report: AiReport) = AiAnalysisFragment().apply { arguments = Bundle().apply { putParcelable("ai_report", report) } }
    }
}
