package com.wifianalyzer.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import com.wifianalyzer.R
import com.wifianalyzer.parsers.AiReport

class AiAnalysisFragment : Fragment() {

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_ai_analysis, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        @Suppress("DEPRECATION")
        val report = arguments?.getParcelable<AiReport>("ai_report") ?: return

        view.findViewById<android.widget.TextView>(R.id.tvFileOverview).text = report.fileOverview
        view.findViewById<android.widget.TextView>(R.id.tvHandshakeSummary).text = report.handshakeSummary
        view.findViewById<android.widget.TextView>(R.id.tvSecurityAnalysis).text = report.securityAnalysis
        view.findViewById<android.widget.TextView>(R.id.tvCrackableInfo).text = report.crackableInfo
        view.findViewById<android.widget.TextView>(R.id.tvRecommendations).text = report.recommendations
    }

    companion object {
        fun newInstance(report: AiReport): AiAnalysisFragment {
            return AiAnalysisFragment().apply {
                arguments = Bundle().apply { putParcelable("ai_report", report) }
            }
        }
    }
}
