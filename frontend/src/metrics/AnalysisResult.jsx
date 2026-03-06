import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import BehaviorPanel from '../components/BehaviorPanel'
import TrackerPanel from '../components/TrackerPanel'
import NetworkPanel from '../components/NetworkPanel'
import PrivacyPanel from '../components/PrivacyPanel'

const TABS = [
    { id: 'security', label: 'Security', icon: '🛡️' },
    { id: 'behavior', label: 'Behavior', icon: '🔍' },
    { id: 'network', label: 'Network', icon: '🌐' },
    { id: 'privacy', label: 'Privacy', icon: '🔒' },
]

const AnalysisResult = ({ data }) => {
    const [activeTab, setActiveTab] = useState('security')
    const { riskScore, label, reasons, checks, analysis } = data

    const getScoreColor = (label) => {
        if (label === 'Safe') return { text: 'text-emerald-400', border: 'border-emerald-400', shadow: 'shadow-emerald-400/20', bg: 'bg-emerald-400' }
        if (label === 'Caution') return { text: 'text-yellow-400', border: 'border-yellow-400', shadow: 'shadow-yellow-400/20', bg: 'bg-yellow-400' }
        if (label === 'Suspicious') return { text: 'text-orange-400', border: 'border-orange-400', shadow: 'shadow-orange-400/20', bg: 'bg-orange-400' }
        return { text: 'text-red-500', border: 'border-red-500', shadow: 'shadow-red-500/20', bg: 'bg-red-500' }
    }

    const colors = getScoreColor(label)

    // Quick-glance summary data from new modules
    const behaviorData = analysis?.behavior || {}
    const trackerData = analysis?.trackers || {}
    const networkData = analysis?.network || {}
    const privacyData = analysis?.privacy || {}

    const summaryItems = [
        {
            icon: '↪️',
            value: behaviorData.error ? '—' : (behaviorData.redirect_count || 0),
            label: 'Redirects',
            alert: !behaviorData.error && behaviorData.redirect_count > 2,
        },
        {
            icon: '📡',
            value: trackerData.tracker_count ?? 0,
            label: 'Trackers',
            alert: trackerData.tracker_count > 5,
        },
        {
            icon: '🌐',
            value: networkData.risk_level || 'n/a',
            label: 'Net Risk',
            alert: networkData.risk_level === 'high',
            isText: true,
        },
        {
            icon: '🛡️',
            value: privacyData.privacy_grade || 'n/a',
            label: 'Privacy',
            alert: privacyData.privacy_grade === 'invasive' || privacyData.privacy_grade === 'poor',
            isText: true,
        },
    ]

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="w-full max-w-4xl mx-auto mt-10 mb-16"
        >
            {/* ══════════════ Score Header — Compact ══════════════ */}
            <div className="bg-white/5 backdrop-blur-md border border-white/10 rounded-2xl p-6 shadow-2xl">
                <div className="flex flex-col sm:flex-row items-center gap-6">
                    {/* Score Circle */}
                    <div className="flex-shrink-0">
                        <div className={`w-24 h-24 rounded-full border-[3px] flex items-center justify-center text-3xl font-bold bg-white/5 shadow-xl ${colors.border} ${colors.text} ${colors.shadow}`}>
                            {riskScore}
                        </div>
                    </div>

                    {/* Label + Recommendation + Progress */}
                    <div className="flex-1 w-full text-center sm:text-left">
                        <h2 className={`text-xl font-bold tracking-wide ${colors.text}`}>
                            {label.toUpperCase()}
                        </h2>
                        <p className="text-gray-400 text-sm mt-1">
                            {data.recommendation}
                        </p>
                        <div className="w-full bg-gray-700/50 rounded-full h-2 mt-3 overflow-hidden">
                            <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${riskScore}%` }}
                                transition={{ duration: 1, ease: "easeOut" }}
                                className={`h-full rounded-full ${colors.bg}`}
                            />
                        </div>
                    </div>

                    {/* Quick hostname tag */}
                    <div className="flex-shrink-0 hidden sm:block">
                        <span className="px-3 py-1 bg-white/5 border border-white/10 rounded-full text-xs text-gray-400 font-mono">
                            {data.hostname}
                        </span>
                    </div>
                </div>

                {/* ══════════════ Quick-Glance Summary Strip ══════════════ */}
                {analysis && (
                    <div className="grid grid-cols-4 gap-2 mt-5 pt-5 border-t border-white/5">
                        {summaryItems.map((item, i) => (
                            <div
                                key={i}
                                className={`text-center p-2 rounded-lg transition-colors ${item.alert ? 'bg-red-500/10' : 'bg-white/[0.03]'}`}
                            >
                                <span className="text-base">{item.icon}</span>
                                <div className={`text-sm font-bold mt-0.5 capitalize ${item.alert ? 'text-red-400' : 'text-gray-200'}`}>
                                    {item.isText ? String(item.value) : item.value}
                                </div>
                                <div className="text-[10px] text-gray-500 uppercase tracking-wider">{item.label}</div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* ══════════════ Metric Cards Grid — Compact ══════════════ */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2 mt-4">
                <MetricCard icon={checks.https ? '🔒' : '🔓'} label={checks.https ? 'HTTPS' : 'No SSL'} ok={checks.https} />
                <MetricCard icon="📅" label={checks.domainAgeDays >= 0 ? `${checks.domainAgeDays}d` : '?'} sublabel="Age" ok={checks.domainAgeDays > 30} />
                <MetricCard icon={!checks.blacklisted ? '✅' : '🚫'} label={checks.blacklisted ? 'Listed' : 'Clean'} sublabel="Blacklist" ok={!checks.blacklisted} />
                <MetricCard icon={!checks.suspiciousPatterns ? '🛡️' : '⚠️'} label={checks.suspiciousPatterns ? 'Flagged' : 'Clean'} sublabel="Patterns" ok={!checks.suspiciousPatterns} />
                <MetricCard icon="📄" label={checks.trustPages?.length || 0} sublabel="Trust Pages" ok={checks.trustPages?.length > 0} />
                <MetricCard icon={checks.mxRecords ? '📧' : '❌'} label={checks.mxRecords ? 'MX' : 'No MX'} sublabel="Email" ok={checks.mxRecords} />
                <MetricCard icon={checks.urgencyScore === 0 ? '😌' : '😰'} label={checks.urgencyScore === 0 ? 'Normal' : 'Urgent'} sublabel="Language" ok={checks.urgencyScore === 0} />
            </div>

            {/* ══════════════ Tabbed Detail Panels ══════════════ */}
            <div className="mt-4 bg-white/5 backdrop-blur-md border border-white/10 rounded-2xl overflow-hidden shadow-2xl">
                {/* Tab Bar */}
                <div className="flex border-b border-white/10">
                    {TABS.map((tab) => (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex-1 px-3 py-3 text-sm font-medium transition-all relative
                                ${activeTab === tab.id
                                    ? 'text-white bg-white/5'
                                    : 'text-gray-500 hover:text-gray-300 hover:bg-white/[0.02]'
                                }`}
                        >
                            <span className="mr-1.5">{tab.icon}</span>
                            <span className="hidden sm:inline">{tab.label}</span>
                            {activeTab === tab.id && (
                                <motion.div
                                    layoutId="activeTab"
                                    className={`absolute bottom-0 left-0 right-0 h-0.5 ${colors.bg}`}
                                    transition={{ type: "spring", stiffness: 500, damping: 30 }}
                                />
                            )}
                        </button>
                    ))}
                </div>

                {/* Tab Content */}
                <div className="p-5">
                    <AnimatePresence mode="wait">
                        {activeTab === 'security' && (
                            <motion.div
                                key="security"
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: 10 }}
                                transition={{ duration: 0.2 }}
                            >
                                {/* Reasons / Findings */}
                                {reasons && reasons.length > 0 && (
                                    <div>
                                        <h3 className="text-base font-bold mb-3 text-white">Analysis Findings</h3>
                                        <ul className="space-y-2">
                                            {reasons.map((reason, index) => (
                                                <li key={index} className="flex items-start text-sm text-gray-300 leading-relaxed">
                                                    <span className="mr-2 text-white/30 mt-0.5">›</span>
                                                    {reason}
                                                </li>
                                            ))}
                                        </ul>
                                    </div>
                                )}
                            </motion.div>
                        )}

                        {activeTab === 'behavior' && (
                            <motion.div
                                key="behavior"
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: 10 }}
                                transition={{ duration: 0.2 }}
                            >
                                {analysis?.behavior ? (
                                    <BehaviorPanel data={analysis.behavior} embedded />
                                ) : (
                                    <EmptyState text="Behavior analysis data not available" />
                                )}
                            </motion.div>
                        )}

                        {activeTab === 'network' && (
                            <motion.div
                                key="network"
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: 10 }}
                                transition={{ duration: 0.2 }}
                            >
                                {analysis?.network ? (
                                    <NetworkPanel data={analysis.network} embedded />
                                ) : (
                                    <EmptyState text="Network analysis data not available" />
                                )}
                                {analysis?.trackers && (
                                    <div className="mt-4">
                                        <TrackerPanel data={analysis.trackers} embedded />
                                    </div>
                                )}
                            </motion.div>
                        )}

                        {activeTab === 'privacy' && (
                            <motion.div
                                key="privacy"
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                exit={{ opacity: 0, x: 10 }}
                                transition={{ duration: 0.2 }}
                            >
                                {analysis?.privacy ? (
                                    <PrivacyPanel data={analysis.privacy} embedded />
                                ) : (
                                    <EmptyState text="Privacy analysis data not available" />
                                )}
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </motion.div>
    )
}

const MetricCard = ({ icon, label, sublabel, ok }) => (
    <div className={`flex flex-col items-center justify-center p-2.5 rounded-xl bg-white/5 border border-white/5 transition-colors ${ok ? 'text-gray-200' : 'text-gray-500'}`}>
        <span className="text-lg">{icon}</span>
        <span className="text-xs font-bold mt-1">{label}</span>
        {sublabel && <span className="text-[10px] text-gray-600 uppercase tracking-wider">{sublabel}</span>}
    </div>
)

const EmptyState = ({ text }) => (
    <div className="text-center py-8 text-gray-600 text-sm">{text}</div>
)

export default AnalysisResult
