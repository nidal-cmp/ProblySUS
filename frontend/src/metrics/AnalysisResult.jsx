import { motion } from 'framer-motion'

const AnalysisResult = ({ data }) => {
    const { riskScore, label, reasons, checks } = data

    const getScoreColor = (label) => {
        if (label === 'Safe') return 'text-green-400 border-green-400 shadow-green-400/20'
        if (label === 'Suspicious') return 'text-yellow-400 border-yellow-400 shadow-yellow-400/20'
        return 'text-red-500 border-red-500 shadow-red-500/20'
    }

    const getProgressBarColor = (label) => {
        if (label === 'Safe') return '#4ade80' // green-400
        if (label === 'Suspicious') return '#facc15' // yellow-400
        return '#ef4444' // red-500
    }

    const scoreColorClass = getScoreColor(label)

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="w-full max-w-4xl mx-auto mt-12 bg-white/5 backdrop-blur-md border border-white/10 rounded-2xl p-8 shadow-2xl"
        >
            <div className="flex flex-col items-center mb-8">
                <div className={`w-32 h-32 rounded-full border-4 flex items-center justify-center text-4xl font-bold bg-white/5 shadow-2xl mb-4 ${scoreColorClass}`}>
                    {riskScore}
                </div>
                <h2 className={`text-2xl font-bold tracking-wide ${scoreColorClass.split(' ')[0]}`}>
                    {label.toUpperCase()}
                </h2>
            </div>

            <p className="text-center text-gray-300 text-lg mb-8 max-w-2xl mx-auto leading-relaxed">
                {data.recommendation}
            </p>

            {/* Progress Bar */}
            <div className="w-full bg-gray-700/50 rounded-full h-3 mb-10 overflow-hidden">
                <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${riskScore}%` }}
                    transition={{ duration: 1, ease: "easeOut" }}
                    style={{
                        height: '100%',
                        backgroundColor: getProgressBarColor(label)
                    }}
                />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-10">
                <MetricItem
                    icon={checks.https ? '🔒' : '🔓'}
                    label={checks.https ? 'Valid HTTPS' : 'No HTTPS'}
                    status={checks.https}
                />
                <MetricItem
                    icon="📅"
                    label={`Domain Age: ${checks.domainAgeDays >= 0 ? `${checks.domainAgeDays} days` : 'Unknown'}`}
                    status={checks.domainAgeDays > 30}
                />
                <MetricItem
                    icon={!checks.blacklisted ? '✅' : '🚫'}
                    label={checks.blacklisted ? 'On Blacklist' : 'Not Blacklisted'}
                    status={!checks.blacklisted}
                />
                <MetricItem
                    icon={!checks.suspiciousPatterns ? '🛡️' : '⚠️'}
                    label={checks.suspiciousPatterns ? 'Suspicious Patterns' : 'Clean URL Patterns'}
                    status={!checks.suspiciousPatterns}
                />
                <MetricItem
                    icon="📄"
                    label={`Trust Pages: ${checks.trustPages && checks.trustPages.length > 0 ? checks.trustPages.length : 'None'}`}
                    status={checks.trustPages && checks.trustPages.length > 0}
                />
                <MetricItem
                    icon={checks.mxRecords ? '📧' : '❌'}
                    label={checks.mxRecords ? 'Valid Email Servers' : 'No Email Records'}
                    status={checks.mxRecords}
                />
                <MetricItem
                    icon={checks.urgencyScore === 0 ? '😌' : '😰'}
                    label={checks.urgencyScore === 0 ? 'Normal Language' : 'High Urgency Detected'}
                    status={checks.urgencyScore === 0}
                />
            </div>

            {reasons && reasons.length > 0 && (
                <div className={`p-6 rounded-xl border ${label === 'Safe' ? 'bg-green-500/10 border-green-500/20' : 'bg-red-500/10 border-red-500/20'}`}>
                    <h3 className="text-lg font-bold mb-4 text-white">Analysis Findings:</h3>
                    <ul className="space-y-2">
                        {reasons.map((reason, index) => (
                            <li key={index} className="flex items-start text-gray-300">
                                <span className="mr-2 text-white/50">•</span>
                                {reason}
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </motion.div>
    )
}

const MetricItem = ({ icon, label, status }) => (
    <div className={`flex items-center p-4 rounded-lg bg-white/5 border border-white/5 ${status ? 'text-gray-200' : 'text-gray-400'}`}>
        <span className="text-2xl mr-4">{icon}</span>
        <span className="font-medium text-sm">{label}</span>
    </div>
)

export default AnalysisResult
