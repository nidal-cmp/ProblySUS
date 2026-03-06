import { motion } from 'framer-motion'

const NetworkPanel = ({ data, embedded }) => {
    if (!data) return null

    const {
        external_domains,
        external_domain_count,
        suspicious_domains,
        suspicious_external_count,
        safe_infra_domains,
        unknown_domains,
        risk_level
    } = data

    const riskColors = {
        low: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', badge: 'text-emerald-400', label: 'Low Risk' },
        medium: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', badge: 'text-yellow-400', label: 'Medium Risk' },
        high: { bg: 'bg-red-500/10', border: 'border-red-500/20', badge: 'text-red-400', label: 'High Risk' },
    }

    const colors = riskColors[risk_level] || riskColors.low

    const content = (
        <>
            <div className="flex items-center justify-between mb-3">
                <h4 className="text-sm font-bold text-white">Network Overview</h4>
                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${colors.bg} ${colors.badge} border ${colors.border}`}>
                    {colors.label}
                </span>
            </div>

            {/* Stats Row */}
            <div className="grid grid-cols-3 gap-2 mb-3">
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className="text-lg font-bold text-gray-200">{external_domain_count || 0}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">External</div>
                </div>
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className="text-lg font-bold text-green-400">{safe_infra_domains?.length || 0}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">CDN/Infra</div>
                </div>
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className={`text-lg font-bold ${suspicious_external_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {suspicious_external_count || 0}
                    </div>
                    <div className="text-[10px] text-gray-500 mt-0.5">Suspicious</div>
                </div>
            </div>

            {/* Suspicious Domains */}
            {suspicious_domains && suspicious_domains.length > 0 && (
                <div className="mb-3 p-3 bg-red-500/10 rounded-lg border border-red-500/20">
                    <p className="text-xs font-semibold text-red-300 mb-2">⚠️ Suspicious external domains:</p>
                    <div className="flex flex-wrap gap-2">
                        {suspicious_domains.map((domain, i) => (
                            <span key={i} className="px-2 py-1 bg-red-500/20 rounded-md text-xs text-red-200 font-mono">
                                {domain}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Domain breakdown */}
            {external_domain_count > 0 && (
                <details className="mt-2">
                    <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-300 transition-colors">
                        View all {external_domain_count} external domains
                    </summary>
                    <div className="mt-2 max-h-36 overflow-y-auto space-y-1 pr-2">
                        {(external_domains || []).map((domain, i) => {
                            const isSafe = safe_infra_domains?.includes(domain)
                            const isSusp = suspicious_domains?.includes(domain)
                            return (
                                <div key={i} className="flex items-center gap-2 text-xs">
                                    <span>{isSusp ? '🔴' : isSafe ? '🟢' : '⚪'}</span>
                                    <span className={`font-mono ${isSusp ? 'text-red-300' : isSafe ? 'text-green-400' : 'text-gray-400'}`}>
                                        {domain}
                                    </span>
                                </div>
                            )
                        })}
                    </div>
                </details>
            )}
        </>
    )

    if (embedded) return content

    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className={`mt-6 p-5 rounded-xl backdrop-blur-md border ${colors.bg} ${colors.border}`}
        >
            {content}
        </motion.div>
    )
}

export default NetworkPanel
