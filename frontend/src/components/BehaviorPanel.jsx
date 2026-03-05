import { motion } from 'framer-motion'

const BehaviorPanel = ({ data, embedded }) => {
    if (!data) return null

    const { redirect_count, redirect_chain, external_request_count, suspicious_domains, page_title, final_url, error } = data

    if (error) {
        return (
            <div className={embedded ? '' : 'mt-6 p-5 rounded-xl bg-gray-500/10 border border-gray-500/20 backdrop-blur-md'}>
                <h3 className={`font-bold text-gray-300 flex items-center gap-2 ${embedded ? 'text-base mb-2' : 'text-lg mb-2'}`}>
                    {!embedded && <span className="text-xl">🔍</span>} Behavior Analysis
                </h3>
                <p className="text-gray-500 text-sm">Runtime analysis unavailable — {error}</p>
            </div>
        )
    }

    const hasIssues = redirect_count > 2 || suspicious_domains?.length > 0

    const content = (
        <>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
                <div className="bg-white/5 rounded-lg p-3 text-center">
                    <div className={`text-2xl font-bold ${redirect_count > 3 ? 'text-red-400' : redirect_count > 1 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {redirect_count}
                    </div>
                    <div className="text-xs text-gray-400 mt-1">Redirects</div>
                </div>
                <div className="bg-white/5 rounded-lg p-3 text-center">
                    <div className={`text-2xl font-bold ${external_request_count > 20 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {external_request_count}
                    </div>
                    <div className="text-xs text-gray-400 mt-1">External Requests</div>
                </div>
                <div className="bg-white/5 rounded-lg p-3 text-center">
                    <div className={`text-2xl font-bold ${suspicious_domains?.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {suspicious_domains?.length || 0}
                    </div>
                    <div className="text-xs text-gray-400 mt-1">Suspicious Domains</div>
                </div>
            </div>

            {suspicious_domains && suspicious_domains.length > 0 && (
                <div className="mt-3 p-3 bg-red-500/10 rounded-lg border border-red-500/20">
                    <p className="text-xs font-semibold text-red-300 mb-2">⚠️ Suspicious domains contacted:</p>
                    <div className="flex flex-wrap gap-2">
                        {suspicious_domains.map((domain, i) => (
                            <span key={i} className="px-2 py-1 bg-red-500/20 rounded-md text-xs text-red-200 font-mono">
                                {domain}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {redirect_chain && redirect_chain.length > 1 && (
                <div className="mt-3 p-3 bg-white/5 rounded-lg">
                    <p className="text-xs font-semibold text-gray-300 mb-2">Redirect chain:</p>
                    <div className="space-y-1">
                        {redirect_chain.slice(0, 5).map((url, i) => (
                            <div key={i} className="flex items-center gap-2 text-xs text-gray-400">
                                <span className="text-gray-600">{i + 1}.</span>
                                <span className="font-mono truncate">{url}</span>
                            </div>
                        ))}
                        {redirect_chain.length > 5 && (
                            <p className="text-xs text-gray-600">...and {redirect_chain.length - 5} more</p>
                        )}
                    </div>
                </div>
            )}

            {page_title && (
                <p className="mt-3 text-xs text-gray-500">
                    Page title: <span className="text-gray-400">{page_title}</span>
                </p>
            )}
        </>
    )

    if (embedded) return content

    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className={`mt-6 p-5 rounded-xl backdrop-blur-md border ${hasIssues
                ? 'bg-orange-500/10 border-orange-500/20'
                : 'bg-emerald-500/10 border-emerald-500/20'
                }`}
        >
            <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                <span className="text-xl">🔍</span> Behavior Analysis
            </h3>
            {content}
        </motion.div>
    )
}

export default BehaviorPanel
