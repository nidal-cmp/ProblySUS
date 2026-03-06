import { motion } from 'framer-motion'

const PrivacyPanel = ({ data, embedded }) => {
    if (!data) return null

    const {
        cookie_count,
        third_party_script_count,
        tracking_cookie_names,
        tracking_cookie_count,
        fingerprinting_signals,
        fingerprinting_score,
        privacy_grade
    } = data

    const gradeConfig = {
        good: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', emoji: '🟢', label: 'Good' },
        moderate: { color: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', emoji: '🟡', label: 'Moderate' },
        poor: { color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20', emoji: '🟠', label: 'Poor' },
        invasive: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', emoji: '🔴', label: 'Invasive' },
    }

    const grade = gradeConfig[privacy_grade] || gradeConfig.good

    const fingerprintIcons = {
        canvas: '🎨',
        webgl: '🖥️',
        audio: '🔊',
        plugins: '🔌',
        language: '🌍',
        screen: '📺',
        hardware: '💻',
        battery: '🔋',
        webrtc: '📡',
    }

    const privacyScore = Math.min(10,
        Math.floor(
            (tracking_cookie_count || 0) * 1.5 +
            (third_party_script_count || 0) * 0.5 +
            (fingerprinting_score || 0) * 1.5
        )
    )

    const content = (
        <>
            {/* Grade + Exposure Bar */}
            <div className="flex items-center justify-between mb-3">
                <h4 className="text-sm font-bold text-white">Privacy Grade</h4>
                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${grade.bg} ${grade.color} border ${grade.border} flex items-center gap-1`}>
                    {grade.emoji} {grade.label}
                </span>
            </div>

            <div className="mb-4">
                <div className="flex justify-between items-center mb-1">
                    <span className="text-[11px] text-gray-400">Privacy Exposure</span>
                    <span className={`text-[11px] font-bold ${grade.color}`}>{privacyScore}/10</span>
                </div>
                <div className="w-full bg-gray-700/50 rounded-full h-1.5 overflow-hidden">
                    <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${privacyScore * 10}%` }}
                        transition={{ duration: 0.8, ease: "easeOut" }}
                        className={`h-full rounded-full ${privacyScore > 6 ? 'bg-red-500' : privacyScore > 3 ? 'bg-yellow-500' : 'bg-emerald-500'}`}
                    />
                </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className="text-lg font-bold text-gray-200">🍪 {cookie_count || 0}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">Cookies</div>
                </div>
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className={`text-lg font-bold ${tracking_cookie_count > 3 ? 'text-red-400' : 'text-gray-200'}`}>
                        🎯 {tracking_cookie_count || 0}
                    </div>
                    <div className="text-[10px] text-gray-500 mt-0.5">Tracking</div>
                </div>
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className={`text-lg font-bold ${third_party_script_count > 5 ? 'text-yellow-400' : 'text-gray-200'}`}>
                        📜 {third_party_script_count || 0}
                    </div>
                    <div className="text-[10px] text-gray-500 mt-0.5">3P Scripts</div>
                </div>
                <div className="bg-white/5 rounded-lg p-2.5 text-center">
                    <div className={`text-lg font-bold ${fingerprinting_score > 2 ? 'text-orange-400' : 'text-gray-200'}`}>
                        🔬 {fingerprinting_score || 0}
                    </div>
                    <div className="text-[10px] text-gray-500 mt-0.5">Fingerprint</div>
                </div>
            </div>

            {/* Fingerprinting Techniques */}
            {fingerprinting_signals && fingerprinting_signals.length > 0 && (
                <div className="mt-3 p-3 bg-white/5 rounded-lg">
                    <p className="text-xs font-semibold text-gray-300 mb-2">Fingerprinting techniques:</p>
                    <div className="flex flex-wrap gap-1.5">
                        {fingerprinting_signals.map((signal, i) => (
                            <span key={i} className="px-2 py-0.5 bg-orange-500/15 border border-orange-500/20 rounded-md text-[11px] text-orange-300 flex items-center gap-1">
                                {fingerprintIcons[signal] || '❓'} {signal}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Tracking Cookies */}
            {tracking_cookie_names && tracking_cookie_names.length > 0 && (
                <details className="mt-3">
                    <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-300 transition-colors">
                        View {tracking_cookie_names.length} tracking cookie(s)
                    </summary>
                    <div className="mt-2 flex flex-wrap gap-1">
                        {tracking_cookie_names.map((name, i) => (
                            <span key={i} className="px-2 py-0.5 bg-white/5 rounded text-xs text-gray-400 font-mono">
                                {name}
                            </span>
                        ))}
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
            transition={{ delay: 0.4 }}
            className={`mt-6 p-5 rounded-xl backdrop-blur-md border ${grade.bg} ${grade.border}`}
        >
            {content}
        </motion.div>
    )
}

export default PrivacyPanel
