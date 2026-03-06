import { motion } from 'framer-motion'

const TrackerPanel = ({ data, embedded }) => {
    if (!data || data.tracker_count === undefined) return null

    const { trackers_detected, tracker_count, tracker_details } = data

    const getTrackerColor = (count) => {
        if (count > 8) return { bg: 'bg-red-500/10', border: 'border-red-500/20', text: 'text-red-400' }
        if (count > 4) return { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', text: 'text-yellow-400' }
        return { bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', text: 'text-emerald-400' }
    }

    const colors = getTrackerColor(tracker_count)

    const elementIcons = {
        'script': '📜',
        'iframe': '🪟',
        'img': '🖼️',
        'link': '🔗',
        'inline_script': '💻',
    }

    const content = (
        <>
            <div className="flex items-center justify-between mb-3">
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <span>📡</span> Trackers
                </h4>
                <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${colors.bg} ${colors.text} border ${colors.border}`}>
                    {tracker_count} found
                </span>
            </div>

            {tracker_count === 0 ? (
                <p className="text-sm text-gray-500">No known trackers detected.</p>
            ) : (
                <div className="space-y-1.5">
                    {(tracker_details || []).map((tracker, i) => (
                        <div
                            key={i}
                            className="flex items-center justify-between p-2.5 bg-white/5 rounded-lg border border-white/5"
                        >
                            <div className="flex items-center gap-2.5">
                                <span className="text-base" title={tracker.element}>
                                    {elementIcons[tracker.element] || '📦'}
                                </span>
                                <div>
                                    <p className="text-sm font-medium text-gray-200">{tracker.name}</p>
                                    <p className="text-[11px] text-gray-500 font-mono">{tracker.domain}</p>
                                </div>
                            </div>
                            <span className="px-1.5 py-0.5 bg-white/5 rounded text-[10px] text-gray-500">
                                {tracker.element}
                            </span>
                        </div>
                    ))}
                </div>
            )}
        </>
    )

    if (embedded) return content

    return (
        <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className={`mt-6 p-5 rounded-xl backdrop-blur-md border ${colors.bg} ${colors.border}`}
        >
            {content}
        </motion.div>
    )
}

export default TrackerPanel
