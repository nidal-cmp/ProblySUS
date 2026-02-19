import { useState } from 'react'
import axios from 'axios'

const BlacklistControl = () => {
    const [updating, setUpdating] = useState(false)
    const [status, setStatus] = useState(null) // 'success' | 'error' | null
    const [message, setMessage] = useState('')

    const handleUpdate = async () => {
        setUpdating(true)
        setStatus(null)
        setMessage('')

        try {
            const response = await axios.post('http://localhost:5000/api/blacklist/update')
            setStatus('success')
            setMessage(`Updated! Added ${response.data.stats.added_count} new domains.`)
        } catch (err) {
            setStatus('error')
            setMessage(err.response?.data?.details || "Update failed.")
        } finally {
            setUpdating(false)
            // Clear success message after a few seconds
            if (status !== 'error') {
                setTimeout(() => {
                    setStatus(null)
                    setMessage('')
                }, 5000)
            }
        }
    }

    return (
        <div className="fixed bottom-4 right-4 z-50">
            <div className="flex flex-col items-end gap-2">
                {message && (
                    <div className={`px-4 py-2 rounded-lg shadow-lg backdrop-blur-md border ${status === 'error'
                            ? 'bg-red-500/20 border-red-500/30 text-red-200'
                            : 'bg-green-500/20 border-green-500/30 text-green-200'
                        }`}>
                        {message}
                    </div>
                )}

                <button
                    onClick={handleUpdate}
                    disabled={updating}
                    className={`
                        px-4 py-2 rounded-lg font-medium transition-all shadow-lg backdrop-blur-md border
                        ${updating
                            ? 'bg-gray-500/20 border-gray-500/30 text-gray-400 cursor-not-allowed'
                            : 'bg-indigo-500/20 border-indigo-500/30 text-indigo-300 hover:bg-indigo-500/30 hover:border-indigo-500/50 hover:text-white'
                        }
                    `}
                >
                    {updating ? (
                        <span className="flex items-center gap-2">
                            <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none"></circle>
                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            Updating DB...
                        </span>
                    ) : (
                        <span className="flex items-center gap-2">
                            🛡️ Update Threat DB
                        </span>
                    )}
                </button>
            </div>
        </div>
    )
}

export default BlacklistControl
