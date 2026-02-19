import { useState } from 'react'
import axios from 'axios'
import UrlInput from './components/UrlInput'
import AnalysisResult from './metrics/AnalysisResult'
import AntigravityParams from './components/AntigravityParams'
import './index.css'

function App() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleAnalyze = async (url) => {
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      // Assuming backend is running on port 5000
      const response = await axios.post('http://localhost:5000/analyze', { url })
      setResult(response.data)
    } catch (err) {
      setError(err.response?.data?.error || "Failed to analyze URL. Server might be down.")
      console.error(err)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AntigravityParams>
      <div className="w-full max-w-5xl mx-auto flex flex-col items-center pt-20">
        <div className="text-center mb-12 animate-fade-in-up">
          <h1 className="text-6xl md:text-8xl font-black tracking-tighter text-white mb-6 drop-shadow-2xl">
            Problysus
          </h1>
          <p className="text-xl md:text-2xl text-gray-400 font-light tracking-wide">
            Universal Website Scam & Trust Detection
          </p>
        </div>

        <UrlInput onAnalyze={handleAnalyze} loading={loading} />

        {error && (
          <div className="mt-8 p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-200 flex items-center shadow-lg backdrop-blur-md">
            <span className="mr-2 text-xl">⚠️</span> {error}
          </div>
        )}

        {result && (
          <AnalysisResult data={result} />
        )}
      </div>
    </AntigravityParams>
  )
}

export default App
