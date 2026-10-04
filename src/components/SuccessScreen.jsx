import { useState } from 'react'
import { IconCheck, IconFolder } from './Icons'
import ErrorBanner from './ErrorBanner'
import { errorMessage } from '../lib/format'

export default function SuccessScreen({ mode, outcome, onReveal, onDone }) {
  const [error, setError] = useState(null)
  const reveal = () => { setError(null); onReveal().catch(e => setError(errorMessage(e))) }
  const label = mode === 'encrypt' ? 'File Encrypted Successfully' : 'File Decrypted Successfully'

  return (
    <div className="screen">
      <div className="success" role="status">
        <div className="success__icon"><IconCheck size={11} /></div>
        <span className="success__label">{label}</span>
      </div>

      <div className="outpath">
        <IconFolder size={14} />
        <div>
          <div className="outpath__text">{outcome.outputPath}</div>
          {mode === 'decrypt' && <div className="outpath__format">From {outcome.format}</div>}
        </div>
      </div>

      <ErrorBanner message={error} />

      <div className="actions actions--even">
        <button type="button" className="btn btn--primary" onClick={reveal}>Show in Folder</button>
        <button type="button" className="btn btn--secondary" onClick={onDone}>Done</button>
      </div>
    </div>
  )
}
