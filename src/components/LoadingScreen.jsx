import FileOpHeader from './FileOpHeader'
import { PHASE_LABELS, shortName } from '../lib/format'

const R = 32
const CIRC = 2 * Math.PI * R

export default function LoadingScreen({ mode, file, progress, cancelling, onCancel }) {
  const pct = Math.min(Math.max(Math.floor(progress.percent ?? 0), 0), 100)
  const phase = cancelling
    ? 'Cancelling…'
    : PHASE_LABELS[progress.phase] ?? (mode === 'encrypt' ? 'Starting…' : 'Reading File…')

  return (
    <div className="screen">
      <FileOpHeader file={file} mode={mode} />

      <div className="progress">
        <div className="ring" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
          <svg width="60" height="60" viewBox="0 0 80 80">
            <circle className="ring__track" cx="40" cy="40" r={R} fill="none" strokeWidth="5" />
            <circle
              className="ring__value"
              cx="40" cy="40" r={R} fill="none" strokeWidth="5" strokeLinecap="round"
              strokeDasharray={CIRC}
              strokeDashoffset={CIRC * (1 - pct / 100)}
            />
          </svg>
          <div className="ring__pct">{pct}%</div>
        </div>
        <div className="progress__phase">{phase}</div>
      </div>

      <div>
        <div className="bar"><div className="bar__fill" style={{ width: `${pct}%` }} /></div>
        <div className="bar__row">
          <span>{shortName(file?.name, 26)}</span>
          <span>{pct}%</span>
        </div>
      </div>

      <button type="button" className="btn btn--secondary" onClick={onCancel} disabled={cancelling}>
        {cancelling ? 'Cancelling…' : 'Cancel'}
      </button>
    </div>
  )
}
