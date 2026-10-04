import { useState, useEffect } from 'react'
import { IconLock } from './Icons'
import PasswordField from './PasswordField'
import FileOpHeader from './FileOpHeader'
import ErrorBanner from './ErrorBanner'
import { scorePassword, STRENGTH_LABELS } from '../lib/strength'

function StrengthMeter({ password }) {
  const [result, setResult] = useState(null)

  useEffect(() => {
    if (!password) { setResult(null); return }
    let stale = false
    scorePassword(password).then(r => { if (!stale) setResult(r) })
    return () => { stale = true }
  }, [password])

  if (!password || !result) return null
  return (
    <div className="strength" data-score={result.score}>
      <div className="strength__bars">
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} className={`strength__bar${i <= result.score ? ' strength__bar--on' : ''}`} />
        ))}
      </div>
      <div className="strength__row">
        <span className="strength__warning">{result.score < 3 ? result.warning : ''}</span>
        <span className="strength__label">{STRENGTH_LABELS[result.score]}</span>
      </div>
    </div>
  )
}

export default function EncryptScreen({ file, initialPassword = '', error, errorAction, onBack, onSubmit }) {
  const [pw, setPw] = useState(initialPassword)
  const [pw2, setPw2] = useState(initialPassword)
  const match = pw.length > 0 && pw === pw2
  const canSubmit = match

  const submit = e => {
    e.preventDefault()
    if (canSubmit) onSubmit(pw)
  }

  return (
    <form className="screen" onSubmit={submit}>
      <FileOpHeader file={file} mode="encrypt" onClose={onBack} />

      <div className="stack">
        <PasswordField label="Password" value={pw} onChange={setPw} placeholder="Choose a Strong Password…" autoFocus />
        <StrengthMeter password={pw} />
        <PasswordField
          label="Verify Password"
          value={pw2}
          onChange={setPw2}
          placeholder="Repeat Password…"
          match={pw2 ? match : null}
        />
      </div>

      <ErrorBanner message={error} action={errorAction} />

      <div className="banner banner--note">
        <div className="dot" />
        <span>There is no password recovery. If you forget it, the file is gone.</span>
      </div>

      <div className="actions">
        <button type="button" className="btn btn--secondary" onClick={onBack}>Cancel</button>
        <button type="submit" className="btn btn--primary" disabled={!canSubmit}>
          <IconLock size={13} /> Encrypt File
        </button>
      </div>
    </form>
  )
}
