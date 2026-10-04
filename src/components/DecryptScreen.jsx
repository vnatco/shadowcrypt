import { useState, useEffect, useRef } from 'react'
import { IconUnlock } from './Icons'
import PasswordField from './PasswordField'
import FileOpHeader from './FileOpHeader'
import ErrorBanner from './ErrorBanner'

export default function DecryptScreen({ file, initialPassword = '', error, errorAction, onBack, onSubmit }) {
  const [pw, setPw] = useState(initialPassword)
  const inputRef = useRef(null)

  // After a wrong password, select the text so the user can just retype.
  useEffect(() => {
    if (error && inputRef.current) inputRef.current.select()
  }, [error])

  const submit = e => {
    e.preventDefault()
    if (pw) onSubmit(pw)
  }

  return (
    <form className="screen" onSubmit={submit}>
      <FileOpHeader file={file} mode="decrypt" onClose={onBack} />

      <PasswordField
        label="Decryption Password"
        value={pw}
        onChange={setPw}
        placeholder="Enter Password to Decrypt…"
        autoFocus
        inputRef={inputRef}
      />

      <ErrorBanner message={error} action={errorAction} />

      <div className="banner banner--note">
        <div className="dot" />
        <span>Output is saved next to the encrypted file. Nothing is overwritten.</span>
      </div>

      <div className="actions">
        <button type="button" className="btn btn--secondary" onClick={onBack}>Cancel</button>
        <button type="submit" className="btn btn--primary" disabled={!pw}>
          <IconUnlock size={13} /> Decrypt File
        </button>
      </div>
    </form>
  )
}
