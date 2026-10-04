import { useState, useId } from 'react'
import { IconEye, IconCheck, IconX } from './Icons'

export default function PasswordField({ label, value, onChange, placeholder, match, autoFocus = false, inputRef }) {
  const [show, setShow] = useState(false)
  const [capsLock, setCapsLock] = useState(false)
  const id = useId()
  const checkCaps = e => setCapsLock(e.getModifierState?.('CapsLock') ?? false)

  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>{label}</label>
      <div className="field__box">
        <input
          id={id}
          ref={inputRef}
          className="field__input"
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          onKeyDown={checkCaps}
          onKeyUp={checkCaps}
          placeholder={placeholder}
          autoFocus={autoFocus}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          spellCheck={false}
        />
        {match != null && value && (
          <div className={`field__status field__status--${match ? 'ok' : 'bad'}`} aria-label={match ? 'Passwords Match' : "Passwords Don't Match"}>
            {match ? <IconCheck size={13} /> : <IconX size={13} />}
          </div>
        )}
        <button
          type="button"
          className="field__toggle"
          onClick={() => setShow(s => !s)}
          aria-label={show ? 'Hide Password' : 'Show Password'}
          title={show ? 'Hide Password' : 'Show Password'}
        >
          <IconEye size={14} closed={show} />
        </button>
      </div>
      {capsLock && <div className="field__hint">Caps Lock is On</div>}
    </div>
  )
}
