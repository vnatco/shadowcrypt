import { windowApi } from '../lib/api'

const IS_MAC = navigator.userAgent.includes('Mac')

export default function AppWindow({ title, mode, children }) {
  return (
    <div className="window" data-mode={mode}>
      <div className={`titlebar${IS_MAC ? ' titlebar--mac' : ''}`} data-tauri-drag-region>
        <div className="titlebar__title" data-tauri-drag-region>{title}</div>
        <div className="titlebar__controls">
          <button type="button" className="titlebar__btn titlebar__btn--min" onClick={() => windowApi.minimize().catch(e => console.error('Minimize failed:', e))} aria-label="Minimize">
            <svg width="10" height="10" viewBox="0 0 10 10"><line x1="0" y1="5" x2="10" y2="5" stroke="currentColor" /></svg>
          </button>
          <button type="button" className="titlebar__btn titlebar__btn--close" onClick={() => windowApi.close().catch(e => console.error('Close failed:', e))} aria-label="Close">
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
              <path d="M1 1l8 8M9 1l-8 8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
            </svg>
          </button>
        </div>
      </div>
      {children}
    </div>
  )
}
