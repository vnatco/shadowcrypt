import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import './app.css'

// Context menu only where it's useful (pasting into password fields).
document.addEventListener('contextmenu', e => {
  if (!(e.target instanceof HTMLInputElement)) e.preventDefault()
})

// Block browser shortcuts that would reload the page or open dev tools and lose
// the app's state mid-operation (Ctrl on Windows/Linux, Cmd on macOS).
if (!import.meta.env.DEV) {
  document.addEventListener('keydown', e => {
    const mod = e.ctrlKey || e.metaKey
    const k = e.key.toLowerCase()
    if (
      e.key === 'F5' || e.key === 'F7' || e.key === 'F12' ||
      (mod && (k === 'r' || k === 'p' || k === 'f' || k === 'g' || k === 'u' || k === 'j')) ||
      (mod && e.shiftKey && (k === 'i' || k === 'c'))
    ) e.preventDefault()
  })
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
)
