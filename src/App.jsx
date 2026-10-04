import { useState, useEffect, useLayoutEffect, useRef, useCallback } from 'react'
import AppWindow from './components/AppWindow'
import DropScreen from './components/DropScreen'
import EncryptScreen from './components/EncryptScreen'
import DecryptScreen from './components/DecryptScreen'
import LoadingScreen from './components/LoadingScreen'
import SuccessScreen from './components/SuccessScreen'
import * as api from './lib/api'
import { errorMessage } from './lib/format'

const TITLES = {
  drop: 'ShadowCrypt',
  encrypt: 'ShadowCrypt - Encrypt',
  decrypt: 'ShadowCrypt - Decrypt',
  success: 'ShadowCrypt - Done',
}

// Errors where saving somewhere else might help.
const LOCATION_ERRORS = new Set(['permission_denied', 'insufficient_space', 'io'])

export default function App() {
  const [screen, setScreen] = useState('drop')
  const [file, setFile] = useState(null)
  const [mode, setMode] = useState('encrypt')
  const [progress, setProgress] = useState({ phase: null, percent: 0 })
  const [outcome, setOutcome] = useState(null)
  const [error, setError] = useState(null) // { message, action? }
  const [cancelling, setCancelling] = useState(false)
  const [dragging, setDragging] = useState(false)
  // Re-populates the form after a recoverable error so the user needn't retype.
  const [retryPassword, setRetryPassword] = useState('')
  // Bumped to remount the form (e.g. to apply retryPassword).
  const [formKey, setFormKey] = useState(0)

  const containerRef = useRef(null)
  const busyRef = useRef(false)
  const shownRef = useRef(false)

  /* ── Opening files ── */
  const openPath = useCallback(async path => {
    if (busyRef.current || !path) return
    try {
      const info = await api.inspectFile(path)
      setFile(info)
      setMode(info.encrypted ? 'decrypt' : 'encrypt')
      setScreen(info.encrypted ? 'decrypt' : 'encrypt')
      setError(null)
      setRetryPassword('')
      setFormKey(k => k + 1)
    } catch (e) {
      setFile(null)
      setScreen('drop')
      setError({ message: errorMessage(e) })
    }
  }, [])

  const checkPending = useCallback(async () => {
    if (busyRef.current) return
    try {
      const f = await api.takePendingFile()
      if (f) openPath(f.path)
    } catch (e) {
      setError({ message: errorMessage(e) })
    }
  }, [openPath])

  // Startup file (command line / "Open with") and files sent to the running app.
  useEffect(() => {
    checkPending()
    const un = api.onFileOpened(checkPending)
    return () => { un.then(f => f()) }
  }, [checkPending])

  // Native drag & drop (gives real file paths).
  useEffect(() => {
    const un = api.onDragDrop(e => {
      if (busyRef.current) return
      if (e.type === 'enter' || e.type === 'over') setDragging(true)
      else if (e.type === 'leave') setDragging(false)
      else if (e.type === 'drop') {
        setDragging(false)
        if (e.paths?.length) openPath(e.paths[0])
      }
    })
    return () => { un.then(f => f()) }
  }, [openPath])

  /* ── Window sizing: fit the window to the content, show it once laid out ── */
  useLayoutEffect(() => {
    const el = containerRef.current
    if (!el) return
    const sync = () => {
      const h = el.offsetHeight
      if (h > 20) {
        api.windowApi.setHeight(h)
          .catch(e => console.error('Resizing the window failed:', e))
          .finally(() => {
            if (shownRef.current) return
            shownRef.current = true
            api.windowApi.show().catch(e => console.error('Showing the window failed:', e))
          })
      }
    }
    sync()
    const ro = new ResizeObserver(sync)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const title = screen === 'loading'
    ? (mode === 'encrypt' ? 'ShadowCrypt - Encrypting…' : 'ShadowCrypt - Decrypting…')
    : TITLES[screen]
  useEffect(() => {
    api.windowApi.setTitle(title).catch(e => console.error('Setting the window title failed:', e))
  }, [title])

  /* ── Actions ── */
  const reset = useCallback(() => {
    setFile(null)
    setOutcome(null)
    setError(null)
    setRetryPassword('')
    setProgress({ phase: null, percent: 0 })
    setScreen('drop')
    // A file may have arrived while we were busy.
    setTimeout(checkPending, 0)
  }, [checkPending])

  const runJob = useCallback(async (password, outputDir = null) => {
    if (busyRef.current || !file) return
    busyRef.current = true
    setError(null)
    setCancelling(false)
    setProgress({ phase: null, percent: 0 })
    setScreen('loading')

    const job = mode === 'encrypt' ? api.encryptFile : api.decryptFile
    try {
      const result = await job(file.path, password, outputDir, setProgress)
      setOutcome(result)
      setRetryPassword('')
      setScreen('success')
    } catch (e) {
      if (e?.code === 'cancelled') {
        busyRef.current = false
        reset()
        return
      }
      const retry = LOCATION_ERRORS.has(e?.code)
      setError({
        message: errorMessage(e),
        action: retry && {
          label: 'Save to Another Folder…',
          onClick: async () => {
            try {
              const dir = await api.pickFolder()
              if (dir) runJob(password, dir)
            } catch (err) {
              setError({ message: errorMessage(err) })
            }
          },
        },
      })
      // Keep the password for errors unrelated to it; a wrong one is selected for retyping.
      setRetryPassword(password)
      setFormKey(k => k + 1)
      setScreen(mode)
    } finally {
      busyRef.current = false
      setCancelling(false)
    }
  }, [file, mode, reset])

  const cancel = useCallback(() => {
    setCancelling(true)
    api.cancelJob().catch(e => {
      setCancelling(false)
      console.error('Cancel failed:', e)
    })
  }, [])

  const browse = useCallback(async () => {
    try {
      const p = await api.pickFile()
      if (p) openPath(p)
    } catch (e) {
      setError({ message: errorMessage(e) })
    }
  }, [openPath])

  // Esc goes back from forms and closes the success screen.
  useEffect(() => {
    const onKey = e => {
      if (e.key !== 'Escape') return
      if (screen === 'encrypt' || screen === 'decrypt' || screen === 'success') reset()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [screen, reset])

  const formProps = {
    file,
    initialPassword: retryPassword,
    error: error?.message,
    errorAction: error?.action || null,
    onBack: reset,
    onSubmit: password => runJob(password),
  }

  return (
    <div ref={containerRef}>
      <AppWindow title={title} mode={mode}>
        {screen === 'drop' && <DropScreen dragging={dragging} error={error?.message} onBrowse={browse} />}
        {screen === 'encrypt' && <EncryptScreen key={formKey} {...formProps} />}
        {screen === 'decrypt' && <DecryptScreen key={formKey} {...formProps} />}
        {screen === 'loading' && (
          <LoadingScreen mode={mode} file={file} progress={progress} cancelling={cancelling} onCancel={cancel} />
        )}
        {screen === 'success' && outcome && (
          <SuccessScreen
            mode={mode}
            outcome={outcome}
            onReveal={() => api.revealInFolder(outcome.outputPath)}
            onDone={reset}
          />
        )}
      </AppWindow>
    </div>
  )
}
