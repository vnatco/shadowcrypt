// Thin wrapper around the Tauri backend so components never touch IPC directly.
import { invoke, Channel } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow, LogicalSize } from '@tauri-apps/api/window'
import { getCurrentWebview } from '@tauri-apps/api/webview'
import { open } from '@tauri-apps/plugin-dialog'

const win = getCurrentWindow()

/** @typedef {{ path: string, name: string, size: number, encrypted: boolean, format: string | null }} FileInfo */
/** @typedef {{ outputPath: string, outputName: string, format: string }} Outcome */

/** @returns {Promise<FileInfo>} */
export const inspectFile = path => invoke('inspect_file', { path })

/** @returns {Promise<FileInfo | null>} */
export const takePendingFile = () => invoke('take_pending_file')

function runJob(command, path, password, outputDir, onProgress) {
  const channel = new Channel()
  channel.onmessage = onProgress
  return invoke(command, { path, password, outputDir: outputDir ?? null, onProgress: channel })
}

/** @returns {Promise<Outcome>} */
export const encryptFile = (path, password, outputDir, onProgress) =>
  runJob('encrypt_file', path, password, outputDir, onProgress)

/** @returns {Promise<Outcome>} */
export const decryptFile = (path, password, outputDir, onProgress) =>
  runJob('decrypt_file', path, password, outputDir, onProgress)

export const cancelJob = () => invoke('cancel')
export const revealInFolder = path => invoke('reveal', { path })

/** Ask the user for a file; returns its path or null. */
export async function pickFile() {
  const p = await open({ multiple: false, directory: false, title: 'Select a file to encrypt or decrypt' })
  return typeof p === 'string' ? p : null
}

/** Ask the user for a folder; returns its path or null. */
export async function pickFolder() {
  const p = await open({ multiple: false, directory: true, title: 'Choose where to save the output' })
  return typeof p === 'string' ? p : null
}

/** OS asked us to open a file (second launch / "Open with" / macOS open event). */
export const onFileOpened = cb => listen('file-opened', cb)

/**
 * Native drag & drop. `cb` receives { type: 'enter' | 'over' | 'drop' | 'leave', paths? }.
 * Returns an unlisten function (as a promise).
 */
export const onDragDrop = cb => getCurrentWebview().onDragDropEvent(e => cb(e.payload))

export const windowApi = {
  show: () => win.show(),
  close: () => win.close(),
  minimize: () => win.minimize(),
  setTitle: t => win.setTitle(t),
  setHeight: h => win.setSize(new LogicalSize(400, Math.max(120, Math.ceil(h)))),
}
