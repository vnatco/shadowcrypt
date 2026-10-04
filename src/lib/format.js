export function formatBytes(b) {
  if (b == null) return '-'
  if (b < 1024) return `${b} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = b / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(1)} ${units[i]}`
}

/** Middle-truncate a file name, keeping its extension visible. */
export function shortName(name, max = 30) {
  if (!name || name.length <= max) return name
  const head = Math.ceil((max - 1) * 0.55)
  const tail = max - 1 - head
  return `${name.slice(0, head)}…${name.slice(-tail)}`
}

/** Extension label for the file header, e.g. "PDF". */
export function extLabel(name) {
  const i = name?.lastIndexOf('.') ?? -1
  return i > 0 ? name.slice(i + 1, i + 5).toUpperCase() : 'FILE'
}

const MESSAGES = {
  wrong_password: 'Incorrect Password',
  wrong_password_or_corrupt: 'Incorrect password, or the file is damaged',
  tampered: 'The file is damaged or has been modified. Nothing was saved.',
  truncated: 'The file is incomplete (truncated)',
  not_encrypted: "This file isn't in a supported encrypted format",
  unsupported_version: 'This file was made by a newer, unsupported version',
  permission_denied: "Can't write to this folder",
  busy: 'Another operation is still running',
}

/** Turn a backend error ({ code, message }) into a user-facing message. */
export function errorMessage(err) {
  if (!err) return 'Something went wrong'
  if (typeof err === 'string') return err
  return MESSAGES[err.code] ?? err.message ?? 'Something went wrong'
}

export const PHASE_LABELS = {
  deriving_key: 'Deriving Key…',
  encrypting: 'Encrypting…',
  decrypting: 'Decrypting…',
  finalizing: 'Verifying & Saving…',
}
