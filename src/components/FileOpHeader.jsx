import { IconX } from './Icons'
import { formatBytes, shortName, extLabel } from '../lib/format'

export default function FileOpHeader({ file, mode, onClose }) {
  return (
    <div className="filehead">
      <div className="filehead__ext">{extLabel(file?.name)}</div>
      <div className="filehead__divider" />
      <div className="filehead__info">
        <div className="filehead__name" title={file?.path}>{shortName(file?.name ?? 'file')}</div>
        <div className="filehead__meta">
          <span>{formatBytes(file?.size)}</span>
          <span>·</span>
          <span className="filehead__mode">
            {mode === 'encrypt' ? 'Encrypt' : `Decrypt${file?.format ? ` · ${file.format}` : ''}`}
          </span>
        </div>
      </div>
      {onClose && (
        <button type="button" className="filehead__close" onClick={onClose} title="Back (Esc)" aria-label="Back">
          <IconX size={10} />
        </button>
      )}
    </div>
  )
}
