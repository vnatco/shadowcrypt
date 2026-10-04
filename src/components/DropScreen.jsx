import { IconShield, IconFile, IconUpload } from './Icons'
import ErrorBanner from './ErrorBanner'

export default function DropScreen({ dragging, error, onBrowse }) {
  return (
    <div className="screen">
      <div className="brand">
        <div className="brand__logo"><IconShield size={16} /></div>
        <div>
          <div className="brand__name">ShadowCrypt</div>
          <div className="brand__tag">AES-256 FILE ENCRYPTION</div>
        </div>
      </div>

      <button type="button" className={`dropzone${dragging ? ' dropzone--active' : ''}`} onClick={onBrowse}>
        <div className="dropzone__icon">
          {dragging ? <IconFile size={28} /> : <IconUpload size={26} />}
        </div>
        <div>
          <div className="dropzone__title">{dragging ? 'Release to Select File' : 'Drag & Drop a File Here'}</div>
          <div className="dropzone__hint">or <em>Browse to Select</em></div>
        </div>
      </button>

      <ErrorBanner message={error} />

      <p className="footnote">
        Opens .aes files from every AES Crypt version
      </p>
    </div>
  )
}
