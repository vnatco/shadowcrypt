import { IconX } from './Icons'

export default function ErrorBanner({ message, action }) {
  if (!message) return null
  return (
    <div className="banner banner--error" role="alert">
      <IconX size={11} />
      <div className="banner__body">
        <span>{message}</span>
        {action && <button type="button" className="banner__action" onClick={action.onClick}>{action.label}</button>}
      </div>
    </div>
  )
}
