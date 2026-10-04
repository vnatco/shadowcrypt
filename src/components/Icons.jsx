export function IconLock({ size = 16, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      <rect x="3" y="7" width="10" height="8" rx="2" stroke={color} strokeWidth="1.4"/>
      <path d="M5 7V5a3 3 0 016 0v2" stroke={color} strokeWidth="1.4" strokeLinecap="round"/>
      <circle cx="8" cy="11" r="1.2" fill={color}/>
    </svg>
  )
}

export function IconUnlock({ size = 16, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      <rect x="3" y="7" width="10" height="8" rx="2" stroke={color} strokeWidth="1.4"/>
      <path d="M5 7V5a3 3 0 016 0" stroke={color} strokeWidth="1.4" strokeLinecap="round"/>
      <circle cx="8" cy="11" r="1.2" fill={color}/>
    </svg>
  )
}

export function IconFile({ size = 40, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none">
      <path d="M10 6h13l7 7v21a2 2 0 01-2 2H10a2 2 0 01-2-2V8a2 2 0 012-2z" stroke={color} strokeWidth="1.6"/>
      <path d="M23 6v8h7" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M14 20h12M14 26h8" stroke={color} strokeWidth="1.4" strokeLinecap="round"/>
    </svg>
  )
}

export function IconUpload({ size = 28, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" fill="none">
      <path d="M14 18V8M14 8l-4 4M14 8l4 4" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M5 20v1a2 2 0 002 2h14a2 2 0 002-2v-1" stroke={color} strokeWidth="1.6" strokeLinecap="round"/>
    </svg>
  )
}

export function IconEye({ size = 15, color = 'currentColor', closed = false }) {
  return closed ? (
    <svg width={size} height={size} viewBox="0 0 15 15" fill="none">
      <path d="M1 7.5C2.5 4 5 2 7.5 2S12.5 4 14 7.5C12.5 11 10 13 7.5 13S2.5 11 1 7.5z" stroke={color} strokeWidth="1.3"/>
      <path d="M3 3L12 12" stroke={color} strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ) : (
    <svg width={size} height={size} viewBox="0 0 15 15" fill="none">
      <path d="M1 7.5C2.5 4 5 2 7.5 2S12.5 4 14 7.5C12.5 11 10 13 7.5 13S2.5 11 1 7.5z" stroke={color} strokeWidth="1.3"/>
      <circle cx="7.5" cy="7.5" r="2" stroke={color} strokeWidth="1.3"/>
    </svg>
  )
}

export function IconShield({ size = 18, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 512 512" fill="none">
      <path d="M174 234L174 196A82 82 0 01338 196L338 234"
            stroke={color} strokeWidth="36" strokeLinecap="round"/>
      <rect x="108" y="246" width="296" height="212" rx="50"
            stroke={color} strokeWidth="36"/>
    </svg>
  )
}

export function IconX({ size = 12, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none">
      <path d="M2 2l8 8M10 2l-8 8" stroke={color} strokeWidth="1.4" strokeLinecap="round"/>
    </svg>
  )
}

export function IconCheck({ size = 12, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 12 12" fill="none">
      <path d="M2 6l3 3 5-5" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
}

export function IconFolder({ size = 16, color = 'currentColor' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="none">
      <path d="M2 4a1 1 0 011-1h3.586a1 1 0 01.707.293L8.414 4.5A1 1 0 009.121 4.793H13a1 1 0 011 1V12a1 1 0 01-1 1H3a1 1 0 01-1-1V4z" stroke={color} strokeWidth="1.3"/>
    </svg>
  )
}
