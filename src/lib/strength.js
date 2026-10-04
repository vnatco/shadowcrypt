// Password strength via zxcvbn-ts. The dictionaries are large, so they are
// loaded lazily the first time a password is scored.
let loader = null

function load() {
  loader ??= Promise.all([
    import('@zxcvbn-ts/core'),
    import('@zxcvbn-ts/language-common'),
    import('@zxcvbn-ts/language-en'),
  ]).then(([core, common, en]) => {
    core.zxcvbnOptions.setOptions({
      dictionary: { ...common.dictionary, ...en.dictionary },
      graphs: common.adjacencyGraphs,
      translations: en.translations,
    })
    return core.zxcvbn
  })
  return loader
}

/** @returns {Promise<{ score: 0|1|2|3|4, warning: string, crackTime: string }>} */
export async function scorePassword(pw) {
  const zxcvbn = await load()
  // zxcvbn's cost grows with length; the tail of a very long password adds nothing.
  const r = zxcvbn(pw.slice(0, 100))
  return {
    score: r.score,
    warning: r.feedback.warning || r.feedback.suggestions[0] || '',
    crackTime: r.crackTimesDisplay.offlineSlowHashing1e4PerSecond,
  }
}

export const STRENGTH_LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']
