const storageKey = 'autotest.publicDemo'

export function publicDemoTransport() {
  let state = ''
  try { state = sessionStorage.getItem(storageKey) || '' } catch { /* Tab memory is enough. */ }
  let pending = Promise.resolve()

  function save(nextState) {
    state = nextState
    try { sessionStorage.setItem(storageKey, state) } catch { /* Keep the demo in memory. */ }
  }

  async function send(path, method, data, signal, retry = true) {
    signal?.throwIfAborted()
    const response = await fetch('/api/public-demo', {
      method: 'POST', signal, credentials: 'omit', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, path, data, state }),
    })
    const envelope = await response.json()
    if (envelope.code === 'expired_demo' && retry) {
      save('')
      return send(path, method, data, signal, false)
    }
    if (envelope.state) save(envelope.state)
    if (!response.ok) throw new Error(typeof envelope.detail === 'string' ? envelope.detail : 'The demo request failed.')
    if (envelope.file) {
      const bytes = Uint8Array.from(atob(envelope.file.body), character => character.charCodeAt(0))
      return new Blob([bytes], { type: envelope.file.type })
    }
    return envelope.result
  }

  return (path, method, data, signal) => {
    const request = pending.then(() => send(path, method, data, signal))
    pending = request.catch(() => {})
    return request
  }
}
