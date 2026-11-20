const storageKey = 'autotest.publicDemo'
const endpoint = '/api/public-demo'

class DemoRequestError extends Error {
  constructor(message, status = 0, code = '') {
    super(message)
    this.status = status
    this.code = code
  }
}

async function readEnvelope(response) {
  try {
    const envelope = await response.json()
    if (envelope && typeof envelope === 'object') return envelope
  } catch {
    // A platform error can return HTML or an empty body.
  }
  throw new DemoRequestError('The demo server returned an unreadable response.', response.status)
}

function responseError(response, envelope) {
  const detail = typeof envelope.detail === 'string' ? envelope.detail
    : response.status === 422 ? 'The demo workspace request was invalid.'
    : `The demo server returned HTTP ${response.status}.`
  return new DemoRequestError(detail, response.status, envelope.code)
}

function retryable(error) {
  return error instanceof TypeError || error.status === 429 || error.status >= 500
}

export function publicDemoTransport() {
  let state = ''
  let opened = false
  try { state = sessionStorage.getItem(storageKey) || '' } catch { /* Tab memory is enough. */ }
  let pending = Promise.resolve()

  function save(nextState) {
    state = nextState
    try { sessionStorage.setItem(storageKey, state) } catch { /* Keep the demo in memory. */ }
  }

  async function read(request, signal) {
    signal?.throwIfAborted()
    const response = await fetch(endpoint, { ...request, signal, cache: 'no-store', credentials: 'omit' })
    const envelope = await readEnvelope(response)
    signal?.throwIfAborted()
    if (typeof envelope.state === 'string' && envelope.state) save(envelope.state)
    if (!response.ok) throw responseError(response, envelope)
    if (envelope.file) {
      const bytes = Uint8Array.from(atob(envelope.file.body), character => character.charCodeAt(0))
      return new Blob([bytes], { type: envelope.file.type })
    }
    if (!Object.hasOwn(envelope, 'result')) {
      throw new DemoRequestError('The demo response did not contain workspace data.', response.status)
    }
    return envelope.result
  }

  function send(path, method, data, signal) {
    return read({
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, path, data, state }),
    }, signal)
  }

  async function fresh(signal) {
    try {
      return await read({ method: 'GET' }, signal)
    } catch (error) {
      signal?.throwIfAborted()
      if (!retryable(error)) throw error
      return read({ method: 'GET' }, signal)
    }
  }

  async function open(signal) {
    if (state) {
      try {
        return await send('/workspace', 'GET', undefined, signal)
      } catch (error) {
        signal?.throwIfAborted()
        if (retryable(error)) {
          try {
            return await send('/workspace', 'GET', undefined, signal)
          } catch {
            signal?.throwIfAborted()
          }
        }
      }
    }
    return fresh(signal)
  }

  async function execute(path, method, data, signal) {
    if (!opened && path === '/workspace' && method === 'GET') {
      const workspace = await open(signal)
      opened = true
      return workspace
    }
    try {
      return await send(path, method, data, signal)
    } catch (error) {
      if (error.code !== 'expired_demo') throw error
      await fresh(signal)
      return send(path, method, data, signal)
    }
  }

  return (path, method, data, signal) => {
    const request = pending.then(() => execute(path, method, data, signal))
    pending = request.catch(() => {})
    return request
  }
}
