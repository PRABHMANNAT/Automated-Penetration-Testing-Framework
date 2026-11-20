import React, { useEffect, useRef, useState } from 'react'

const chapters = ['Scope', 'Replay', 'Process', 'Review', 'Report', 'Research']
const lead = 450

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    signal.throwIfAborted()
    const finish = () => {
      signal.removeEventListener('abort', abort)
      resolve()
    }
    const id = setTimeout(finish, ms)
    function abort() { clearTimeout(id); reject(signal.reason) }
    signal.addEventListener('abort', abort, { once: true })
  })
}

export function useGuidedDemo() {
  const control = useRef(null)
  const [guide, setGuide] = useState(null)

  function stop() {
    const active = control.current
    if (active) active.controller.abort()
    control.current = null
    setGuide(null)
  }

  function togglePause() {
    const active = control.current
    if (!active) return
    active.paused = !active.paused
    setGuide(item => ({ ...item, paused: active.paused }))
  }

  useEffect(() => () => control.current?.controller.abort(), [])

  async function play({ ws, api, navigate, select, updateRun, refresh }) {
    if (control.current) return
    const active = { controller: new AbortController(), paused: false }
    control.current = active
    const { signal } = active.controller
    let state = { chapter: 0, caption: 'Opening the approved Storefront fixture.', anchor: 'demo-start',
      phase: 'running', paused: false, form: null, tab: null, metric: null, stats: null }

    function show(patch) {
      signal.throwIfAborted()
      state = { ...state, ...patch }
      setGuide({ ...state, paused: active.paused })
    }

    async function wait(ms) {
      for (let remaining = ms; remaining > 0 || active.paused;) {
        await delay(100, signal)
        if (!active.paused) remaining -= 100
      }
      signal.throwIfAborted()
    }

    async function point(anchor, caption, patch = {}) {
      show({ anchor, caption, ...patch, pressed: false })
      await wait(lead)
      show({ pressed: true })
      await wait(180)
    }

    const request = (path, method = 'GET', data) => api(path, method, data, signal)
    try {
      show({})
      const now = Date.now()
      const approved = ws.authorizations.filter(item => item.asset === 'storefront' && item.path === '/shop'
        && item.status === 'Approved' && Date.parse(item.start) <= now && Date.parse(item.end) >= now)
      const authorization = approved.find(item => item.id === 'AUTH-1001') || approved[0]
      if (!authorization) throw new Error('The Storefront fixture needs a current, approved authorization.')
      const asset = ws.targets[authorization.asset]
      const target = `https://${asset.host}${authorization.path}`
      const badPort = `https://${asset.host}:8443${authorization.path}`
      const scope = { authorization: authorization.id, target }
      const form = { ...scope, name: 'Guided Storefront replay', profile: 'Full fixture', scanners: Object.keys(ws.tools).slice(1), result: null }
      await wait(350)
      navigate('scope')
      await point('scope-submit', 'Check the same fixture with an out-of-scope port.', { form: { ...form, target: badPort } })
      const rejected = await request('/scope', 'POST', { ...scope, target: badPort })
      if (rejected.passed) throw new Error('The out-of-scope example was unexpectedly accepted.')
      show({ form: { ...form, target: badPort, result: rejected }, caption: 'Port 8443 was rejected. The decision was recorded.' })
      await refresh(signal)
      await wait(1350)
      await point('scope-submit', 'Check the approved HTTPS port and path.', { form })
      const accepted = await request('/scope', 'POST', scope)
      if (!accepted.passed) throw new Error(accepted.reason)
      show({ form: { ...form, result: accepted }, caption: 'Scope accepted. The approved fixture can now be replayed.' })
      await refresh(signal)
      await wait(1050)

      navigate('new')
      await point('replay-submit', 'Start a replay with all three recorded detectors.', { chapter: 1, form })
      const { name, profile, scanners } = form
      let job = await request('/runs', 'POST', { ...scope, name, profile, scanners })
      select(job.id)
      updateRun(job)
      await refresh(signal)
      navigate('monitor')
      show({ form: null, anchor: 'live-progress', pressed: false, caption: 'Watch the pipeline advance and the observation count update.' })
      for (let attempts = 0; job.status === 'Running' && attempts < 35; attempts++) {
        await wait(450)
        job = await request(`/runs/${job.id}`)
        updateRun(job)
      }
      if (job.status !== 'Completed') throw new Error(`The guided replay ended with status ${job.status.toLowerCase()}.`)
      const observations = job.stages.raw.length
      const grouped = job.stages.findings.length
      const included = job.summary.total
      show({ stats: { observations, grouped, included }, caption: `${observations} recorded observations are ready for review.` })
      await refresh(signal)
      await wait(900)

      navigate('processing')
      const pipeline = [
        ['raw', `Open the ${observations} original observations.`],
        ['normalized', 'Map each adapter’s result to a common schema.'],
        ['dedup', `Group repeated observations into ${grouped} unique findings.`],
        ['verification', 'Read the recorded evidence check for each finding.'],
        ['filtering', `Hold ${grouped - included} low-confidence observations. ${included} remain in the report.`],
      ]
      for (const [tab, caption] of pipeline) {
        await point(`pipeline-${tab}`, caption, { chapter: 2 })
        show({ tab })
        await wait(680)
      }

      navigate('findings')
      const topFinding = job.stages.findings.find(item => item.included)
      await point(`finding-${topFinding.id}`, 'Open the top-ranked finding and its saved evidence.', { chapter: 3, tab: null })
      show({ finding: topFinding.id, anchor: 'finding-evidence' })
      await wait(1250)
      navigate('analysis')
      const verified = job.stages.findings.find(item => item.included && item.verification === 'Confirmed')
      await point(`review-${verified.id}`, 'Mark a verified example resolved in this demo replay.')
      job = await request(`/runs/${job.id}/findings/${verified.id}`, 'PATCH', { decision: 'Resolved' })
      updateRun(job)
      await refresh(signal)
      show({ caption: 'The resolved count increased. The decision is visible in the audit log.' })
      await wait(950)
      navigate('risk')
      await point('score-formula', 'Inspect how confidence, severity, and asset context determine rank.')
      await wait(1100)

      navigate('reports')
      await point('report-preview', 'Open the report preview with evidence and remediation.', { chapter: 4 })
      await wait(1000)
      navigate('audit')
      await point('audit-table', 'Review the scope and analyst decisions in the audit trail.')
      await wait(1000)
      navigate('research')
      await point('benchmark-metric', 'Compare the paper’s reported experiment with its baselines.', { chapter: 5 })
      show({ metric: 'Execution time', caption: 'Switch the chart to execution time. These values are from the paper.' })
      await wait(1350)

      await refresh(signal)
      navigate('dashboard')
      show({ phase: 'done', anchor: null, stats: { observations, grouped, included, resolved: job.summary.resolved },
        caption: `${job.id} added to the workspace with ${included} findings and ${job.summary.resolved} resolved.` })
    } catch (error) {
      if (!signal.aborted) show({ phase: 'error', anchor: null, form: null, tab: null, caption: error.message })
    } finally {
      if (control.current === active) control.current = null
    }
  }
  return { guide, play, stop, togglePause }
}

export function GuidedCursor({ guide }) {
  const cursor = useRef(null)
  const anchor = guide?.anchor
  useEffect(() => {
    if (!anchor) return
    let frame
    let attempts = 0
    let target
    function locate() {
      target = document.querySelector(`[data-guide="${anchor}"]`)
      if (!target) {
        if (attempts++ < 40) frame = requestAnimationFrame(locate)
        return
      }
      target.setAttribute('data-guide-focus', 'true')
      const rect = target.getBoundingClientRect()
      if (rect.top < 100 || rect.bottom > window.innerHeight - 145 || rect.left < 8 || rect.right > window.innerWidth - 8) {
        const motion = matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'
        target.scrollIntoView({ block: 'center', inline: 'nearest', behavior: motion })
      }
      update()
    }
    function update() {
      if (!target || !cursor.current) return
      const rect = target.getBoundingClientRect()
      const x = Math.min(window.innerWidth - 28, Math.max(6, rect.left + Math.min(rect.width / 2, 74)))
      const y = Math.min(window.innerHeight - 28, Math.max(6, rect.top + Math.min(rect.height / 2, 22)))
      cursor.current.style.transform = `translate3d(${x}px, ${y}px, 0)`
      cursor.current.style.opacity = '1'
    }
    locate()
    window.addEventListener('scroll', update, { passive: true, capture: true })
    window.addEventListener('resize', update)
    return () => {
      cancelAnimationFrame(frame)
      target?.removeAttribute('data-guide-focus')
      window.removeEventListener('scroll', update, true)
      window.removeEventListener('resize', update)
    }
  }, [anchor, guide?.form?.result])
  if (!anchor) return null
  return <div ref={cursor} className={`guided-cursor ${guide.pressed ? 'is-pressing' : ''}`} aria-hidden="true">
    <svg width="29" height="30" viewBox="0 0 28 30" fill="none"><path d="M3 2 24 17l-9 1-4 9L3 2Z" fill="#cafd75" stroke="#172018" strokeWidth="2" strokeLinejoin="round"/></svg>
    {guide.pressed && <i key={anchor}/>}
  </div>
}

export function GuideDock({ guide, stop, togglePause }) {
  if (!guide) return null
  const running = guide.phase === 'running'
  const title = running ? (guide.paused ? 'Demo paused' : 'Guided demo') : guide.phase === 'done' ? 'Demo complete' : 'Demo interrupted'
  return <aside className={`guide-dock ${running ? 'guide-running' : ''}`} aria-label="Guided demo controls">
    {running && <div className="guide-track" aria-hidden="true">{chapters.map((chapter, index) => <i key={chapter} className={index <= guide.chapter ? 'visited' : ''}/>)}</div>}
    <div className="guide-copy" role="status">
      <strong>{title}{running && <span>{chapters[guide.chapter]} · {guide.chapter + 1}/{chapters.length}</span>}</strong>
      <p>{guide.caption}</p>
      {guide.stats && <small>{guide.stats.observations} observations <b>→</b> {guide.stats.grouped} grouped <b>→</b> {guide.stats.included} included</small>}
    </div>
    <div className="guide-buttons">
      {running && <button type="button" onClick={togglePause}>{guide.paused ? 'Resume' : 'Pause'}</button>}
      <button type="button" onClick={stop}>{running ? 'Stop' : 'Close'}</button>
    </div>
  </aside>
}
