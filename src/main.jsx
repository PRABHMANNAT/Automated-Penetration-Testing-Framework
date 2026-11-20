import React, { useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { publicDemoTransport } from './demo-transport.js'
import { GuideDock, GuidedCursor, useGuidedDemo } from './guide.jsx'
import './style.css'
import './workbench.css'

const icons = {
  brand: 'M12 2 3 6v6c0 5 4 8 9 10 5-2 9-5 9-10V6l-9-4z M7 13l3 3 7-7',
  dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  key: 'M21 3l-2 2m-4 4 2 2 2-2-2-2m-2 2-3 3a5.5 5.5 0 1 1-2-2l7-7h4v4',
  shield: 'M12 2 4 6v6c0 4 3 8 8 10 5-2 8-6 8-10V6l-8-4z M8 12l3 3 5-6',
  plus: 'M12 5v14M5 12h14',
  radio: 'M5 19a10 10 0 1 1 14 0M8 16a6 6 0 1 1 8 0M12 12v9',
  layers: 'm12 3 9 5-9 5-9-5 9-5z M3 12l9 5 9-5 M3 16l9 5 9-5',
  pulse: 'M3 12h4l3-7 4 14 3-7h4',
  filter: 'M4 5h16l-6 7v6l-4 2v-8z',
  findings: 'M9 4h6l2 4v9l-3 3h-4l-3-3V8l2-4z M7 9H3m4 4H3m4 4H3m14-8h4m-4 4h4m-4 4h4m-9-7v10',
  bars: 'M4 20h16 M8 16v-5m4 5V5m4 11V8',
  report: 'M6 3h9l4 4v14H6z M14 3v5h5m-9 5h5m-5 4h5',
  history: 'M3 12a9 9 0 1 1 3 7M3 6v6h6m3-5v5l3 2',
  compare: 'M4 18h16M5 14l5-4 4 2 5-6m-4 0h4v4',
  audit: 'M9 5H5v16h14V5h-4M9 3h6v4H9z M8 12h8m-8 4h8',
  chevron: 'm9 6 6 6-6 6',
  down: 'm6 9 6 6 6-6',
  download: 'M12 4v11m-4-4 4 4 4-4M5 17v4h14v-4',
  check: 'm5 12 4 4L19 6',
  warning: 'M12 3 2 21h20L12 3z m0 6v4m0 4v.1',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7v6l4 2',
  terminal: 'M3 5h18v14H3z M7 9l3 3-3 3m6 0h4',
  menu: 'M4 6h16M4 12h16M4 18h16',
  close: 'm6 6 12 12M18 6 6 18',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
  search: 'M10 4a6 6 0 1 0 0 12 6 6 0 0 0 0-12zm5 11 5 5',
  logout: 'M11 4H4v16h7m3-4 4-4-4-4m-4 4h8',
  play: 'm8 4 12 8-12 8z',
}

function Icon({ name, size = 18 }) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round"><path d={icons[name]} /></svg>
}

const sections = [
  { label: 'Overview', route: 'dashboard', tabs: [['history', 'Replay history'], ['authorization', 'Authorizations'], ['audit', 'Audit log']] },
  { label: 'Replay', route: 'monitor', tabs: [['new', 'Setup'], ['scope', 'Scope check'], ['monitor', 'Monitor'], ['processing', 'Pipeline']], aliases: ['recon', 'scanners'] },
  { label: 'Results', route: 'findings', tabs: [['findings', 'Findings'], ['analysis', 'Review queue'], ['risk', 'Risk ranking'], ['reports', 'Report']] },
  { label: 'Research', route: 'research', tabs: [] },
]
const labels = {
  dashboard: 'Security assessment', authorization: 'Authorizations', scope: 'Scope check', new: 'Replay setup',
  monitor: 'Live replay', recon: 'Reconnaissance', scanners: 'Scanners', processing: 'Evidence pipeline',
  analysis: 'Analyst review', findings: 'Replay findings', risk: 'Risk ranking', reports: 'Assessment report',
  history: 'Replay history', audit: 'Audit log', research: 'Research evaluation',
}
const runPages = new Set(['monitor', 'recon', 'scanners', 'processing', 'analysis', 'findings', 'risk', 'reports'])
const bands = ['Critical', 'High', 'Medium', 'Low']
const palette = ['#b9483e', '#d08142', '#c6a34a', '#709484']
const fmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' })
const short = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })
const when = (value, compact = false) => value ? (compact ? short : fmt).format(new Date(value)) : '—'
const pct = value => `${Math.round(value * 100)}%`
const fixed = (value, digits = 3) => value == null ? '—' : value.toFixed(digits)
const pathFor = (target, path) => `https://${target.host}${path}`
const initials = name => name.split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase()

let demoRequest = null

async function api(path, method = 'GET', data, signal) {
  if (demoRequest && path !== '/session') return demoRequest(path, method, data, signal)
  const response = await fetch(`/api${path}`, {
    method, signal, credentials: 'same-origin',
    ...(data ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) } : {}),
  })
  if (response.ok && path.includes('/export/')) return response.blob()
  const body = await response.json()
  if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : 'Check the required fields and try again.')
  return body
}

function Button({ icon, secondary, children, ...props }) {
  return <button type="button" className={secondary ? 'button secondary' : 'button primary'} {...props}>{icon && <Icon name={icon} size={16}/>}<span>{children}</span></button>
}

function Badge({ children }) {
  const type = String(children).toLowerCase().replaceAll(' ', '-')
  return <span className={`badge badge-${type}`}>{children}</span>
}

function Panel({ title, detail, action, children, className = '' }) {
  return <section className={`panel ${className}`}>
    {title && <header className="panel-head"><div><h2>{title}</h2>{detail && <p>{detail}</p>}</div>{action}</header>}
    {children}
  </section>
}

function Empty({ children }) { return <div className="empty">{children}</div> }
function Notice({ children, error = false }) { return children ? <div role={error ? 'alert' : 'status'} className={`notice ${error ? 'error' : ''}`}><Icon name={error ? 'warning' : 'shield'} size={17}/><span>{children}</span></div> : null }
function Field({ label, hint, children }) { return <label className="field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label> }

function DataTable({ headers, rows, empty = 'There are no records to display.' }) {
  if (!rows.length) return <Empty>{empty}</Empty>
  return <div className="table-scroll"><table><thead><tr>{headers.map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
    <tbody>{rows.map(({ key, cells }) => <tr key={key}>{cells.map((cell, index) => <td key={index}>{cell}</td>)}</tr>)}</tbody></table></div>
}

function LoginScreen({ onLogin, hosted, startupError }) {
  const [mode, setMode] = useState('login')
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [busy, setBusy] = useState(false)
  async function submit(next, data) {
    setError('')
    setInfo('')
    setBusy(true)
    try {
      const result = await api(`/session/${next}`, 'POST', data)
      if (result.user) onLogin(result.user)
      if (result.recovery) {
        setInfo(`Account created. Save this local recovery code: ${result.recovery}`)
        setMode('login')
      }
      if (next === 'reset') {
        setInfo('Password updated. Sign in with your new password.')
        setMode('login')
      }
    } catch (cause) { setError(cause.message) } finally { setBusy(false) }
  }
  function switchMode(next) { setMode(next); setInfo(''); setError('') }
  return <main className="login-shell">
    <aside className="login-brand"><div className="logo"><span className="logo-icon"><Icon name="brand" size={22}/></span><span>AutoTest<small>Research workbench</small></span></div>
      <div><h1>Web security<br/>research workbench</h1><p>Replay the assessment pipeline, review the evidence, and compare the paper’s reported results.</p></div>
      <span className="local-label"><i/> {hosted ? 'Hosted fixture workspace' : 'Local fixture workspace'}</span>
    </aside>
    <section className="login-form">
      <h2>{mode === 'login' ? 'Sign in' : mode === 'register' ? 'Create an analyst account' : 'Reset your password'}</h2>
      <p>{hosted ? 'Enter the password configured for the hosted demo account.' : mode === 'login' ? 'Open the seeded workspace or use a local analyst account.' : mode === 'register' ? 'New accounts can request authorizations and review findings.' : 'Use the recovery code issued when you registered.'}</p>
      <Notice error>{startupError}</Notice>
      {!hosted && mode === 'login' && <Button icon="terminal" secondary disabled={busy || Boolean(startupError)} onClick={() => submit('demo')}>Open demo workspace</Button>}
      <form key={mode} className="stack" onSubmit={event => { event.preventDefault(); submit(mode, Object.fromEntries(new FormData(event.currentTarget))) }}>
        {mode === 'register' && <Field label="Full name"><input name="name" required minLength="2" maxLength="80" autoComplete="name"/></Field>}
        <Field label="Email address"><input name="email" type="email" defaultValue={hosted ? 'demo@autotest.test' : undefined} readOnly={hosted} required maxLength="150" autoComplete="username"/></Field>
        {mode === 'reset' && <Field label="Recovery code"><input name="recovery" minLength="8" maxLength="80" required/></Field>}
        <Field label={mode === 'reset' ? 'New password' : 'Password'}><input name="password" type="password" required minLength={mode === 'login' ? undefined : 8} maxLength="128" autoComplete={mode === 'login' ? 'current-password' : 'new-password'}/></Field>
        <Notice error>{error}</Notice><Notice>{info}</Notice>
        <Button type="submit" disabled={busy || Boolean(startupError)}>{mode === 'login' ? 'Sign in' : mode === 'register' ? 'Create account' : 'Update password'}</Button>
      </form>
      {!hosted && <div className="login-links">{mode === 'login' ? <><button onClick={() => switchMode('register')}>Create account</button><button onClick={() => switchMode('reset')}>Forgot password?</button></> : <button onClick={() => switchMode('login')}>Back to sign in</button>}</div>}
    </section>
  </main>
}

function RiskDistribution({ values }) {
  const total = bands.reduce((sum, name) => sum + (values[name] || 0), 0)
  let from = 0
  const segments = bands.map((name, index) => {
    const to = from + 100 * (values[name] || 0) / (total || 1)
    const segment = `${palette[index]} ${from}% ${to}%`
    from = to
    return segment
  })
  return <div className="risk-distribution">
    <div className="donut" role="img" aria-label={bands.map(name => `${name} ${values[name] || 0}`).join(', ')} style={{ background: total ? `conic-gradient(${segments.join(',')})` : '#edf0ed' }}>
      <div><strong>{total}</strong><span>Findings</span></div>
    </div>
    <div className="legend">{bands.map((name, index) => <div key={name}><i style={{ background: palette[index] }}/><span>{name}</span><strong>{values[name] || 0}</strong></div>)}</div>
  </div>
}

function RunsTable({ runs, open, compact = false }) {
  const headers = compact ? ['Replay', 'Status', 'Findings'] : ['Replay', 'Target', 'Status', 'Findings', 'Started']
  const rows = runs.map(run => {
    const name = <><button className="text-link row-title" onClick={() => open(run.id)}>{run.name}</button><small className="block mono">{run.id}</small></>
    const status = <Badge>{run.status}</Badge>
    const count = run.status === 'Running' ? '—' : run.summary.total
    const target = <span className="mono">{new URL(run.target).hostname}</span>
    const started = <span className="nowrap">{when(run.created, true)}</span>
    return { key: run.id, cells: compact ? [name, status, count] : [name, target, status, count, started] }
  })
  return <DataTable headers={headers} rows={rows}/>
}

function Dashboard({ ws, go, open, play, playing }) {
  const totals = ws.runs.reduce((sum, run) => {
    sum.total += run.summary.total
    sum.resolved += run.summary.resolved
    bands.forEach(band => { sum.bands[band] += run.summary.bands[band] })
    return sum
  }, { total: 0, resolved: 0, bands: Object.fromEntries(bands.map(band => [band, 0])) })
  const stats = [['Replays', ws.runs.length, 'history', 'Stored assessments'],
    ['Findings', totals.total, 'findings', 'Included in reports'],
    ['Critical findings', totals.bands.Critical, 'warning', 'Composite risk ≥ 0.75'],
    ['Resolved findings', totals.resolved, 'check', 'Marked by an analyst']]
  const latest = ws.runs[0]
  return <>
    <section className="overview-hero">
      <div className="hero-copy">
        <span className="hero-context"><Icon name="lock" size={13}/> {demoRequest ? 'Browser demo workspace' : ws.hosted ? 'Hosted evidence workspace' : 'Local evidence workspace'}</span>
        <h1>Security assessment</h1>
        <p>Follow the research pipeline from approved scope to ranked findings and an assessment report.</p>
        <div className="hero-actions">
          <Button icon="play" data-guide="demo-start" disabled={playing} onClick={play}>Auto-run demo</Button>
          <Button secondary onClick={() => go('new')}>Manual setup</Button>
        </div>
        <small>Recorded fixtures · zero target traffic</small>
      </div>
      <div className="hero-workflow">
        <div className="workflow-head"><span><Icon name="pulse" size={16}/> Replay workflow</span>{latest && <span className="workflow-id">{latest.id}</span>}</div>
        <div className="workflow-steps" aria-label="Assessment workflow">
          {[['shield', 'Scope'], ['layers', 'Replay'], ['filter', 'Triage'], ['report', 'Report']].map(([icon, label]) =>
            <div key={label}><span><Icon name={icon} size={20}/></span><strong>{label}</strong></div>)}
        </div>
        <div className="workflow-foot"><span>{latest ? 'Latest replay' : 'Replay status'}</span>{latest ? <Badge>{latest.status}</Badge> : <strong>Ready</strong>}</div>
      </div>
    </section>
    <section className="overview-activity">
      <div className="overview-heading"><h2>Workspace activity</h2><button type="button" className="text-link" onClick={() => go('history')}>Workspace records</button></div>
      <div className="stats" aria-label="Workspace statistics">{stats.map(([label, number, icon, note]) => <div className="stat" key={label}>
        <div className="stat-top"><span>{label}</span><span className={`stat-icon stat-${icon}`}><Icon name={icon} size={17}/></span></div>
        <strong key={number} className="stat-value">{number}</strong><small>{note}</small>
      </div>)}</div>
    </section>
    <div className="overview-grid">
      <Panel title="Recent replays" action={<button className="text-link" onClick={() => go('history')}>View all</button>}><RunsTable runs={ws.runs.slice(0, 3)} open={open} compact/></Panel>
      <Panel title="Risk distribution" detail="Findings across completed replays"><RiskDistribution values={totals.bands}/></Panel>
    </div>
  </>
}

function localInput(date) {
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
}

function Authorizations({ ws, refresh, go }) {
  const [creating, setCreating] = useState(false)
  const [asset, setAsset] = useState('storefront')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const target = ws.targets[asset]
  async function action(callback) {
    setError(''); setMessage(''); setBusy(true)
    try { setMessage(await callback()); await refresh() } catch (cause) { setError(cause.message) } finally { setBusy(false) }
  }
  return <>
    <Notice error>{error}</Notice><Notice>{message}</Notice>
    {creating && <Panel title="Register a scope" detail="Choose a fixture and the time window covered by the approval.">
      <form className="form-body" onSubmit={event => {
        event.preventDefault()
        const form = Object.fromEntries(new FormData(event.currentTarget))
        action(async () => {
          const item = await api('/authorizations', 'POST', { ...form, asset, criticality: Number(form.criticality), start: new Date(form.start).toISOString(), end: new Date(form.end).toISOString() })
          setCreating(false)
          return `${item.id} was submitted for administrator approval.`
        })
      }}>
        <div className="form-grid">
          <Field label="Fixture asset"><select value={asset} onChange={event => setAsset(event.target.value)}>{Object.entries(ws.targets).map(([id, item]) => <option key={id} value={id}>{item.name}</option>)}</select></Field>
          <Field label="Target owner"><input key={asset} name="owner" required minLength="2" maxLength="100" defaultValue={target.owner}/></Field>
          <Field label="Authorized domain"><input readOnly value={target.host}/></Field>
          <Field label="Approved path"><input key={asset + '-path'} name="path" required maxLength="150" defaultValue={target.path}/></Field>
          <Field label="Window opens" hint="Local time"><input name="start" type="datetime-local" defaultValue={localInput(new Date(Date.now() - 3600000))} required/></Field>
          <Field label="Window closes" hint="Local time"><input name="end" type="datetime-local" defaultValue={localInput(new Date(Date.now() + 86400000))} required/></Field>
          <Field label="Asset criticality" hint="Scale from 0 to 1"><input name="criticality" type="number" defaultValue=".75" min="0" max="1" step=".01" required/></Field>
          <Field label="Fixture address / port"><input readOnly value={`${target.ip} / ${target.port}`}/></Field>
        </div><div className="actions"><Button type="submit" icon="plus" disabled={busy}>Submit authorization</Button><Button secondary onClick={() => setCreating(false)}>Cancel</Button></div>
      </form>
    </Panel>}
    <Panel title="Authorization register" detail="Each replay is linked to an approved authorization." action={!creating && <Button icon="plus" onClick={() => setCreating(true)}>Register scope</Button>}>
      <DataTable headers={['Authorization / owner', 'Approved scope', 'Testing window', 'Approver', 'Status / decision']}
        rows={ws.authorizations.map(item => ({ key: item.id, cells: [
          <><strong className="mono">{item.id}</strong><small className="block">{item.owner}</small></>,
          <><span className="mono">{ws.targets[item.asset].host}</span><small className="block mono">{item.path} · {ws.targets[item.asset].ip}:{ws.targets[item.asset].port}</small></>,
          <><span className="nowrap">{when(item.start)}</span><small className="block nowrap">to {when(item.end)}</small></>,
          item.approver || '—',
          <div className="cell-actions"><Badge>{item.status}</Badge>{item.status === 'Pending' && ws.user.role === 'Admin' && ['Approved', 'Rejected'].map(status =>
            <button className="text-link" key={status} disabled={busy} onClick={() => action(async () => { await api(`/authorizations/${item.id}`, 'PATCH', { status }); return `${item.id} was ${status.toLowerCase()}.` })}>{status === 'Approved' ? 'Approve' : 'Reject'}</button>)}</div>,
        ] }))}/>
    </Panel>
    <Button secondary icon="shield" onClick={() => go('scope')}>Validate a target</Button>
  </>
}

function ScopeForm({ ws, refresh, start, isRun, guided }) {
  const options = ws.authorizations.filter(item => !isRun || item.status === 'Approved')
  const [authId, setAuthId] = useState(options[0]?.id || '')
  const selected = options.find(item => item.id === (guided?.authorization || authId))
  const target = selected && ws.targets[selected.asset]
  const [url, setUrl] = useState(() => selected ? pathFor(target, selected.path) : '')
  const [profile, setProfile] = useState(ws.profiles[0])
  const [scanners, setScanners] = useState(Object.keys(ws.tools).slice(1))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const shownResult = guided ? guided.result : result
  async function submit(event) {
    event.preventDefault()
    if (guided) return
    const form = new FormData(event.currentTarget)
    setBusy(true); setError(''); setResult(null)
    const scope = { authorization: authId, target: url.trim() }
    try {
      if (isRun) { await start({ ...scope, name: form.get('name'), profile, scanners }) }
      else { setResult(await api('/scope', 'POST', scope)); await refresh() }
    } catch (cause) { setError(cause.message); await refresh() } finally { setBusy(false) }
  }
  function choose(id) {
    const option = options.find(item => item.id === id)
    setAuthId(id); setUrl(option ? pathFor(ws.targets[option.asset], option.path) : '')
    setResult(null); setError('')
  }
  return <>
    <div className="form-layout">
      <Panel title={isRun ? 'Replay configuration' : 'Validate a target'} detail={isRun ? 'Select the scope and recorded detector outputs for this replay.' : 'Check the requested URL against an authorization record.'}>
        <form className="form-body" onSubmit={submit}>
          {isRun && <Field label="Replay name">{guided ? <input value={guided.name} readOnly/> : <input name="name" required minLength="2" maxLength="100" defaultValue="Fixture evidence review"/>}</Field>}
          <Field label="Authorization record"><select value={guided?.authorization ?? authId} onChange={event => choose(event.target.value)} required disabled={!options.length || !!guided}>
            {!options.length && <option value="">No available authorizations</option>}{options.map(item => <option key={item.id} value={item.id}>{item.id} · {ws.targets[item.asset].name} · {item.status}</option>)}
          </select></Field>
          <Field label="Requested target URL"><input type="url" value={guided?.target ?? url} readOnly={!!guided} onChange={event => setUrl(event.target.value)} required maxLength="300" placeholder="https://storefront.demo.test/shop"/></Field>
          {isRun && <>
            <Field label="Replay profile" hint={profile === 'Recorded scanner error' ? 'Nikto returns a saved timeout when selected.' : profile === 'Headers only' ? 'Replays observations related to response and cookie headers.' : 'Replays the full set of saved observations.'}><select value={guided?.profile ?? profile} disabled={!!guided} onChange={event => setProfile(event.target.value)}>{ws.profiles.map(name => <option key={name}>{name}</option>)}</select></Field>
            <fieldset><legend>Scanner evidence</legend><label className="checkbox"><input type="checkbox" checked disabled/> Nmap <small>Reconnaissance</small></label>
              {Object.keys(ws.tools).slice(1).map(name => <label key={name} className="checkbox"><input type="checkbox" disabled={!!guided} checked={(guided?.scanners || scanners).includes(name)} onChange={event => setScanners(event.target.checked ? [...scanners, name] : scanners.filter(item => item !== name))}/> {name}</label>)}
            </fieldset>
          </>}
          <Notice error>{error}</Notice>
          {shownResult && <Notice error={!shownResult.passed}>{shownResult.passed ? 'Accepted. Domain, port, path, approval, and testing window matched.' : `Rejected. ${shownResult.reason}`}</Notice>}
          <div className="actions"><Button data-guide={isRun ? 'replay-submit' : 'scope-submit'} aria-disabled={!!guided} type={guided ? 'button' : 'submit'} icon={isRun ? 'plus' : 'shield'} disabled={busy || !authId || (isRun && !scanners.length)}>{busy ? 'Checking…' : isRun ? 'Start replay' : 'Validate scope'}</Button></div>
        </form>
      </Panel>
      <Panel title="Selected scope" detail={selected ? selected.id : 'Choose an authorization'}>
        {selected ? <dl className="compact-details"><div><dt>Authorized domain</dt><dd className="mono">{target.host}</dd></div><div><dt>Allowed IP and port</dt><dd className="mono">{target.ip}:{target.port}</dd></div><div><dt>Approved path</dt><dd className="mono">{selected.path}</dd></div><div><dt>Testing window</dt><dd>{when(selected.start)}<small className="block">to {when(selected.end)}</small></dd></div><div><dt>Approval</dt><dd><Badge>{selected.status}</Badge></dd></div></dl> : <Empty>No scope is selected.</Empty>}
      </Panel>
    </div>
    {!isRun && <Panel title="Validation history"><DataTable headers={['Requested target', 'Authorization', 'Decision', 'Reason', 'Time']} rows={ws.validations.slice(0, 50).map(item => ({ key: item.id, cells: [<span className="mono">{item.target}</span>, item.authorization, <Badge>{item.passed ? 'Accepted' : 'Rejected'}</Badge>, item.reason || 'Scope matched', when(item.created, true)] }))}/></Panel>}
  </>
}

function RunSelector({ runs, id, select }) {
  return <label className="run-select"><span>Replay record</span><select value={id} onChange={event => select(event.target.value)}>
    {runs.map(run => <option key={run.id} value={run.id}>{run.name} · {run.id}</option>)}
  </select></label>
}

function Monitor({ run, go, ws }) {
  const events = run.logs
  return <>
    <Panel title={run.name} detail={`${run.id} · ${run.authorization}`} action={<Badge>{run.status}</Badge>}>
      <div className="monitor-body" data-guide="live-progress"><div className="progress-label"><strong>{run.stage}</strong><strong>{run.progress}%</strong></div>
        <progress max="100" value={run.progress} aria-label="Replay progress"/>
        <div className="monitor-meta"><div><span>Started</span><strong>{when(run.created)}</strong></div><div><span>Completed</span><strong>{when(run.completed)}</strong></div><div><span>Raw observations</span><strong>{run.observed}</strong></div><div><span>Included findings</span><strong>{run.completed ? run.summary.total : '—'}</strong></div></div>
      </div>
    </Panel>
    <div className="monitor-grid">
      <Panel title="Execution log" detail="Stages are replayed against recorded observations.">
        <ol className="timeline" aria-live="polite">{events.map((event, index) => <li key={event.stage}><span className="timeline-icon"><Icon name={index === events.length - 1 && run.status === 'Running' ? 'pulse' : 'check'} size={14}/></span><div><strong>{event.stage}</strong><p>{event.message}</p></div><time>{new Date(event.time).toLocaleTimeString()}</time></li>)}</ol>
      </Panel>
      <Panel title="Adapter activity" detail={run.tools.filter(tool => tool.status === 'Running').map(tool => tool.name).join(', ') || 'Recorded scanner timeline'}><div className="tool-list">
        {run.tools.map(tool => <div className="tool-line" key={tool.name}><span className="tool-icon"><Icon name="terminal" size={16}/></span><div><strong>{tool.name}</strong><small>{tool.error || (tool.seconds == null ? 'Fixture replay' : `${tool.seconds}s replay time`)}</small></div><Badge>{tool.status}</Badge></div>)}
      </div>{run.completed && run.status !== 'Failed' && <div className="panel-actions"><Button icon="findings" onClick={() => go('findings')}>Review findings</Button></div>}</Panel>
    </div>
    <details className="expand-panel"><summary>Recorded adapter and host details</summary><div><Scanners run={run} ws={ws}/><Recon run={run}/></div></details>
  </>
}

function Recon({ run }) {
  const host = run.recon
  if (!host) return <Panel title="Recorded host inventory"><Empty>Host inventory is available when reconnaissance completes.</Empty></Panel>
  return <>
    <Panel title="Recorded host inventory" detail="Nmap fixture · one discovered host" action={<Badge>Completed</Badge>}>
      <DataTable headers={['Host', 'Fixture IP', 'Port', 'Service', 'Technology', 'HTTP / HTTPS']} rows={[{key: host.host, cells: [<span className="mono">{host.host}</span>, <span className="mono">{host.ip}</span>, `${host.port}/tcp · open`, 'HTTPS', host.technology, 'HTTPS recorded · HTTP unobserved']}]}/>
    </Panel>
    <Panel title="Reconnaissance log"><DataTable headers={['Time', 'Source', 'Event']} rows={run.logs.filter(item => item.stage === 'Reconnaissance').map(item => ({ key: item.stage, cells: [when(item.time), 'Nmap fixture', item.message] }))}/></Panel>
  </>
}

function Scanners({ run, ws }) {
  return <Panel title="Scanner adapters" detail="Execution times are replay timings. Paper timings are in Paper evaluation.">
    <div className="scanner-cards">{Object.entries(ws.tools).map(([name, description]) => {
      const tool = run.tools.find(row => row.name === name)
      return <article className="scanner-card" key={name}><div className="scanner-card-top"><span className="stat-icon"><Icon name={name === 'Nmap' ? 'radio' : 'terminal'}/></span><Badge>{tool?.status || 'Skipped'}</Badge></div>
        <h3>{name}</h3><p>{description}</p><dl><div><dt>Replay time</dt><dd>{tool?.seconds == null ? '—' : `${tool.seconds}s`}</dd></div><div><dt>{name === 'Nmap' ? 'Hosts' : 'Observations'}</dt><dd>{tool?.count ?? '—'}</dd></div></dl>
        {tool?.error && <Notice error>{tool.error}</Notice>}
      </article>
    })}</div>
  </Panel>
}

function Processing({ run, guidedTab }) {
  const [tab, setTab] = useState('raw')
  const selectedTab = guidedTab || tab
  const { raw, normalized, findings } = run.stages
  const stages = [
    ['raw', 'Raw output', raw.length],
    ['normalized', 'Normalized', normalized.length],
    ['dedup', 'Deduplicated', findings.length],
    ['verification', 'Verification', findings.filter(item => item.verification === 'Confirmed').length],
    ['filtering', 'Held by filter', findings.filter(item => item.filtered).length],
  ]
  return <Panel title="Evidence pipeline" detail="Trace observations from each scanner through the result-processing stages.">
    <div className="tabs" aria-label="Processing stages">{stages.map(([id, title, count]) => <button key={id} data-guide={`pipeline-${id}`} aria-pressed={selectedTab === id} onClick={() => setTab(id)}>{title}<span>{count}</span></button>)}</div>
    {selectedTab === 'raw' && <DataTable headers={['Scanner', 'Recorded fields']} rows={raw.map((item, index) => ({key: index, cells: [item.scanner, <code className="wrap-code">{JSON.stringify(item.record)}</code>]}))}/>}
    {selectedTab === 'normalized' && <DataTable headers={['Finding', 'Target / endpoint', 'Parameter', 'CWE / CVE', 'Scanner', 'CVSS', 'Tool confidence']} rows={normalized.map((item, index) => ({key: index, cells: [item.title, <span className="mono">{item.target}{item.endpoint}</span>, item.parameter || '—', `${item.cwe} / ${item.cve || '—'}`, item.scanner, fixed(item.cvss, 1), pct(item.tool_confidence)]}))}/>}
    {selectedTab === 'dedup' && <DataTable headers={['Finding', 'Group key', 'Sources', 'Primary observation']} rows={findings.map(item => ({key: item.id, cells: [item.title, <span className="mono">{item.endpoint} · {item.parameter || '—'} · {item.cwe}</span>, item.sources.join(', '), `${item.scanner} · ${pct(item.tool_confidence)}`]}))}/>}
    {selectedTab === 'verification' && <DataTable headers={['Finding', 'Recorded outcome', 'Evidence summary']} rows={findings.map(item => ({key: item.id, cells: [item.title, <Badge>{item.verification}</Badge>, item.evidence]}))}/>}
    {selectedTab === 'filtering' && <DataTable headers={['Finding', 'Recorded confidence', 'Model decision', 'Analyst decision']} rows={findings.map(item => ({key: item.id, cells: [item.title, pct(item.gamma), <Badge>{item.filtered ? 'Held' : 'Retained'}</Badge>, item.review || 'Pending']}))}/>}
  </Panel>
}

function Analysis({ run, review }) {
  const [onlyHeld, setOnlyHeld] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(null)
  async function change(id, decision) {
    if (!decision) return
    setBusy(id); setError('')
    try { await review(id, decision) } catch (cause) { setError(cause.message) } finally { setBusy(null) }
  }
  const items = run.stages.findings
  return <>
    <div className="model-strip"><div><small>Classification model</small><strong>XGBoost gradient boosting</strong></div><div><small>Threshold</small><strong>γ &lt; 0.35</strong></div><div><small>Held by filter</small><strong>{items.filter(item => item.filtered).length} of {items.length}</strong></div></div>
    <Notice>The replay uses saved example probabilities. The threshold applies to observations without a conclusive confirmation.</Notice>
    <Notice error>{error}</Notice>
    <Panel title="Analyst review queue" detail="Decisions update the included findings and are recorded in the audit log." action={<label className="checkbox"><input type="checkbox" checked={onlyHeld} onChange={event => setOnlyHeld(event.target.checked)}/> Held only</label>}>
      <DataTable headers={['Finding', 'Classifier outcome', 'P(true) / P(false)', 'Verification / agreement', 'Analyst decision']} rows={items.filter(item => !onlyHeld || item.filtered).map(item => ({key: item.id, cells: [
        <><strong>{item.title}</strong><small className="block mono">{item.endpoint}</small></>,
        <Badge>{item.gamma < .35 ? 'Likely false positive' : 'Likely true positive'}</Badge>,
        <span className="nowrap">{pct(item.gamma)} / {pct(1 - item.gamma)}</span>, <>{item.verification}<small className="block">{item.sources.length} source{item.sources.length === 1 ? '' : 's'}</small></>,
        <div className="review-cell"><Badge>{item.review || (item.included ? 'Included' : 'Held')}</Badge><select data-guide={`review-${item.id}`} aria-label={`Review ${item.title}`} value="" disabled={busy !== null} onChange={event => change(item.id, event.target.value)}><option value="">Set decision</option><option>Confirmed</option><option>Dismissed</option>{item.included && <option>Resolved</option>}{item.review && <option>Clear</option>}</select></div>,
      ]}))}/>
    </Panel>
  </>
}

function FindingDetails({ item, onClose, go }) {
  useEffect(() => {
    function close(event) { if (event.key === 'Escape') onClose() }
    document.addEventListener('keydown', close)
    return () => document.removeEventListener('keydown', close)
  }, [onClose])
  return <Panel title={item.title} detail={item.endpoint} action={<button className="icon-button" onClick={onClose} aria-label="Close finding details"><Icon name="close"/></button>}>
    <div className="finding-detail">
      <div className="finding-tags"><Badge>{item.severity}</Badge><span className="mono">{item.cwe}</span><span>CVE {item.cve || 'unassigned'}</span><span>{item.sources.join(', ')}</span></div>
      <div className="finding-columns"><div><h3 data-guide="finding-evidence">Recorded evidence</h3><p>{item.evidence}</p><small>{item.verification} · {item.observations.length} recorded observation{item.observations.length === 1 ? '' : 's'}</small></div><div><h3>Recommended remediation</h3><p>{item.remediation}</p><Button secondary onClick={() => go('analysis')}>Open analyst review</Button></div></div>
    </div>
  </Panel>
}

function Findings({ run, go, guidedFinding }) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('All severities')
  const [selected, setSelected] = useState(null)
  const items = run.stages.findings.filter(item => item.included)
  const filtered = items.filter(item => (severity === 'All severities' || item.severity === severity)
    && `${item.title} ${item.endpoint} ${item.cwe} ${item.sources.join(' ')}`.toLowerCase().includes(search.toLowerCase().trim()))
  const selectedId = guidedFinding || selected
  const detail = items.find(item => item.id === selectedId)
  return <>
    <Panel title="Included findings" detail={`${items.length} findings · ordered by composite risk`}>
      <div className="filters"><label className="search"><Icon name="search" size={17}/><input value={search} onChange={event => setSearch(event.target.value)} aria-label="Search findings" placeholder="Search findings or endpoints"/></label>
        <select aria-label="Filter severity" value={severity} onChange={event => setSeverity(event.target.value)}>{['All severities', ...bands].map(value => <option key={value}>{value}</option>)}</select></div>
      <DataTable headers={['Finding', 'Endpoint', 'Severity', 'Risk', 'CVSS', 'Confidence', 'Review']} empty="No findings match the current view." rows={filtered.map(item => ({ key: item.id, cells: [
        <><button className="text-link row-title" data-guide={`finding-${item.id}`} aria-expanded={selectedId === item.id} onClick={() => setSelected(selectedId === item.id ? null : item.id)}>{item.title}</button><small className="block">{item.cwe} · {item.sources.join(', ')}</small></>,
        <span className="mono">{item.endpoint}</span>, <Badge>{item.severity}</Badge>, <strong className="mono">{fixed(item.score)}</strong>, fixed(item.cvss, 1), pct(item.gamma), item.review || 'Pending',
      ] }))}/>
    </Panel>
    {detail && <FindingDetails item={detail} onClose={() => setSelected(null)} go={go}/>}
  </>
}

function Risk({ run }) {
  const items = run.stages.findings.filter(item => item.included)
  const [selection, setSelection] = useState('')
  const item = items.find(row => row.id === selection) || items[0]
  return <>
    <div className="dashboard-grid">
      <Panel title="Risk distribution" detail={`Composite bands · ${run.id}`}><RiskDistribution values={run.summary.bands}/></Panel>
      <Panel title="Score calculation" detail="Equation 2 · confidence-weighted composite">
        <div className="formula"><code data-guide="score-formula">R = γ × (0.40C + 0.25E + 0.20A + 0.15B)</code>
          <p>CVSS is divided by 10. Exploit factor, asset criticality, business impact, and confidence are on a 0–1 scale.</p>
          {item && <><select aria-label="Finding to explain" value={item.id} onChange={event => setSelection(event.target.value)}>{items.map(row => <option key={row.id} value={row.id}>{row.title}</option>)}</select>
            <code>{fixed(item.gamma, 2)} × (0.40 × {fixed(item.cvss / 10, 2)} + 0.25 × {fixed(item.exploit, 2)} + 0.20 × {fixed(item.asset_criticality, 2)} + 0.15 × {fixed(item.impact, 2)}) = <strong>{fixed(item.score)}</strong></code></>}
        </div>
      </Panel>
    </div>
    <Panel title="Risk ranking" detail="Critical ≥ 0.75 · High ≥ 0.55 · Medium ≥ 0.35 · Low < 0.35">
      <DataTable headers={['Rank', 'Finding', 'CVSS', 'Exploit factor', 'Asset', 'Impact', 'Confidence', 'Composite', 'Band']} rows={items.map((row, index) => ({key: row.id, cells: [
        index + 1, <strong>{row.title}</strong>, fixed(row.cvss, 1), fixed(row.exploit, 2), fixed(row.asset_criticality, 2), fixed(row.impact, 2), pct(row.gamma), <strong className="mono">{fixed(row.score)}</strong>, <Badge>{row.severity}</Badge>,
      ]}))}/>
    </Panel>
  </>
}

function Reports({ run, refresh }) {
  const available = ['Completed', 'Partial'].includes(run.status)
  const items = run.stages.findings.filter(item => item.included)
  const [error, setError] = useState('')
  async function download(format) {
    setError('')
    try {
      const url = URL.createObjectURL(await api(`/runs/${run.id}/export/${format}`))
      const anchor = Object.assign(document.createElement('a'), { href: url, download: `AutoTest-${run.id}.${format}` })
      anchor.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      await refresh()
    } catch (cause) { setError(cause.message) }
  }
  return <>
    <Notice error>{error}</Notice>
    <Panel title="Assessment report" detail={`${run.name} · ${run.authorization}`} action={available && <div className="header-actions"><Button secondary icon="download" onClick={() => download('html')}>Export HTML</Button><Button icon="download" onClick={() => download('pdf')}>Export PDF</Button></div>}>
      {available ? <div className="report-summary"><h3 data-guide="report-preview">Executive summary</h3><p>This {run.status.toLowerCase()} fixture replay has {items.length} included findings and {run.stages.findings.length - items.length} held or dismissed observations.</p><p className="mono">{run.target}</p><div className="finding-tags">{bands.map(band => <span key={band}><Badge>{band}</Badge> <strong>{run.summary.bands[band]}</strong></span>)}</div></div> : <Empty>{run.status === 'Failed' ? 'A failed replay has no report.' : 'The report becomes available when the replay finishes.'}</Empty>}
    </Panel>
    {available && <Panel title="Evidence and remediation"><div className="report-findings">{items.length ? items.map(item => <details key={item.id}><summary><strong>{item.title}</strong><Badge>{item.severity}</Badge></summary><div><p className="mono">{item.endpoint} · {item.cwe} · Risk {fixed(item.score)}</p><p><strong>Evidence.</strong> {item.evidence}</p><p><strong>Remediation.</strong> {item.remediation}</p></div></details>) : <Empty>No observations were included.</Empty>}</div></Panel>}
  </>
}

function Audit({ ws }) {
  const [filter, setFilter] = useState('All activity')
  const events = ws.audit.events.filter(item => filter === 'All activity' || (filter === 'Report access' ? item.action === 'Report exported' : item.action.startsWith('Scope')))
  return <Panel title="Workspace audit trail" detail={`${ws.database} · append-only event records with a verified hash chain`} action={<Badge>{ws.audit.valid ? 'Integrity verified' : 'Integrity check failed'}</Badge>}>
    <div className="filters"><select data-guide="audit-table" aria-label="Audit event filter" value={filter} onChange={event => setFilter(event.target.value)}>{['All activity', 'Report access', 'Scope decisions'].map(type => <option key={type}>{type}</option>)}</select></div>
    <DataTable headers={['Time', 'Actor', 'Action', 'Authorization', 'Replay', 'Details']} rows={events.map(item => ({key: item.seq, cells: [
      <span className="nowrap">{when(item.timestamp)}</span>, item.actor, <strong>{item.action}</strong>, <span className="mono">{item.authorization || '—'}</span>, <span className="mono">{item.run || '—'}</span>, item.detail,
    ]}))}/>
  </Panel>
}

function Research({ ws, guidedMetric }) {
  const [selectedMetric, setMetric] = useState('F1 score')
  const metric = guidedMetric || selectedMetric
  const metrics = {'Precision': 3, 'Recall': 4, 'F1 score': 5, 'False discovery rate': -1, 'Execution time': 6}
  const available = ws.benchmarks.filter(row => metric === 'Execution time' || row[1] != null)
  const max = metric === 'Execution time' ? 200 : 1
  const value = row => metric === 'False discovery rate' ? 1 - row[3] : row[metrics[metric]]
  return <>
    <Notice>Results from <cite>Design and Evaluation of an Automated Penetration Testing Framework for Web Applications</cite>. Local replays use a separate fixture dataset.</Notice>
    <div className="stats">{[['Pipeline F1', '0.821', 'Proposed configuration', 'compare'], ['False discovery rate', '15.8%', 'Proposed configuration', 'filter'], ['Mean execution time', '47.9 min', '± 4.1 min reported', 'clock'], ['Ranking agreement', '0.81', 'Spearman ρ · composite', 'bars']].map(([title, number, description, icon]) =>
      <div className="stat" key={title}><div className="stat-top"><span>{title}</span><span className="stat-icon"><Icon name={icon} size={17}/></span></div><strong>{number}</strong><small>{description}</small></div>)}</div>
    <Panel title="Baseline comparison" detail="Table IV · 240 ground-truth instances · five runs per configuration" action={<select data-guide="benchmark-metric" aria-label="Benchmark metric" value={metric} onChange={event => setMetric(event.target.value)}>{Object.keys(metrics).map(name => <option key={name}>{name}</option>)}</select>}>
      <div className="benchmark-bars">{available.map(row => <div key={row[0]}><span>{row[0]}</span><div className="bar-track"><div className={row[0] === 'Proposed pipeline' ? 'proposed' : ''} style={{ width: `${value(row) / max * 100}%` }}/></div><strong>{metric === 'Execution time' ? `${fixed(value(row), 1)} min` : fixed(value(row))}</strong></div>)}</div>
      <details className="table-disclosure"><summary>Benchmark data table</summary><DataTable headers={['Configuration', 'TP', 'FP', 'Precision', 'Recall', 'F1', 'FDR', 'Time (min)']} rows={ws.benchmarks.map(row => ({ key: row[0], cells: [
        <strong>{row[0]}</strong>, row[1] ?? '—', row[2] ?? '—', fixed(row[3]), fixed(row[4]), fixed(row[5]), row[3] == null ? '—' : fixed(1 - row[3]), `${row[6]} ± ${row[7]}`,
      ] }))}/></details>
    </Panel>
    <div className="dashboard-grid">
      <Panel title="Prioritization quality" detail="Section IV-D · compared with analyst triage order"><DataTable headers={['Ordering', 'Spearman ρ', 'nDCG@10']} rows={[
        { key: 'composite', cells: [<strong>Composite risk</strong>, '0.81', '0.88'] },
        { key: 'cvss', cells: ['CVSS base score', '—', '0.71'] },
      ]}/></Panel>
      <Panel title="False-positive classifiers" detail="Paper’s held-out split · false-positive class"><DataTable headers={['Model', 'F1 score', 'ROC-AUC']} rows={[
        { key: 'lr', cells: ['Logistic regression', '0.766', '0.842'] },
        { key: 'rf', cells: ['Random forest', '0.835', '0.897'] },
        { key: 'xgb', cells: [<strong>Gradient boosting</strong>, '0.858', '0.913'] },
      ]}/></Panel>
    </div>
    <details className="expand-panel"><summary>Detection by OWASP category</summary><div><Panel title="Category results" detail="Table III · F1 0.821 (95% bootstrap CI 0.794–0.848)">
      <DataTable headers={['OWASP category', 'Ground truth', 'TP', 'FP', 'FN', 'Precision', 'Recall']} rows={ws.categories.map(row => ({key: row[0], cells: [`${row[0]} · ${row[1]}`, ...row.slice(2, 6), fixed(row[6]), fixed(row[7])]}))}/>
    </Panel></div></details>
  </>
}

const descriptions = {
  authorization: 'Register fixture owners, approved scope, and permitted testing windows.',
  scope: 'Check the requested domain, port, and path before starting a replay.',
  new: 'Configure a scoped assessment using recorded scanner observations.',
  monitor: 'Follow scanner activity, evidence processing, and report availability.',
  recon: 'Inspect the recorded hosts, services, and web technology for this replay.',
  scanners: 'Review each adapter’s status, timing, observation count, and errors.',
  processing: 'Inspect how recorded observations become evidence-backed findings.',
  analysis: 'Compare model confidence with verification evidence and record analyst decisions.',
  findings: 'Review affected endpoints, severity, evidence, and remediation.',
  risk: 'See how confidence and asset context change the order of remediation.',
  reports: 'Preview and export a replay’s findings, evidence, and remediation.',
  history: 'Open completed replays or return to an assessment in progress.',
  audit: 'Trace authorization decisions, analyst actions, and report access.',
  research: 'Compare the results reported in the research paper across baseline configurations.',
}
const currentRoute = () => labels[location.hash.slice(1)] ? location.hash.slice(1) : 'dashboard'

function App() {
  const [user, setUser] = useState(undefined)
  const [hosted, setHosted] = useState(false)
  const [publicDemo, setPublicDemo] = useState(false)
  const [ws, setWs] = useState(null)
  const [page, setPage] = useState(currentRoute)
  const [runId, setRunId] = useState(() => sessionStorage.getItem('autotest.run') || '')
  const [run, setRun] = useState(null)
  const [error, setError] = useState('')
  const demo = useGuidedDemo()
  const { guide } = demo
  const playing = guide?.phase === 'running'
  const activeId = ws?.runs.some(item => item.id === runId) ? runId : ws?.runs[0]?.id || ''
  const activeRun = run?.id === activeId ? run : null
  const hasRunning = Boolean(ws?.runs.some(item => item.status === 'Running'))
  const section = sections.find(item => item.route === page || item.tabs.some(([route]) => route === page)
    || item.aliases?.includes(page))

  async function refresh(signal) {
    const data = await api('/workspace', 'GET', undefined, signal)
    signal?.throwIfAborted()
    setWs(data)
  }
  function go(to, replace = false) {
    if (currentRoute() !== to) {
      const hash = to === 'dashboard' ? '' : `#${to}`
      history[replace ? 'replaceState' : 'pushState'](null, '', location.pathname + location.search + hash)
      window.scrollTo(0, 0)
    }
    setPage(to)
    setError('')
  }
  function manualGo(to) {
    if (playing) demo.stop()
    go(to)
  }
  function select(id) { setRunId(id); sessionStorage.setItem('autotest.run', id); setError('') }
  function open(id) { select(id); manualGo('monitor') }
  function play() { demo.play({ ws, api, navigate: to => go(to, true), select, updateRun: setRun, refresh }) }
  async function start(data) {
    const job = await api('/runs', 'POST', data)
    await refresh()
    setRun(job)
    open(job.id)
  }
  async function review(id, decision) {
    setRun(await api(`/runs/${activeId}/findings/${id}`, 'PATCH', { decision }))
    await refresh()
  }
  async function logout() {
    demo.stop()
    try { await api('/session/logout', 'POST'); setUser(null); setWs(null); go('dashboard') }
    catch (cause) { setError(cause.message) }
  }
  useEffect(() => {
    const navigate = () => { demo.stop(); setPage(currentRoute()); setError(''); window.scrollTo(0, 0) }
    window.addEventListener('hashchange', navigate)
    window.addEventListener('popstate', navigate)
    api('/session').then(result => {
      setHosted(Boolean(result.hosted))
      setPublicDemo(Boolean(result.public_demo))
      demoRequest = result.public_demo ? publicDemoTransport() : null
      setUser(result.user)
    }).catch(cause => { setError(cause.message); setUser(null) })
    return () => {
      window.removeEventListener('hashchange', navigate)
      window.removeEventListener('popstate', navigate)
    }
  }, [])
  useEffect(() => {
    if (!user) return
    let live = true
    api('/workspace').then(result => { if (live) setWs(result) }).catch(cause => { if (live) setError(cause.message) })
    return () => { live = false }
  }, [user])
  useEffect(() => {
    if (playing || !user || !activeId || !runPages.has(page)) return
    let live = true
    let timer
    async function poll() {
      try {
        const item = await api(`/runs/${activeId}`)
        if (!live) return
        setRun(item)
        if (item.status === 'Running') timer = setTimeout(poll, 650)
      } catch (cause) { if (live) setError(cause.message) }
    }
    poll()
    return () => { live = false; clearTimeout(timer) }
  }, [activeId, page, playing, user])
  useEffect(() => {
    if (playing || !user || !hasRunning) return
    let live = true
    const timer = setInterval(async () => {
      try { const result = await api('/workspace'); if (live) setWs(result) }
      catch (cause) { if (live) setError(cause.message) }
    }, 1650)
    return () => { live = false; clearInterval(timer) }
  }, [hasRunning, playing, user])

  if (user === undefined) return <main className="loading">Opening AutoTest…</main>
  if (!user) return <LoginScreen hosted={hosted} startupError={error} onLogin={result => { setError(''); setUser(result) }}/>
  if (!ws) return <main className="loading"><Notice error>{error}</Notice>{!error && 'Loading the workspace…'}{error && (publicDemo ? <Button secondary onClick={() => location.reload()}>Reload demo</Button> : <Button secondary onClick={logout}>Return to sign in</Button>)}</main>

  function content() {
    switch (page) {
      case 'dashboard': return <Dashboard ws={ws} go={manualGo} open={open} play={play} playing={playing}/>
      case 'authorization': return <Authorizations ws={ws} refresh={refresh} go={manualGo}/>
      case 'scope': return <ScopeForm key="scope" ws={ws} refresh={refresh} guided={playing ? guide.form : null}/>
      case 'new': return <ScopeForm key="new" ws={ws} refresh={refresh} start={start} guided={playing ? guide.form : null} isRun/>
      case 'history': return <Panel title="Assessment records" detail={`${ws.runs.length} stored replays`}><RunsTable runs={ws.runs} open={open}/></Panel>
      case 'audit': return <Audit ws={ws}/>
      case 'research': return <Research ws={ws} guidedMetric={playing ? guide.metric : null}/>
      default:
        if (!activeRun) return <Panel><Empty>{activeId ? 'Loading replay record…' : 'Start a replay to view this section.'}</Empty></Panel>
        switch (page) {
          case 'monitor': return <Monitor run={activeRun} go={manualGo} ws={ws}/>
          case 'recon': return <Recon run={activeRun}/>
          case 'scanners': return <Scanners run={activeRun} ws={ws}/>
          case 'processing': return <Processing key={activeId} run={activeRun} guidedTab={playing ? guide.tab : null}/>
          case 'analysis': return <Analysis key={activeId} run={activeRun} review={review}/>
          case 'findings': return <Findings key={activeId} run={activeRun} go={manualGo} guidedFinding={playing ? guide.finding : null}/>
          case 'risk': return <Risk key={activeId} run={activeRun}/>
          case 'reports': return <Reports key={activeId} run={activeRun} refresh={refresh}/>
        }
    }
  }

  return <div className={`workbench-shell ${guide ? 'has-guide' : ''}`}>
    <a className="skip-link" href="#main-content" onClick={event => { event.preventDefault(); document.getElementById('main-content').focus() }}>Skip to content</a>
    <header className="masthead">
      <div className="mast-inner">
        <button className="logo" onClick={() => manualGo('dashboard')} aria-label="AutoTest home"><span className="logo-icon"><Icon name="brand" size={20}/></span><span>AutoTest</span></button>
        <nav className="main-nav" aria-label="Main sections">{sections.map(item =>
          <button key={item.route} aria-current={section === item ? 'page' : undefined} onClick={() => manualGo(item.route)}>
            {item.label}{item.route === 'monitor' && hasRunning && <i className="running-dot"/>}
          </button>)}</nav>
        <div className="top-account">
          {page !== 'dashboard' && <Button data-guide="demo-start" disabled={playing} icon="play" secondary onClick={play}>Auto-run demo</Button>}
          {publicDemo ? <span className="public-demo-label">Demo</span> : <details className="account-menu"><summary aria-label="Account options"><span className="avatar">{initials(user.name)}</span><Icon name="down" size={13}/></summary>
            <div className="account-popup"><strong>{user.name}</strong><small>{user.email}</small><button className="text-link" onClick={logout}><Icon name="logout" size={16}/>Sign out</button></div>
          </details>}
        </div>
      </div>
    </header>
    <main id="main-content" className={`main-content ${page === 'dashboard' ? 'overview-content' : ''}`} tabIndex="-1">
      {page !== 'dashboard' && <>
        <div className="page-heading"><div><h1>{labels[page]}</h1><p>{descriptions[page]}</p></div>
          {runPages.has(page) && activeId && <RunSelector runs={ws.runs} id={activeId} select={id => { if (playing) demo.stop(); select(id) }}/>}
        </div>
        {section.tabs.length > 0 && <nav className="section-tabs" aria-label={`${section.label} views`}>{section.tabs.map(([route, label]) =>
          <button key={route} aria-current={route === page || (route === 'monitor' && section.aliases?.includes(page)) ? 'location' : undefined} onClick={() => manualGo(route)}>{label}</button>
        )}</nav>}
      </>}
      <Notice error>{error}</Notice>
      {content()}
    </main>
    <GuidedCursor guide={guide}/>
    <GuideDock guide={guide} stop={demo.stop} togglePause={demo.togglePause}/>
  </div>
}

createRoot(document.getElementById('root')).render(<App/>)
