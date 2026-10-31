import { useEffect, useState } from 'react'
import { getKillSwitchStatus, activateKillSwitch, deactivateKillSwitch, KillSwitchStatus } from '../api/client'

export default function Settings() {
  const [status, setStatus] = useState<KillSwitchStatus | null>(null)
  const [scope, setScope] = useState('global')
  const [target, setTarget] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  function refresh() {
    getKillSwitchStatus().then(setStatus).catch(console.error)
  }

  useEffect(refresh, [])

  async function activate() {
    setBusy(true)
    try {
      await activateKillSwitch(scope, reason, target || undefined)
      setMessage('Kill-switch activated')
      refresh()
    } catch {
      setMessage('Error activating kill-switch')
    } finally {
      setBusy(false)
    }
  }

  async function deactivate() {
    setBusy(true)
    try {
      await deactivateKillSwitch(scope, target || undefined)
      setMessage('Kill-switch deactivated')
      refresh()
    } catch {
      setMessage('Error deactivating kill-switch')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <h2 className="text-xl font-semibold text-gray-800">Settings</h2>

      {/* Kill-switch status */}
      <div className={`rounded-lg border-2 p-4 ${status?.global ? 'border-red-500 bg-red-50' : 'border-gray-200 bg-white'}`}>
        <h3 className="font-semibold text-gray-800">Emergency Kill-Switch</h3>
        <p className="mt-1 text-sm text-gray-500">
          Status: <strong className={status?.global ? 'text-red-600' : 'text-green-600'}>
            {status?.global ? 'ACTIVE — all AI traffic blocked' : 'Inactive'}
          </strong>
        </p>
      </div>

      {/* Controls */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm space-y-3">
        <h3 className="font-semibold text-gray-700">Activate / Deactivate</h3>
        <div className="flex gap-3 flex-wrap">
          <select
            className="rounded border border-gray-300 px-3 py-1.5 text-sm"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
          >
            <option value="global">Global</option>
            <option value="org">Org</option>
            <option value="caller">Caller</option>
          </select>
          {scope !== 'global' && (
            <input
              className="rounded border border-gray-300 px-3 py-1.5 text-sm w-44"
              placeholder="Target ID…"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          )}
        </div>
        <input
          className="w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
          placeholder="Reason (required for activation)…"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <div className="flex gap-3">
          <button
            onClick={activate}
            disabled={busy || !reason}
            className="rounded bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-40"
          >
            🛑 Activate
          </button>
          <button
            onClick={deactivate}
            disabled={busy}
            className="rounded bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-40"
          >
            ✓ Deactivate
          </button>
        </div>
        {message && <p className="text-sm text-gray-600">{message}</p>}
      </div>
    </div>
  )
}
