import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Overview from './pages/Overview'
import RequestExplorer from './pages/RequestExplorer'
import RequestDetail from './pages/RequestDetail'
import Analytics from './pages/Analytics'
import PolicyCenter from './pages/PolicyCenter'
import ShadowMode from './pages/ShadowMode'
import Settings from './pages/Settings'

const NAV = [
  { to: '/',          label: '📊 Overview' },
  { to: '/requests',  label: '🔍 Requests' },
  { to: '/analytics', label: '📈 Analytics' },
  { to: '/policies',  label: '📋 Policies' },
  { to: '/shadow',    label: '👁 Shadow Mode' },
  { to: '/settings',  label: '⚙️ Settings' },
]

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      end={to === '/'}
      className={({ isActive }) =>
        `block rounded-lg px-3 py-2 text-sm font-medium transition ${
          isActive
            ? 'bg-blue-600 text-white'
            : 'text-gray-600 hover:bg-gray-100'
        }`
      }
    >{label}</NavLink>
  )
}

export default function App() {
  return (
    <BrowserRouter basename="/dashboard">
      <div className="flex h-screen bg-gray-50">
        {/* Sidebar */}
        <aside className="w-52 flex-shrink-0 border-r border-gray-200 bg-white flex flex-col">
          <div className="border-b border-gray-100 px-4 py-4">
            <h1 className="text-lg font-bold text-gray-900">REVOC</h1>
            <p className="text-xs text-gray-400">AI Governance</p>
          </div>
          <nav className="flex-1 space-y-0.5 p-3">
            {NAV.map((n) => <NavItem key={n.to} {...n} />)}
          </nav>
          <div className="border-t border-gray-100 p-3">
            <p className="text-xs text-gray-400">revoc.io • Apache 2.0</p>
          </div>
        </aside>

        {/* Main */}
        <main className="flex-1 overflow-y-auto p-6">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/requests" element={<RequestExplorer />} />
            <Route path="/requests/:traceId" element={<RequestDetail />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/policies" element={<PolicyCenter />} />
            <Route path="/shadow" element={<ShadowMode />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
