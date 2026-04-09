import React from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Layout() {
  const { user, logout } = useAuth()

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">ShieldPay</div>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/customers">Customers</NavLink>
          <NavLink to="/cards">Cards</NavLink>
          <NavLink to="/transactions">Transactions</NavLink>
          <NavLink to="/payments/new">New payment</NavLink>
          <NavLink to="/settings">Settings</NavLink>
          {user?.role === 'admin' && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <div className="sidebar-footer">
          <div>{user?.email}</div>
          <button type="button" className="btn btn-ghost" style={{ marginTop: '0.5rem', width: '100%' }} onClick={logout}>
            Log out
          </button>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
