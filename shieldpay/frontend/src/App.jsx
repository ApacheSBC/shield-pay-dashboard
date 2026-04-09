import React from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './context/AuthContext.jsx'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Register from './pages/Register.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Customers from './pages/Customers.jsx'
import CustomerDetail from './pages/CustomerDetail.jsx'
import Cards from './pages/Cards.jsx'
import Transactions from './pages/Transactions.jsx'
import TransactionDetail from './pages/TransactionDetail.jsx'
import NewPayment from './pages/NewPayment.jsx'
import Admin from './pages/Admin.jsx'
import Settings from './pages/Settings.jsx'

function PrivateRoute({ children }) {
  const { isAuthenticated, ready } = useAuth()
  if (!ready) return <p style={{ color: 'var(--muted)', padding: '2rem' }}>Loading…</p>
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route
        path="/"
        element={
          <PrivateRoute>
            <Layout />
          </PrivateRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="customers" element={<Customers />} />
        <Route path="customers/:id" element={<CustomerDetail />} />
        <Route path="cards" element={<Cards />} />
        <Route path="transactions" element={<Transactions />} />
        <Route path="transactions/:id" element={<TransactionDetail />} />
        <Route path="payments/new" element={<NewPayment />} />
        <Route path="settings" element={<Settings />} />
        <Route path="admin" element={<Admin />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
