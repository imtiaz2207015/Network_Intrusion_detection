import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './AuthContext';
import { sanitizeNextPath } from './utils';
import Layout from './Layout';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import BlockedIps from './pages/BlockedIps';
import Analytics from './pages/Analytics';
import ModelPerformance from './pages/ModelPerformance';
import Assistant from './pages/Assistant';
import SecurityChat from './pages/SecurityChat';
import Placeholder from './pages/Placeholder';
import Landing from './pages/Landing';
import Settings from './pages/Settings';
import Help from './pages/Help';
import NotFound from './pages/NotFound';

function Protected({ children }) {
  const { token } = useAuth();
  const { pathname, search, hash } = useLocation();
  if (token) return children;
  if (pathname === '/' && !search && !hash) {
    return <Navigate to="/home" replace />;
  }
  const intended = sanitizeNextPath(`${pathname}${search || ''}${hash || ''}`);
  try {
    sessionStorage.setItem('nids_next_path', intended);
  } catch { /* ignore */ }
  return <Navigate to={`/login?next=${encodeURIComponent(intended)}`} replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/home" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route element={<Protected><Layout /></Protected>}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/blocked" element={<BlockedIps />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/models" element={<ModelPerformance />} />
            <Route path="/assistant" element={<Assistant />} />
            <Route path="/chat" element={<SecurityChat />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/help" element={<Help />} />
            <Route path="/admin" element={<Placeholder title="Admin" note="User and role management arrive in Phase 7." />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
