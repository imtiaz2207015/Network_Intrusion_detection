import { Link } from 'react-router-dom';
import { useAuth } from '../AuthContext';
import '../auth.css';

export default function NotFound() {
  const { token } = useAuth();
  return (
    <div className="au">
      <div className="au-box" style={{ textAlign: 'center' }}>
        <div style={{
          fontSize: 84, fontWeight: 800, lineHeight: 1, marginBottom: 8,
          background: 'linear-gradient(90deg,#22d3ee,#8b5cf6)',
          WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent',
        }}>404</div>
        <h2>Page not found</h2>
        <p className="au-sub">The page you're looking for doesn't exist or was moved.</p>
        <Link to={token ? '/' : '/home'} className="au-btn"
          style={{ display: 'block', textDecoration: 'none', boxSizing: 'border-box' }}>
          {token ? 'Back to dashboard' : 'Back to home'}
        </Link>
      </div>
    </div>
  );
}