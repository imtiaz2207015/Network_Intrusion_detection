import { useEffect, useRef } from 'react';
import { api } from './api';
import { useAuth } from './AuthContext';

function loadScript() {
  return new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) return resolve();
    const existing = document.getElementById('gsi-script');
    if (existing) {
      existing.addEventListener('load', resolve);
      return;
    }
    const s = document.createElement('script');
    s.id = 'gsi-script';
    s.src = 'https://accounts.google.com/gsi/client';
    s.async = true;
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

export default function GoogleButton({ onSuccess, onError }) {
  const { googleLogin } = useAuth();
  const ref = useRef(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { client_id } = await api('/google-config');
        if (!client_id) return;
        await loadScript();
        if (cancelled || !ref.current) return;
        window.google.accounts.id.initialize({
          client_id,
          callback: async (resp) => {
            try {
              await googleLogin(resp.credential);
              onSuccess && onSuccess();
            } catch (err) {
              onError && onError(err.message);
            }
          },
        });
        window.google.accounts.id.renderButton(ref.current, {
          theme: 'filled_black',
          size: 'large',
          text: 'continue_with',
          shape: 'pill',
          width: 300,
        });
      } catch {
        onError && onError('Could not load Google sign-in');
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return <div ref={ref} style={{ display: 'flex', justifyContent: 'center', margin: '4px 0 14px' }} />;
}