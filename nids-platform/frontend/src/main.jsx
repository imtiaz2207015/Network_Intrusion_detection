import '@fontsource/poppins/400.css';
import '@fontsource/poppins/500.css';
import '@fontsource/poppins/600.css';
import '@fontsource/poppins/700.css';
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import './theme.css'
import './responsive.css'
import './light.css'
import { applyTheme, getTheme } from './theme'
applyTheme(getTheme())

const vp = document.querySelector('meta[name="viewport"]');
if (vp) {
  vp.setAttribute('content', 'width=device-width, initial-scale=1, viewport-fit=cover');
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
