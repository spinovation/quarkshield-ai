import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import QuantumRiskCalculator from './components/QuantumRiskCalculator';
import './index.css';
import { installAuthInterceptor } from './lib/authInterceptor';

// Redirect to sign-in on any /api 401 instead of showing demo data (DEF-55).
installAuthInterceptor();

// Standalone public tool page(s) render outside the App shell so they get a
// clean, shareable, SEO-friendly URL and don't load the console/landing state.
const p = window.location.pathname.toLowerCase().replace(/\/+$/, '');
const Root = (p === '/quantum-risk' || p === '/tools/quantum-risk')
  ? <QuantumRiskCalculator />
  : <App />;

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    {Root}
  </React.StrictMode>
);
