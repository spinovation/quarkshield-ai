import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';
import { installAuthInterceptor } from './lib/authInterceptor';

// Redirect to sign-in on any /api 401 instead of showing demo data (DEF-55).
installAuthInterceptor();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
