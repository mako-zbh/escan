import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { ToastProvider } from './components/Toast';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Templates from './pages/Templates';
import TemplateDetailPage from './pages/TemplateDetail';
import Scan from './pages/Scan';
import Vulnerabilities from './pages/Vulnerabilities';
import Config from './pages/Config';
import Proxy from './pages/Proxy';

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Dashboard />} />
            <Route path="/templates" element={<Templates />} />
            <Route path="/templates/:id" element={<TemplateDetailPage />} />
            <Route path="/scan" element={<Scan />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
            <Route path="/proxy" element={<Proxy />} />
            <Route path="/config" element={<Config />} />
          </Route>
        </Routes>
      </ToastProvider>
    </BrowserRouter>
  );
}
