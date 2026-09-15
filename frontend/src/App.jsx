import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout } from './components/Layout';
import { OverviewPage } from './pages/OverviewPage';
import { LiveAttacksPage } from './pages/LiveAttacksPage';
import { DetectionAnalyticsPage } from './pages/DetectionAnalyticsPage';
import { CryptoAnalyticsPage } from './pages/CryptoAnalyticsPage';
import { SaheDecisionsPage } from './pages/SaheDecisionsPage';
import { BenchmarkResultsPage } from './pages/BenchmarkResultsPage';
import { FirewallActionsPage } from './pages/FirewallActionsPage';
import './components/layout.css';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/attacks" element={<LiveAttacksPage />} />
          <Route path="/detection" element={<DetectionAnalyticsPage />} />
          <Route path="/crypto" element={<CryptoAnalyticsPage />} />
          <Route path="/sahe" element={<SaheDecisionsPage />} />
          <Route path="/benchmarks" element={<BenchmarkResultsPage />} />
          <Route path="/firewall" element={<FirewallActionsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
