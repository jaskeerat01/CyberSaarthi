import { lazy, Suspense } from 'react';
import { Routes, Route, Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import SubmissionPage from './features/submission/SubmissionPage';
import ScanStatusPage from './features/scans/ScanStatusPage';

// The submission + status flow is the primary entry path, so it is bundled
// eagerly. Heavier secondary screens (evidence result, PDF report, history)
// load on demand, keeping the first paint small.
const ResultPage = lazy(() => import('./features/report/ResultPage'));
const ReportPage = lazy(() => import('./features/report/ReportPage'));
const HistoryPage = lazy(() => import('./features/scans/HistoryPage'));

export default function App() {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const toggle = () => i18n.changeLanguage(lang === 'en' ? 'hi' : 'en');

  return (
    <div className="min-h-screen bg-gray-50">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:bg-white focus:p-2">
        {t('a11y.skip')}
      </a>
      <header className="bg-white shadow-sm">
        <div className="max-w-3xl mx-auto px-4 py-3 flex justify-between items-center">
          <Link to="/" className="font-bold text-lg" aria-label={t('app.title')}>
            {t('app.title')}
          </Link>
          <div className="flex gap-4 items-center">
            <Link to="/history" className="text-sm underline">
              {t('nav.history')}
            </Link>
            <button
              onClick={toggle}
              aria-label={t('lang.switch')}
              className="text-sm border rounded px-2 py-1"
            >
              {lang === 'en' ? 'हिन्दी' : 'English'}
            </button>
          </div>
        </div>
      </header>
      <main id="main" className="max-w-3xl mx-auto px-4 py-6">
        <Suspense fallback={<p aria-live="polite">{t('scan.pending')}</p>}>
          <Routes>
            <Route path="/" element={<SubmissionPage />} />
            <Route path="/scan/:scanId" element={<ScanStatusPage />} />
            <Route path="/scan/:scanId/result" element={<ResultPage />} />
            <Route path="/scan/:scanId/report" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </Suspense>
      </main>
      <footer className="text-center text-xs text-gray-500 py-4">
        <p>
          Helpline: <strong>1930</strong> · Report:{' '}
          <a className="underline" href="https://cybercrime.gov.in">
            cybercrime.gov.in
          </a>
        </p>
      </footer>
    </div>
  );
}
