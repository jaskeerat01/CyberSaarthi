import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { fetchReportPdf, getReportSignedUrl, getScan } from '../../shared/api';
import HelplineBanner from '../../shared/HelplineBanner';

export default function ReportPage() {
  const { t } = useTranslation();
  const { scanId = '' } = useParams();
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState(false);

  const { data, isError } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId),
  });
  const completed = data?.status === 'COMPLETED';

  const download = async () => {
    setDownloading(true);
    setError(false);
    try {
      // Step 1: mint a short-lived signed URL (expires in 15 minutes)
      const signed = await getReportSignedUrl(scanId);
      // Step 2: fetch the PDF bytes through the signed URL
      const blob = await fetchReportPdf(signed.url);
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = objectUrl;
      a.download = `cybersathi-${scanId}.pdf`;
      a.style.display = 'none';
      document.body.appendChild(a);
      try {
        a.click();
      } finally {
        a.remove();
        // Give the browser a moment to start the download before revoking.
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      }
    } catch {
      setError(true);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">{t('report.title')}</h1>
      <p className="bg-yellow-50 border border-yellow-300 rounded p-3 text-sm mb-4">
        {t('report.note')}
      </p>
      {data?.reported_financial_loss && <HelplineBanner />}
      <button
        onClick={download}
        disabled={downloading || !completed}
        className="bg-blue-600 text-white px-6 py-2 rounded disabled:opacity-50"
      >
        {downloading ? t('report.preparing') : t('report.download')}
      </button>
      {isError && (
        <p role="alert" className="mt-3 text-sm text-red-600">
          {t('error.generic')}
        </p>
      )}
      {error && (
        <p role="alert" className="mt-3 text-sm text-red-600">
          {t('error.generic')}
        </p>
      )}
    </div>
  );
}
