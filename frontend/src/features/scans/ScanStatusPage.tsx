import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getScan } from '../../shared/api';
import { upsertHistory } from '../../shared/history';
import HelplineBanner from '../../shared/HelplineBanner';

export default function ScanStatusPage() {
  const { t } = useTranslation();
  const { scanId = '' } = useParams();
  const navigate = useNavigate();

  const { data, isError } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      return s === 'COMPLETED' || s === 'FAILED' ? false : 2000;
    },
  });

  useEffect(() => {
    if (!data) return;
    upsertHistory(scanId, data.status);
    if (data.status === 'COMPLETED') navigate(`/scan/${scanId}/result`);
  }, [data, navigate, scanId]);

  if (isError)
    return (
      <p role="alert" className="text-red-600">
        {t('error.generic')}
      </p>
    );
  if (!data) return <p aria-live="polite">{t('scan.pending')}</p>;

  const stageLabel =
    data.status === 'PENDING'
      ? t('scan.pending')
      : data.status === 'RUNNING'
        ? t('scan.running')
        : data.status === 'COMPLETED'
          ? t('scan.completed')
          : t('scan.failed');

  return (
    <div>
      {data.reported_financial_loss && <HelplineBanner />}
      <h1 className="text-2xl font-bold mb-4">{stageLabel}</h1>
      <ol className="list-decimal ml-6 space-y-1" aria-live="polite">
        <li>{t('scan.pending')}</li>
        <li>{t('scan.running')}</li>
        <li>{t('scan.completed')}</li>
      </ol>
      <p className="mt-4 text-sm text-gray-500">{data.status}</p>
    </div>
  );
}
