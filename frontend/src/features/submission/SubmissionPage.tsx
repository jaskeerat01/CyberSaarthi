import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { createScan } from '../../shared/api';
import HelplineBanner from '../../shared/HelplineBanner';

const MAX_CHARS = 5000;

export default function SubmissionPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [content, setContent] = useState('');
  const [ack, setAck] = useState(false);
  const [lostMoney, setLostMoney] = useState(false);
  const [error, setError] = useState('');

  const mutation = useMutation({
    mutationFn: () => createScan(content, lostMoney),
    onSuccess: (data) => navigate(`/scan/${data.scan_id}`),
    onError: () => setError(t('error.generic')),
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || !ack) {
      setError(t('validation.required'));
      return;
    }
    mutation.mutate();
  };

  return (
    <div>
      {lostMoney && <HelplineBanner />}
      <h1 className="text-2xl font-bold mb-4">{t('submit.title')}</h1>
      <form onSubmit={submit} className="space-y-4" aria-label={t('submit.title')}>
        <div>
          <label htmlFor="content" className="block text-sm font-medium mb-1">
            {t('submit.title')}
          </label>
          <textarea
            id="content"
            value={content}
            onChange={(e) => setContent(e.target.value)}
            maxLength={MAX_CHARS}
            rows={6}
            placeholder={t('submit.placeholder')}
            className="w-full border rounded p-3"
            aria-describedby="char-count"
          />
          <p id="char-count" className="text-xs text-gray-500 mt-1">
            {content.length} / {MAX_CHARS}
          </p>
        </div>

        <div className="bg-yellow-50 border border-yellow-300 rounded p-3 text-sm">
          <p>{t('submit.privacy')}</p>
        </div>

        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={ack}
            onChange={(e) => setAck(e.target.checked)}
            className="mt-1"
          />
          <span className="text-sm">{t('submit.ack')}</span>
        </label>

        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={lostMoney}
            onChange={(e) => setLostMoney(e.target.checked)}
            className="mt-1"
          />
          <span className="text-sm">{t('submit.lostMoney')}</span>
        </label>

        {error && (
          <p role="alert" className="text-red-600 text-sm">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={mutation.isPending}
          className="bg-blue-600 text-white px-6 py-2 rounded disabled:opacity-50"
        >
          {mutation.isPending ? '…' : t('submit.button')}
        </button>
      </form>
    </div>
  );
}
