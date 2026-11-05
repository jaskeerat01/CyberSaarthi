import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { deleteScan } from '../../shared/api';
import { readHistory, removeHistory, type HistoryItem } from '../../shared/history';

/** Scan history stored only as IDs + status (never raw content). */
export default function HistoryPage() {
  const { t } = useTranslation();
  const [items, setItems] = useState<HistoryItem[]>(readHistory);
  const [error, setError] = useState(false);

  const remove = async (id: string) => {
    if (!window.confirm(t('history.delete') + '?')) return;
    setError(false);
    try {
      await deleteScan(id);
    } catch {
      // Keep the entry: the server still has it, so silently dropping it
      // locally would make the failure invisible to the user.
      setError(true);
      return;
    }
    removeHistory(id);
    setItems((current) => current.filter((item) => item.scan_id !== id));
  };

  if (!items.length) return <p>{t('history.empty')}</p>;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">{t('history.title')}</h1>
      {error && (
        <p role="alert" className="text-red-600 text-sm mb-3">
          {t('error.generic')}
        </p>
      )}
      <ul className="space-y-2">
        {items.map((item) => (
          <li key={item.scan_id} className="flex justify-between items-center border rounded p-3">
            <Link to={`/scan/${item.scan_id}`} className="underline text-sm">
              {item.scan_id.slice(0, 8)}… · {item.status}
            </Link>
            <button
              onClick={() => remove(item.scan_id)}
              className="text-sm text-red-600 border rounded px-2 py-1"
            >
              {t('history.delete')}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
