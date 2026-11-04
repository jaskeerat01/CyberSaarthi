import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { deleteScan } from '../../shared/api';

type HistoryItem = { scan_id: string; status: string; created?: string };

/** Scan history stored only as IDs + status (never raw content). */
export default function HistoryPage() {
  const { t } = useTranslation();
  const [items, setItems] = useState<HistoryItem[]>(() => {
    try {
      const raw = localStorage.getItem('cybersathi-history');
      return raw ? (JSON.parse(raw) as HistoryItem[]) : [];
    } catch {
      return [];
    }
  });

  const remove = async (id: string) => {
    if (!window.confirm(t('history.delete') + '?')) return;
    await deleteScan(id);
    const next = items.filter((i) => i.scan_id !== id);
    setItems(next);
    localStorage.setItem('cybersathi-history', JSON.stringify(next));
  };

  if (!items.length) return <p>{t('history.empty')}</p>;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">{t('history.title')}</h1>
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
