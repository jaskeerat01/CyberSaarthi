import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { defang } from './api';

type Props = {
  /** Raw indicator values (URLs, domains, phone numbers, UPI IDs…). */
  values: string[];
};

/**
 * Shows extracted indicators in defanged form (hxxps://example[.]com) so the
 * user can read and copy them safely — never rendered as clickable links.
 */
export default function DefangedIndicators({ values }: Props) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);

  if (!values.length) return null;

  const defanged = values.map((v) => defang(v));

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(defanged.join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — user can still select the text manually */
    }
  };

  return (
    <section className="mt-4" aria-labelledby="defanged-heading">
      <div className="flex items-center gap-3">
        <h2 id="defanged-heading" className="font-semibold">
          {t('result.indicators')}
        </h2>
        <button
          onClick={copy}
          className="text-sm border rounded px-2 py-1"
          aria-label={t('result.copyIndicators')}
        >
          {copied ? t('result.copied') : t('result.copyIndicators')}
        </button>
      </div>
      <p className="text-xs text-gray-500 mt-1">{t('result.defangedNote')}</p>
      <ul className="mt-2 space-y-1 text-sm">
        {defanged.map((v) => (
          <li key={v} className="bg-gray-100 p-2 rounded font-mono break-all">
            {v}
          </li>
        ))}
      </ul>
    </section>
  );
}
