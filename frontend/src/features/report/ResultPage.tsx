import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getScan, defang } from '../../shared/api';
import HelplineBanner from '../../shared/HelplineBanner';
import DefangedIndicators from '../../shared/DefangedIndicators';

const CLASSIFICATION_LABELS: Record<string, string> = {
  CONFIRMED_MALICIOUS: 'assessment.confirmed_malicious',
  HIGH_RISK: 'assessment.high_risk',
  SUSPICIOUS: 'assessment.suspicious',
  NO_KNOWN_THREAT_DETECTED: 'assessment.no_known_threat',
  INCONCLUSIVE: 'assessment.inconclusive',
};

/** Pull indicator values (domains…) out of the stored evidence structure. */
function extractIndicators(evidence: unknown): string[] {
  const out = new Set<string>();
  const visit = (node: unknown) => {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (!node || typeof node !== 'object') return;
    const record = node as Record<string, unknown>;
    if (Array.isArray(record.domains)) {
      record.domains.forEach((value) => {
        if (typeof value === 'string') out.add(value);
      });
    }
    // The API wraps evidence as {items: [...]}; older fixtures use a bare list.
    if (Array.isArray(record.items)) record.items.forEach(visit);
  };
  visit(evidence);
  return [...out];
}

/**
 * Defang domains inside the raw evidence dump as well: the backend stores
 * domains in `technical_evidence.items[].domains`, and the evidence <pre>
 * must not show copy-pasteable live URLs anywhere on the page.
 */
function defangDomains(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(defangDomains);
  if (!node || typeof node !== 'object') return node;
  const record = node as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    out[key] =
      key === 'domains' && Array.isArray(value)
        ? value.map((d) => (typeof d === 'string' ? defang(d) : d))
        : defangDomains(value);
  }
  return out;
}

export default function ResultPage() {
  const { t } = useTranslation();
  const { scanId = '' } = useParams();
  const [showRules, setShowRules] = useState(false);

  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId),
  });

  if (isLoading) return <p aria-live="polite">{t('scan.running')}</p>;
  if (isError || !data)
    return (
      <p role="alert" className="text-red-600">
        {t('error.generic')}
      </p>
    );
  // The result view only makes sense once the assessment exists; send the
  // user back to the status screen while a scan is still running or failed.
  if (data.status !== 'COMPLETED') return <Navigate to={`/scan/${scanId}`} replace />;

  const labelKey = CLASSIFICATION_LABELS[data.classification || ''] || 'assessment.inconclusive';
  const indicators = extractIndicators(data.technical_evidence);

  return (
    <div>
      {data.reported_financial_loss && <HelplineBanner />}
      <h1 className="text-2xl font-bold mb-2">{t(labelKey)}</h1>
      {data.confidence && (
        <p className="text-sm text-gray-600">
          {t('result.confidence')}: {data.confidence}
        </p>
      )}

      <DefangedIndicators values={indicators} />

      <section className="mt-4">
        <h2 className="font-semibold">{t('result.technicalEvidence')}</h2>
        <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
          {JSON.stringify(defangDomains(data.technical_evidence || {}), null, 2)}
        </pre>
        <h2 className="font-semibold mt-4">{t('result.socialEvidence')}</h2>
        <pre className="bg-gray-100 p-3 rounded text-xs overflow-auto">
          {JSON.stringify(data.social_engineering_evidence || {}, null, 2)}
        </pre>
      </section>

      <button
        onClick={() => setShowRules(!showRules)}
        className="mt-4 text-sm underline"
        aria-expanded={showRules}
      >
        {showRules ? t('result.hideRules') : t('result.showRules')}
      </button>
      {showRules && (
        <ul className="list-disc ml-6 mt-2 text-sm">
          {(data.rule_ids || []).map((r) => (
            <li key={r}>{r}</li>
          ))}
          <li>
            {t('result.ruleset')}: {data.ruleset_version}
          </li>
        </ul>
      )}

      <p className="mt-4 text-sm bg-gray-100 p-3 rounded">{t('result.disclaimer')}</p>
      {data.disclaimer && (
        <p role="note" className="mt-2 text-sm bg-yellow-50 border border-yellow-300 p-3 rounded">
          {data.disclaimer}
        </p>
      )}
      <p className="mt-2 text-sm">{t('result.nextSteps')}</p>

      <Link
        to={`/scan/${scanId}/report`}
        className="inline-block mt-4 bg-blue-600 text-white px-4 py-2 rounded"
      >
        {t('report.download')}
      </Link>
    </div>
  );
}
