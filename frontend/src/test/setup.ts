import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

vi.mock('react-i18next', async () => {
  const actual = await vi.importActual<typeof import('react-i18next')>('react-i18next');
  return {
    ...actual,
    useTranslation: () => ({
      t: (key: string) => {
        // Mirrors src/i18n/index.ts (en) — keep in sync when adding keys.
        const map: Record<string, string> = {
          'submit.placeholder': 'Paste the suspicious message or URL here…',
          'submit.lostMoney': 'I have lost money in this incident',
          'submit.button': 'Check now',
          'submit.title': 'Check suspicious content',
          'submit.privacy': 'Privacy notice',
          'submit.ack': 'I have read and agree to the privacy notice',
          'validation.required': 'Please enter content and accept the privacy notice.',
          'error.generic': 'Something went wrong. Please try again.',
          'helpline.banner':
            'If you lost money, call the National Cyber Crime Helpline: 1930 — now.',
          'assessment.confirmed_malicious': 'This content matches verified threat intelligence.',
          'assessment.high_risk': 'Multiple independent signals suggest high risk.',
          'assessment.suspicious': 'Signals warrant caution. Do not click or share.',
          'assessment.no_known_threat':
            'No known threat detected. This is not a guarantee of safety.',
          'assessment.inconclusive': 'We could not reach a conclusion. Please be cautious.',
          'result.disclaimer': 'This assessment is not a guarantee of safety or legitimacy.',
          'result.nextSteps': 'Report at cybercrime.gov.in. If you lost money, call 1930.',
          'result.confidence': 'Confidence',
          'result.technicalEvidence': 'Technical evidence',
          'result.socialEvidence': 'Social-engineering evidence',
          'result.showRules': 'Show rule IDs',
          'result.hideRules': 'Hide rule IDs',
          'result.ruleset': 'Ruleset',
          'result.indicators': 'Extracted indicators (defanged)',
          'result.copyIndicators': 'Copy indicators',
          'result.copied': 'Copied',
          'result.defangedNote':
            'URLs are shown defanged (hxxps://…[.]…) so they cannot be opened by mistake.',
          'report.title': 'Cyber Fraud Evidence and Complaint Preparation Report',
          'report.note': 'This is a preparation aid, not a submitted complaint.',
          'report.download': 'Download PDF',
          'report.preparing': 'Preparing PDF…',
          'history.title': 'Scan history',
          'history.empty': 'No scans yet.',
          'history.delete': 'Delete',
          'scan.pending': 'Scan pending…',
          'scan.running': 'Analysing…',
          'scan.completed': 'Scan complete',
          'scan.failed': 'Scan failed',
        };
        return map[key] || key;
      },
      i18n: { language: 'en', changeLanguage: () => Promise.resolve() },
    }),
  };
});
