import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const savedLang =
  typeof localStorage !== 'undefined' ? localStorage.getItem('cybersathi-lang') : null;

i18n.use(initReactI18next).init({
  lng: savedLang || 'en',
  fallbackLng: 'en',
  resources: {
    en: {
      translation: {
        'app.title': 'Citizen CyberSathi',
        'a11y.skip': 'Skip to content',
        'nav.history': 'History',
        'lang.switch': 'Switch language',
        'submit.title': 'Check suspicious content',
        'submit.placeholder': 'Paste the suspicious message or URL here…',
        'submit.privacy':
          'Privacy notice: content is encrypted, kept 30 days, never sold or shared. Do not paste passwords or OTPs.',
        'submit.ack': 'I have read and agree to the privacy notice',
        'submit.lostMoney': 'I have lost money in this incident',
        'submit.button': 'Check now',
        'helpline.banner': 'If you lost money, call the National Cyber Crime Helpline: 1930 — now.',
        'scan.pending': 'Scan pending…',
        'scan.running': 'Analysing…',
        'scan.completed': 'Scan complete',
        'scan.failed': 'Scan failed',
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
        'error.generic': 'Something went wrong. Please try again.',
        'validation.required': 'Please enter content and accept the privacy notice.',
      },
    },
    hi: {
      translation: {
        'app.title': 'सिटिज़न साइबर साथी',
        'a11y.skip': 'सामग्री पर जाएँ',
        'nav.history': 'इतिहास',
        'lang.switch': 'भाषा बदलें',
        'submit.title': 'संदिग्ध सामग्री जाँचें',
        'submit.placeholder': 'संदिग्ध संदेश या URL यहाँ डालें…',
        'submit.privacy':
          'गोपनीयता सूचना: सामग्री एन्क्रिप्ट की जाती है, 30 दिन रखी जाती है, कभी बेची/साझा नहीं की जाती। पासवर्ड या OTP न डालें।',
        'submit.ack': 'मैंने गोपनीयता सूचना पढ़ ली है',
        'submit.lostMoney': 'इस घटना में मेरा पैसा गया है',
        'submit.button': 'अभी जाँचें',
        'helpline.banner':
          'अगर आपका पैसा गया है, तो राष्ट्रीय साइबर अपराध हेल्पलाइन 1930 पर कॉल करें — अभी।',
        'scan.pending': 'स्कैन प्रतीक्षा में…',
        'scan.running': 'विश्लेषण हो रहा है…',
        'scan.completed': 'स्कैन पूर्ण',
        'scan.failed': 'स्कैन विफल',
        'assessment.confirmed_malicious': 'यह सामग्री सत्यापित ख़तरे से मेल खाती है।',
        'assessment.high_risk': 'कई स्वतंत्र संकेत उच्च जोखिम बताते हैं।',
        'assessment.suspicious': 'संकेत सावधानी की माँग करते हैं। क्लिक या साझा न करें।',
        'assessment.no_known_threat': 'कोई ज्ञात ख़तरा नहीं मिला। यह सुरक्षा की गारंटी नहीं है।',
        'assessment.inconclusive': 'हम कोई निष्कर्ष नहीं निकाल सके। कृपया सावधान रहें।',
        'result.disclaimer': 'यह आकलन सुरक्षा या वैधता की गारंटी नहीं है।',
        'result.nextSteps': 'cybercrime.gov.in पर रिपोर्ट करें। पैसे गए हों तो 1930 पर कॉल करें।',
        'result.confidence': 'विश्वास स्तर',
        'result.technicalEvidence': 'तकनीकी साक्ष्य',
        'result.socialEvidence': 'सोशल इंजीनियरिंग साक्ष्य',
        'result.showRules': 'नियम ID दिखाएँ',
        'result.hideRules': 'नियम ID छिपाएँ',
        'result.ruleset': 'नियम संस्करण',
        'result.indicators': 'निकाले गए संकेतक (डिफ़ैंग किए हुए)',
        'result.copyIndicators': 'संकेतक कॉपी करें',
        'result.copied': 'कॉपी हो गया',
        'result.defangedNote':
          'URL डिफ़ैंग करके दिखाए गए हैं (hxxps://…[.]…) ताकि गलती से खुल न सकें।',
        'report.title': 'साइबर धोखाधड़ी साक्ष्य और शिकायत तैयारी रिपोर्ट',
        'report.note': 'यह तैयारी सहायता है, दर्ज शिकायत नहीं।',
        'report.download': 'PDF डाउनलोड करें',
        'report.preparing': 'PDF तैयार हो रहा है…',
        'history.title': 'स्कैन इतिहास',
        'history.empty': 'अभी कोई स्कैन नहीं।',
        'history.delete': 'हटाएँ',
        'error.generic': 'कुछ गलत हुआ। कृपया पुनः प्रयास करें।',
        'validation.required': 'कृपया सामग्री डालें और गोपनीयता सूचना स्वीकार करें।',
      },
    },
  },
});

i18n.on('languageChanged', (lng) => {
  try {
    localStorage.setItem('cybersathi-lang', lng);
  } catch {
    /* ignore */
  }
});

export default i18n;
