import { useTranslation } from 'react-i18next';

export default function HelplineBanner() {
  const { t } = useTranslation();
  return (
    <div role="alert" className="bg-red-600 text-white px-4 py-3 rounded mb-4 text-center">
      <p className="font-bold text-lg">{t('helpline.banner')}</p>
      <p className="text-2xl font-extrabold mt-1">1930</p>
    </div>
  );
}
