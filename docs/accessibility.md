# Accessibility

Target: WCAG 2.2 AA.

- Keyboard navigation for every control; visible focus states; proper labels.
- Live regions (`aria-live="polite"`) for scan status updates and classification.
- Mobile-first layout; tested at 360px width.
- Colour contrast AA; classification conveyed by text + icon, never colour alone.
- axe checks in tests (Vitest + Playwright).
