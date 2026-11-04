import axe, { type Result } from 'axe-core';

/**
 * Run axe-core against a container and return serious/critical violations.
 * Medium/minor issues are filtered: they're tracked but don't fail CI.
 */
export async function seriousViolations(container: Element): Promise<Result[]> {
  const results = await axe.run(container, {
    resultTypes: ['violations'],
    rules: {
      // jsdom has no real layout engine — colour-contrast needs rendering.
      'color-contrast': { enabled: false },
    },
  });
  return results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
}
