import { describe, it, expect } from 'vitest';
import { defang } from './api';

describe('defang', () => {
  it('defangs URLs', () => {
    expect(defang('https://evil.example.com/login')).toBe('hxxps://evil[.]example[.]com/login');
  });
});
