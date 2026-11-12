import '@testing-library/jest-dom';

// Polyfill clipboard for JSDOM test environment
if (typeof navigator !== 'undefined') {
  if (!navigator.clipboard) {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: async () => {},
        readText: async () => '',
      },
      configurable: true,
      writable: true,
    });
  }
}

if (typeof document !== 'undefined') {
  if (!document.execCommand) {
    document.execCommand = () => true;
  }
}
