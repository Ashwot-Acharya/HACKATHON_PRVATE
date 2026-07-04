import { useRef, useEffect } from 'react';

export const useDebounce = (fn: (...args: unknown[]) => void, delay = 300) => {
  const tRef = useRef<number | null>(null);
  useEffect(() => () => { if (tRef.current) window.clearTimeout(tRef.current); }, []);
  return (...args: unknown[]) => {
    if (tRef.current) window.clearTimeout(tRef.current);
    tRef.current = window.setTimeout(() => fn(...args), delay);
  };
};
