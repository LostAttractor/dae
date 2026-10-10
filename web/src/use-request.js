import { useCallback, useLayoutEffect, useRef, useState } from "react";

const idle = { pending: false, value: null, error: null };

// Both success and failure belong to the request that started them. Closing a
// view, losing access or starting a newer request invalidates late completions.
export function useRequest() {
  const sequence = useRef(0);
  const [state, setState] = useState(idle);
  const reset = useCallback(() => {
    sequence.current++;
    setState(idle);
  }, []);
  const start = useCallback(() => {
    const own = ++sequence.current;
    const current = () => own === sequence.current;
    setState({ ...idle, pending: true });
    return {
      current,
      cancel: () => { if (current()) sequence.current++; },
      resolve: (value) => { if (current()) setState({ pending: false, value, error: null }); },
      reject: (error) => { if (current()) setState({ pending: false, value: null, error: error.message }); },
    };
  }, []);
  useLayoutEffect(() => () => { sequence.current++; }, []);
  return { ...state, start, reset };
}
