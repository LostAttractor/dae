import { useCallback, useLayoutEffect, useRef, useState } from "react";
import { errorMessage } from "./api.ts";

interface RequestState<T> { pending: boolean; value: T | null; error: string | null }

// Both success and failure belong to the request that started them. Closing a
// view, losing access or starting a newer request invalidates late completions.
export function useRequest<T>() {
  const idle: RequestState<T> = { pending: false, value: null, error: null };
  const sequence = useRef(0);
  const [state, setState] = useState<RequestState<T>>(idle);
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
      resolve: (value: T) => { if (current()) setState({ pending: false, value, error: null }); },
      reject: (error: unknown) => { if (current()) setState({ pending: false, value: null, error: errorMessage(error) }); },
    };
  }, []);
  useLayoutEffect(() => () => { sequence.current++; }, []);
  return { ...state, start, reset };
}
