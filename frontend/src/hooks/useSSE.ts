import { useState, useEffect, useRef, useCallback } from 'react';
import type { SSEProgressEvent } from '../types';

export function useSSE(taskId: string | null) {
  const [data, setData] = useState<SSEProgressEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const readerRef = useRef<ReadableStreamDefaultReader<Uint8Array> | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const cleanup = useCallback(() => {
    readerRef.current?.cancel();
    abortRef.current?.abort();
    readerRef.current = null;
    abortRef.current = null;
  }, []);

  useEffect(() => {
    if (!taskId) return;

    let cancelled = false;
    let retryTimer: ReturnType<typeof setTimeout>;

    const connect = async () => {
      cleanup();

      const controller = new AbortController();
      abortRef.current = controller;

      try {
        const res = await fetch(`/api/scans/${taskId}/stream`, {
          signal: controller.signal,
          headers: { Accept: 'text/event-stream' },
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        if (!res.body) throw new Error('No response body');

        setConnected(true);
        setError(null);

        const reader = res.body.getReader();
        readerRef.current = reader;
        const decoder = new TextDecoder();
        let buffer = '';

        while (!cancelled) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          let eventType = '';
          let eventData = '';

          for (const line of lines) {
            if (line.startsWith('event: ')) {
              eventType = line.slice(7).trim();
            } else if (line.startsWith('data: ')) {
              eventData = line.slice(6);
            } else if (line === '' && eventData) {
              try {
                const parsed = JSON.parse(eventData);
                if (eventType === 'progress') {
                  setData(parsed as SSEProgressEvent);
                } else if (eventType === 'done') {
                  setConnected(false);
                  return;
                }
              } catch {
                // skip unparseable events
              }
              eventType = '';
              eventData = '';
            }
          }
        }
      } catch (err) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : 'SSE error';
          setError(msg);
          setConnected(false);

          // Exponential backoff reconnect
          retryTimer = setTimeout(connect, 3000);
        }
      }
    };

    connect();

    return () => {
      cancelled = true;
      cleanup();
      clearTimeout(retryTimer);
    };
  }, [taskId, cleanup]);

  return { data, connected, error };
}
