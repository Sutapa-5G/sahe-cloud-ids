import { useEffect, useRef, useState, useCallback } from 'react';
import { API_BASE } from '../api/client';

const WS_URL = API_BASE.replace(/^http/, 'ws') + '/ws/events';
const MAX_ALERTS_KEPT = 200;
const RECONNECT_DELAY_MS = 3000;

export function useLiveAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [connectionState, setConnectionState] = useState('connecting'); // connecting | open | closed
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  // Holds the latest `connect` function so onclose's setTimeout callback
  // can call it without referencing the function while it's still being
  // defined (avoids a self-reference during initialization).
  const connectRef = useRef(null);

  const connect = useCallback(() => {
    setConnectionState('connecting');
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnectionState('open');

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        setAlerts((prev) => [payload, ...prev].slice(0, MAX_ALERTS_KEPT));
      } catch {
        // Malformed message — ignore rather than crash the UI. A
        // production system would log this for investigation.
      }
    };

    ws.onclose = () => {
      setConnectionState('closed');
      reconnectTimerRef.current = setTimeout(() => connectRef.current?.(), RECONNECT_DELAY_MS);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, []);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { alerts, connectionState };
}
