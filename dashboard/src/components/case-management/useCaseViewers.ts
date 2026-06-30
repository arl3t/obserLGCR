/**
 * useCaseViewers — presencia en tiempo real de operadores en un caso (C3).
 *
 * Funcionamiento:
 *   1. Al montar (caseId presente), hace GET /api/cases/:id/viewers → snapshot.
 *   2. Emite `case:subscribe` por el socket para joinear la room.
 *   3. POSTea heartbeat cada 30s mientras la pestaña está visible. El backend
 *      hace upsert; en el primer heartbeat broadcast emite `case:viewer_joined`.
 *   4. Escucha `case:viewer_joined`/`case:viewer_left` de la room para
 *      actualizar la lista en vivo (incluyo o saco al operador del array).
 *   5. Al desmontar: emite `case:unsubscribe` + DELETE /viewers para limpiar.
 *
 * Notas:
 *   - El propio operador se incluye en la lista (sirve de feedback de que el
 *     heartbeat funciona); el consumidor decide si filtrarlo del avatar
 *     stack.
 *   - Si la pestaña no está visible (document.hidden), el heartbeat se pausa;
 *     la fila vencerá por TTL (2 min) y el server emitirá viewer_left a los
 *     que sí están suscritos. Heurística simple sin necesidad de un
 *     watchdog.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/api/client";
import { socket } from "@/lib/socket";

export interface CaseViewer {
  operatorId:   string;
  operatorName: string | null;
  activeTab:    string | null;
  lastSeenAt:   string;
  firstSeenAt:  string;
}

interface ViewersResponse {
  case_id: string;
  viewers: CaseViewer[];
}

const HEARTBEAT_INTERVAL_MS = 30_000;

export function useCaseViewers(
  caseId: string | null | undefined,
  activeTab: string | null = null,
): {
  viewers: CaseViewer[];
  isLoading: boolean;
  /** Operadores distintos al usuario actual — útil para el avatar stack. */
  othersOnly: (selfOperatorId: string | null | undefined) => CaseViewer[];
} {
  const enabled = !!caseId;

  // Snapshot inicial vía HTTP. Reuso react-query para invalidation centralizado.
  const snapshotQuery = useQuery<ViewersResponse>({
    queryKey: ["case-viewers", caseId],
    queryFn: async () => {
      const { data } = await api.get<ViewersResponse>(`/api/cases/${caseId}/viewers`);
      return data;
    },
    enabled,
    staleTime: 60_000,
    refetchInterval: 60_000,        // safety net si el socket falla
    refetchOnWindowFocus: false,
  });

  // Live updates desde socket + propio heartbeat.
  const [liveViewers, setLiveViewers] = useState<CaseViewer[]>([]);
  // Sync inicial cuando llega el snapshot.
  useEffect(() => {
    if (snapshotQuery.data?.viewers) {
      setLiveViewers(snapshotQuery.data.viewers);
    }
  }, [snapshotQuery.data]);

  const activeTabRef = useRef(activeTab);
  useEffect(() => { activeTabRef.current = activeTab; }, [activeTab]);

  // Suscripción a la room + heartbeat + listeners.
  useEffect(() => {
    if (!caseId) return;

    socket.connect();
    socket.emit("case:subscribe", caseId);

    const onJoined = (payload: { caseId: string; operatorId: string; operatorName: string | null; activeTab: string | null; firstSeenAt: string }) => {
      if (payload.caseId !== caseId) return;
      setLiveViewers((prev) => {
        if (prev.some((v) => v.operatorId === payload.operatorId)) return prev;
        return [
          ...prev,
          {
            operatorId:   payload.operatorId,
            operatorName: payload.operatorName ?? null,
            activeTab:    payload.activeTab ?? null,
            lastSeenAt:   new Date().toISOString(),
            firstSeenAt:  payload.firstSeenAt,
          },
        ];
      });
    };
    const onLeft = (payload: { caseId: string; operatorId: string }) => {
      if (payload.caseId !== caseId) return;
      setLiveViewers((prev) => prev.filter((v) => v.operatorId !== payload.operatorId));
    };

    socket.on("case:viewer_joined", onJoined);
    socket.on("case:viewer_left",   onLeft);

    // Heartbeat. Se ejecuta SIEMPRE inmediatamente para hacer el "join"
    // visible al server (que dispara case:viewer_joined a los demás).
    let stopped = false;
    async function beat() {
      if (stopped || document.hidden) return;
      try {
        await api.post(`/api/cases/${caseId}/viewers/heartbeat`, {
          activeTab: activeTabRef.current,
        });
      } catch {/* tolerante: el TTL del server cubre el caso */}
    }
    void beat();
    const interval = window.setInterval(beat, HEARTBEAT_INTERVAL_MS);
    // Cuando la pestaña vuelve a estar visible, beat inmediato para
    // re-establecer presencia sin esperar al próximo tick.
    const onVis = () => { if (!document.hidden) void beat(); };
    document.addEventListener("visibilitychange", onVis);

    return () => {
      stopped = true;
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVis);
      socket.off("case:viewer_joined", onJoined);
      socket.off("case:viewer_left",   onLeft);
      socket.emit("case:unsubscribe", caseId);
      // Best-effort delete — no esperamos respuesta. El server +TTL ya cubre.
      void api.delete(`/api/cases/${caseId}/viewers`).catch(() => {});
    };
  }, [caseId]);

  const othersOnly = useMemo(
    () => (selfId: string | null | undefined) => {
      if (!selfId) return liveViewers;
      return liveViewers.filter((v) => v.operatorId !== selfId);
    },
    [liveViewers],
  );

  return {
    viewers: liveViewers,
    isLoading: snapshotQuery.isLoading,
    othersOnly,
  };
}
