"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import toast, { Toaster } from "react-hot-toast";
import styles from "../app/page.module.css";
import HealthScore from "./HealthScore";
import IdentityTable from "./IdentityTable";
// Capture upload zone removed from dashboard capture card per simplified UI
import RecordsTable from "./RecordsTable";
import { API_BASE_URL as API } from "../lib/api";

const LIVE_CAPTURE_DURATION = 30;
const LIVE_CAPTURE_PACKET_LIMIT = 3000;
const CAPTURE_MODE_STANDARD = "standard";
const CAPTURE_MODE_OTX = "otx";

export default function Dashboard() {
  const [health, setHealth] = useState({
    health_score: 100,
    white_count: 0,
    black_count: 0,
    blocked_count: 0,
    active_threats: 0,
    total_identities: 0,
  });
  const [whiteUsers, setWhiteUsers] = useState([]);
  const [blackUsers, setBlackUsers] = useState([]);
  const [modelExists, setModelExists] = useState(false);
  const [modelInfo, setModelInfo] = useState(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [captureStats, setCaptureStats] = useState({ packets: 0, elapsed: 0 });
  const [lastAnalysisId, setLastAnalysisId] = useState(null);
  const [recentAnalyses, setRecentAnalyses] = useState([]);
  const [captureMode, setCaptureMode] = useState(CAPTURE_MODE_STANDARD);
  const captureModeRef = useRef(CAPTURE_MODE_STANDARD);
  const captureIntervalRef = useRef(null);
  const captureFinalizingRef = useRef(false);

  const setMode = (mode) => {
    setCaptureMode(mode);
    captureModeRef.current = mode;
  };

  const refreshData = useCallback(async () => {
    try {
      const [summaryRes, identitiesRes] = await Promise.all([
        fetch(`${API}/api/summary`),
        fetch(`${API}/api/identities`),
      ]);
      const summaryData = await summaryRes.json();
      const identitiesData = await identitiesRes.json();

      setHealth(summaryData.health || { health_score: 100 });
      setModelExists(summaryData.model_exists || false);
      setModelInfo(summaryData.model);
      setWhiteUsers(identitiesData.white_users || []);
      setBlackUsers(identitiesData.black_users || []);
      setRecentAnalyses(summaryData.recent_analyses || []);
    } catch (error) {
      console.log("Backend not available yet", error);
    }
  }, []);

  useEffect(() => {
    const initialRefresh = setTimeout(() => {
      void refreshData();
    }, 0);
    const interval = setInterval(refreshData, 5000);
    return () => {
      clearTimeout(initialRefresh);
      clearInterval(interval);
    };
  }, [refreshData]);

  useEffect(() => {
    return () => {
      if (captureIntervalRef.current) {
        clearInterval(captureIntervalRef.current);
        captureIntervalRef.current = null;
      }
      captureFinalizingRef.current = false;
    };
  }, []);

  const finalizeCapture = useCallback(async () => {
    if (captureFinalizingRef.current) return;
    captureFinalizingRef.current = true;

    if (captureIntervalRef.current) clearInterval(captureIntervalRef.current);
    captureIntervalRef.current = null;

    try {
      const currentMode = captureModeRef.current;
      const res = await fetch(`${API}/api/capture/stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: currentMode }),
      });
      const data = await res.json();
      setIsCapturing(false);

      if (data.error) {
        throw new Error(data.error);
      }

      if (data.analysis_id) {
        setLastAnalysisId(data.analysis_id);
        await refreshData();

        const analyzeUrl = currentMode === CAPTURE_MODE_OTX
          ? `${API}/api/analyze/${data.analysis_id}?otx_only=1`
          : `${API}/api/analyze/${data.analysis_id}`;
        const analyzeRes = await fetch(analyzeUrl);
        const analyzeData = await analyzeRes.json();
        if (!analyzeRes.ok || analyzeData.error) {
          throw new Error(analyzeData.error || "Analysis failed after capture.");
        }

        toast.success(
          currentMode === CAPTURE_MODE_OTX
            ? `OTX capture completed: ${analyzeData.otx_only_matches || 0} OTX-matched flows returned.`
            : `Live capture completed: ${(data.packets_captured || 0).toLocaleString()} packets analyzed.`,
        );
        await refreshData();
      } else {
        toast("Capture stopped.");
        await refreshData();
      }
    } catch (error) {
      setIsCapturing(false);
      await refreshData();
      toast.error(error.message || "Failed to stop and analyze the live capture.");
    } finally {
      setMode(CAPTURE_MODE_STANDARD);
      captureFinalizingRef.current = false;
    }
  }, [refreshData]);

  const pollCapture = useCallback(() => {
    if (captureIntervalRef.current) clearInterval(captureIntervalRef.current);
    captureIntervalRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API}/api/capture/status`);
        const data = await res.json();
        setCaptureStats({
          packets: data.display_packets_captured ?? data.packets_captured ?? 0,
          elapsed: Math.round(data.elapsed_seconds || 0),
        });
        if (!data.is_capturing) {
          clearInterval(captureIntervalRef.current);
          captureIntervalRef.current = null;
          await finalizeCapture();
        }
      } catch {
        clearInterval(captureIntervalRef.current);
        captureIntervalRef.current = null;
        setIsCapturing(false);
      }
    }, 1000);
  }, [finalizeCapture]);

  const syncCaptureStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/capture/status`);
      const data = await res.json();
      const active = Boolean(data.is_capturing);

      setCaptureStats({
        packets: data.display_packets_captured ?? data.packets_captured ?? 0,
        elapsed: Math.round(data.elapsed_seconds || 0),
      });
      setIsCapturing(active);

      if (active && !captureIntervalRef.current) {
        pollCapture();
      }
    } catch {
      // Keep the dashboard usable if background sync fails.
    }
  }, [pollCapture]);

  useEffect(() => {
    void syncCaptureStatus();
  }, [syncCaptureStatus]);

  // Simplified payload: use reasonable defaults for live captures.
  const getCapturePayload = useCallback(() => {
    return {
      duration: LIVE_CAPTURE_DURATION,
      packet_count: LIVE_CAPTURE_PACKET_LIMIT,
    };
  }, []);

  const startCapture = useCallback(async (mode = CAPTURE_MODE_STANDARD) => {
    if (isCapturing || captureFinalizingRef.current) return;

    try {
      setMode(mode);
      setCaptureStats({ packets: 0, elapsed: 0 });
      const payload = getCapturePayload();
      const bodyPayload = Object.assign({}, payload, { mode });
      const res = await fetch(`${API}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(bodyPayload),
      });
      const data = await res.json();

      if (data.status === "busy") {
        setMode(mode);
        setCaptureStats({
          packets: data.display_packets_captured ?? data.packets_captured ?? 0,
          elapsed: Math.round(data.elapsed_seconds || 0),
        });
        setIsCapturing(true);
        pollCapture();
        toast("Capture already running. Reconnected to active session.");
        return;
      }

      if (!res.ok || data.error || data.status === "error") {
        throw new Error(data.error || "Failed to start capture.");
      }

      setIsCapturing(true);
      toast.success(mode === CAPTURE_MODE_OTX ? "OTX capture started." : "Live capture started.");
      pollCapture();
    } catch (error) {
      console.error(error);
      setIsCapturing(false);
      setMode(CAPTURE_MODE_STANDARD);
      toast.error(error.message || "Failed to start live capture.");
    }
  }, [getCapturePayload, isCapturing, pollCapture]);

  const stopAndAnalyze = async () => {
    if (!isCapturing && !captureFinalizingRef.current) return;
    await finalizeCapture();
  };

  const captureModeLabel = captureMode === CAPTURE_MODE_OTX ? "OTX mode" : "Live mode";

  return (
    <div className={styles.dashboard}>
      <Toaster
        position="bottom-right"
        toastOptions={{
          style: {
            background: "var(--bg-card)",
            color: "var(--text-primary)",
            border: "1px solid var(--border)",
          },
        }}
      />

      <div className={styles.topBar}>
        <div>
          <div className={styles.brand}>THE OBSIDIAN LENS</div>
          <div className={styles.brandSub}>
            Network Forensic Tool | 49-Parameter Behavioral Analysis
          </div>
        </div>
        <div className={styles.actions}>
          <Link href="/" className="btn">
            View Intro
          </Link>
          <button className="btn btn-accent" onClick={refreshData}>
            Sync Dashboard
          </button>
        </div>
      </div>

      <div className={styles.modelBar}>
        <div className={styles.modelStatus}>
          <div
            className={`${styles.modelDot} ${modelExists ? styles.modelDotActive : styles.modelDotInactive}`}
          />
          <span
            style={{
              color: modelExists ? "var(--white-badge)" : "var(--text-muted)",
            }}
          >
            {modelExists
              ? "Weighted Random Forest Classifier Active (Learning enabled)"
              : "Network Service Starting..."}
          </span>
        </div>
        {modelInfo && (
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "0.75rem",
              color: "var(--text-muted)",
            }}
          >
            {modelInfo.class_labels?.length || "?"} profiles |{" "}
            {modelInfo.n_samples || "?"} dataset size |{" "}
            {((modelInfo.cv_accuracy || 0) * 100).toFixed(1)}% accuracy
          </span>
        )}
      </div>

      <div className={styles.topRow}>
        <div className={`card ${styles.healthCard}`}>
          <HealthScore
            score={health.health_score}
            whiteCount={health.white_count}
            blackCount={health.black_count}
            blockedCount={health.blocked_count}
            activeThreats={health.active_threats}
            totalIdentities={health.total_identities}
          />
        </div>

        <div className={`card ${styles.ingestionCard}`}>
          <div className={styles.ingestionGrid}>
            <div className={styles.capturePreset} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', margin: '0 auto', width: '100%' }}>
              <div style={{ paddingTop: 8 }}>
                <div className={styles.captureButtons}>
                  <button
                    className="btn btn-accent"
                    onClick={() => startCapture(CAPTURE_MODE_STANDARD)}
                    disabled={isCapturing || captureFinalizingRef.current}
                  >
                    Start Live
                  </button>
                  <button
                    className="btn btn-sm"
                    onClick={() => startCapture(CAPTURE_MODE_OTX)}
                    disabled={isCapturing || captureFinalizingRef.current}
                    title="Capture and return only OTX-matched flows"
                  >
                    Start OTX
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={stopAndAnalyze}
                    disabled={!isCapturing || captureFinalizingRef.current}
                  >
                    Stop Capture
                  </button>
                </div>
              </div>
            </div>
          </div>

          {isCapturing && (
            <div className={styles.captureRow}>
              <span className={styles.captureInfo}>
                {captureModeLabel} | {captureStats.packets.toLocaleString()} packets | {captureStats.elapsed}s elapsed
              </span>
            </div>
          )}
          {captureFinalizingRef.current && (
            <div className={styles.captureRow}>
              <span className={styles.captureInfo}>Finalizing capture...</span>
            </div>
          )}

          {lastAnalysisId && (
            <div className={styles.lastCaptureNote}>
              Latest live analysis ID: <span>{lastAnalysisId}</span>
            </div>
          )}
        </div>
      </div>

      <div style={{ marginBottom: "1.25rem" }}>
        <RecordsTable records={recentAnalyses} onRefresh={refreshData} />
      </div>

      <div className={styles.tablesSection}>
        <IdentityTable identities={blackUsers} type="black" onAction={refreshData} />
        <IdentityTable identities={whiteUsers} type="white" onAction={refreshData} />
      </div>
    </div>
  );
}
