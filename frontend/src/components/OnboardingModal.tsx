'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, ExternalLink, Key, Shield, Radar, Globe, Satellite, Ship, Radio } from 'lucide-react';

const CURRENT_ONBOARDING_VERSION = '0.9.7-docker-keys-1';
const STORAGE_KEY = `shadowbroker_onboarding_complete_v${CURRENT_ONBOARDING_VERSION}`;
const LEGACY_STORAGE_KEY = 'shadowbroker_onboarding_complete';

const API_GUIDES = [
  {
    name: 'OpenSky Network',
    icon: <Radar size={14} className="text-cyan-400" />,
    required: true,
    description:
      'Flight tracking with global ADS-B coverage. Provides real-time aircraft positions.',
    steps: [
      'Create a free account at opensky-network.org',
      'Go to Dashboard → OAuth → Create Client',
      'Copy your Client ID and Client Secret',
      'Paste both into Quick Local Setup above or Settings → API Keys',
    ],
    url: 'https://opensky-network.org/index.php?option=com_users&view=registration',
    color: 'cyan',
  },
  {
    name: 'AIS Stream',
    icon: <Ship size={14} className="text-blue-400" />,
    required: true,
    description: 'Real-time vessel tracking via AIS (Automatic Identification System).',
    steps: [
      'Register at aisstream.io',
      'Navigate to your API Keys page',
      'Generate a new API key',
      'Paste it into Quick Local Setup above or Settings → API Keys',
    ],
    url: 'https://aisstream.io/authenticate',
    color: 'blue',
  },
];

const FREE_SOURCES = [
  { name: 'ADS-B Exchange', desc: 'Military & general aviation', icon: <Radar size={12} /> },
  { name: 'USGS Earthquakes', desc: 'Global seismic data', icon: <Globe size={12} /> },
  { name: 'CelesTrak', desc: '2,000+ satellite orbits', icon: <Satellite size={12} /> },
  { name: 'GDELT Project', desc: 'Global conflict events', icon: <Globe size={12} /> },
  { name: 'RainViewer', desc: 'Weather radar overlay', icon: <Globe size={12} /> },
  { name: 'OpenMHz', desc: 'Radio scanner feeds', icon: <Radio size={12} /> },
  { name: 'RSS Feeds', desc: 'NPR, BBC, Reuters, AP', icon: <Globe size={12} /> },
  { name: 'Yahoo Finance', desc: 'Defense stocks & oil', icon: <Globe size={12} /> },
];

interface OnboardingModalProps {
  onClose: () => void;
  onOpenSettings: () => void;
}

const OnboardingModal = React.memo(function OnboardingModal({
  onClose,
  onOpenSettings,
}: OnboardingModalProps) {
  const [step, setStep] = useState(0);
  const [setupKeys, setSetupKeys] = useState({
    OPENSKY_CLIENT_ID: '',
    OPENSKY_CLIENT_SECRET: '',
    AIS_API_KEY: '',
  });
  const [setupSaving, setSetupSaving] = useState(false);
  const [setupMsg, setSetupMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const handleDismiss = () => {
    localStorage.setItem(STORAGE_KEY, 'true');
    localStorage.setItem(LEGACY_STORAGE_KEY, 'true');
    onClose();
  };

  const handleOpenSettings = () => {
    localStorage.setItem(STORAGE_KEY, 'true');
    localStorage.setItem(LEGACY_STORAGE_KEY, 'true');
    onClose();
    onOpenSettings();
  };

  const saveSetupKeys = async () => {
    const payload = Object.fromEntries(
      Object.entries(setupKeys).filter(([, value]) => value.trim()),
    );
    if (!Object.keys(payload).length) {
      setSetupMsg({ type: 'err', text: 'Enter at least one API key first.' });
      return;
    }
    setSetupSaving(true);
    setSetupMsg(null);
    try {
      const res = await fetch('/api/settings/api-keys', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data?.ok === false) {
        throw new Error(data?.detail || 'Could not save API keys.');
      }
      setSetupKeys({ OPENSKY_CLIENT_ID: '', OPENSKY_CLIENT_SECRET: '', AIS_API_KEY: '' });
      setSetupMsg({ type: 'ok', text: 'Keys saved locally. Restart or refresh feeds to use them.' });
    } catch (error) {
      setSetupMsg({
        type: 'err',
        text: error instanceof Error ? error.message : 'Could not save API keys.',
      });
    } finally {
      setSetupSaving(false);
    }
  };

  return (
    <AnimatePresence>
      {/* Backdrop */}
      <motion.div
        key="onboarding-backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[10000]"
        onClick={handleDismiss}
      />

      {/* Modal */}
      <motion.div
        key="onboarding-modal"
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.9, y: 20 }}
        transition={{ type: 'spring', damping: 25, stiffness: 300 }}
        className="fixed inset-0 z-[10001] flex items-center justify-center pointer-events-none"
      >
        <div
          className="w-[580px] max-h-[85vh] bg-[var(--bg-secondary)]/98 border border-cyan-900/50 pointer-events-auto flex flex-col overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="p-6 pb-4 border-b border-[var(--border-primary)]/80">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                  <Shield size={20} className="text-cyan-400" />
                </div>
                <div>
                  <h2 className="text-sm font-bold tracking-[0.2em] text-[var(--text-primary)] font-mono">
                    MISSION BRIEFING
                  </h2>
                  <span className="text-[13px] text-[var(--text-muted)] font-mono tracking-widest">
                    FIRST-TIME SETUP
                  </span>
                </div>
              </div>
              <button
                onClick={handleDismiss}
                className="w-8 h-8 border border-[var(--border-primary)] hover:border-red-500/50 flex items-center justify-center text-[var(--text-muted)] hover:text-red-400 transition-all hover:bg-red-950/20"
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Step Indicators */}
          <div className="flex gap-2 px-6 pt-4">
            {['API Keys', 'Trust Modes', 'Free Sources'].map((label, i) => (
              <button
                key={label}
                onClick={() => setStep(i)}
                className={`flex-1 py-1.5 text-[13px] font-mono tracking-widest border transition-all ${
                  step === i
                    ? 'border-cyan-500/50 text-cyan-400 bg-cyan-950/20'
                    : 'border-[var(--border-primary)] text-[var(--text-muted)] hover:border-[var(--border-secondary)] hover:text-[var(--text-secondary)]'
                }`}
              >
                {label.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto styled-scrollbar p-6">
            {step === 1 && (
              <div className="space-y-4">
                <div className="text-center py-4">
                  <div className="text-lg font-bold tracking-[0.3em] text-[var(--text-primary)] font-mono mb-2">
                    T R U S T <span className="text-cyan-400">M O D E S</span>
                  </div>
                  <p className="hidden">
                    Real-time OSINT dashboard aggregating 12+ live intelligence sources. Flights,
                    ships, satellites, earthquakes, conflicts, and more — all on one map.
                  </p>
                  <p className="text-[11px] text-[var(--text-secondary)] font-mono leading-relaxed max-w-md mx-auto">
                    These modes explain what lane the network is using. Set up the API keys first,
                    then use this screen to understand public mesh versus private Wormhole paths.
                  </p>
                </div>

                <div className="hidden">
                  <div className="flex items-start gap-2">
                    <Globe size={14} className="text-green-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-[11px] text-green-400 font-mono font-bold mb-1">
                        8 Sources Work Immediately
                      </p>
                      <p className="text-sm text-[var(--text-secondary)] font-mono leading-relaxed">
                        Military aircraft, satellites, earthquakes, global conflicts, weather radar,
                        radio scanners, news, and market data all work out of the box — no keys
                        needed.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="bg-cyan-950/20 border border-cyan-500/20 p-4">
                  <div className="flex items-start gap-2">
                    <Shield size={14} className="text-cyan-400 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-[11px] text-cyan-300 font-mono font-bold mb-1">
                        TRUST MODES
                      </p>
                      <div className="space-y-1 text-sm text-[var(--text-secondary)] font-mono leading-relaxed">
                        <div>
                          <span className="text-orange-300">PUBLIC / DEGRADED</span> — Meshtastic,
                          APRS, and perimeter feeds. Observable and linkable.
                        </div>
                        <div>
                          <span className="text-yellow-300">PRIVATE / TRANSITIONAL</span> —
                          Wormhole lane is active. Gate chat runs on this lane, but metadata resistance is reduced until Reticulum is ready.
                        </div>
                        <div>
                          <span className="text-green-300">PRIVATE / STRONG</span> — Wormhole and
                          Reticulum are both ready. Dead Drop / DM requires this tier for the strongest privacy posture.
                        </div>
                      </div>
                      <p className="mt-2 text-sm text-[var(--text-secondary)] font-mono leading-relaxed">
                        Public mesh is not private just because Wormhole exists. Use Wormhole when
                        you want the private lane, and treat public mesh as public.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {step === 0 && (
              <div className="space-y-4">
                <div className="bg-yellow-950/20 border border-yellow-500/20 p-4">
                  <div className="flex items-start gap-2">
                    <Key size={14} className="text-yellow-500 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-[11px] text-yellow-400 font-mono font-bold mb-1">
                        START HERE
                      </p>
                      <p className="text-sm text-[var(--text-secondary)] font-mono leading-relaxed">
                        OpenSky Network and AIS Stream are the free keys that make ShadowBroker
                        useful immediately: live aircraft and vessel tracking. Paste them below or
                        use Settings later; secrets stay on the local backend.
                      </p>
                    </div>
                  </div>
                </div>

                <div className="border border-cyan-900/40 bg-cyan-950/10 p-4 space-y-3">
                  <div>
                    <p className="text-[11px] text-cyan-300 font-mono font-bold tracking-widest">
                      QUICK LOCAL SETUP
                    </p>
                    <p className="text-sm text-[var(--text-secondary)] font-mono leading-relaxed mt-1">
                      Paste keys here once. ShadowBroker stores them server-side only and never
                      displays the secret back in the browser.
                    </p>
                  </div>
                  {[
                    ['OPENSKY_CLIENT_ID', 'OpenSky Client ID'],
                    ['OPENSKY_CLIENT_SECRET', 'OpenSky Client Secret'],
                    ['AIS_API_KEY', 'AIS Stream API Key'],
                  ].map(([key, label]) => (
                    <input
                      key={key}
                      type="password"
                      value={setupKeys[key as keyof typeof setupKeys]}
                      onChange={(event) =>
                        setSetupKeys((prev) => ({ ...prev, [key]: event.target.value }))
                      }
                      placeholder={label}
                      className="w-full bg-[var(--bg-primary)] border border-[var(--border-primary)] px-3 py-2 text-sm text-[var(--text-primary)] font-mono outline-none focus:border-cyan-500/70 placeholder:text-[var(--text-muted)]/60"
                      autoComplete="off"
                    />
                  ))}
                  {setupMsg && (
                    <p
                      className={`text-sm font-mono ${
                        setupMsg.type === 'ok' ? 'text-green-300' : 'text-red-300'
                      }`}
                    >
                      {setupMsg.text}
                    </p>
                  )}
                  <button
                    onClick={() => void saveSetupKeys()}
                    disabled={setupSaving}
                    className="w-full py-2 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-[11px] font-mono tracking-widest"
                  >
                    {setupSaving ? 'SAVING...' : 'SAVE KEYS LOCALLY'}
                  </button>
                </div>

                {API_GUIDES.map((api) => (
                  <div
                    key={api.name}
                    className={`border border-${api.color}-900/30 bg-${api.color}-950/10 p-4`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {api.icon}
                        <span className="text-xs font-mono text-white font-bold">{api.name}</span>
                        <span className="text-[12px] font-mono px-1.5 py-0.5 border border-yellow-500/30 text-yellow-400 bg-yellow-950/20">
                          REQUIRED
                        </span>
                      </div>
                      <a
                        href={api.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className={`text-sm font-mono text-${api.color}-400 hover:text-${api.color}-300 flex items-center gap-1 transition-colors`}
                      >
                        GET KEY <ExternalLink size={10} />
                      </a>
                    </div>
                    <p className="text-sm text-[var(--text-secondary)] font-mono mb-3">
                      {api.description}
                    </p>
                    <ol className="space-y-1.5">
                      {api.steps.map((s, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span
                            className={`text-[13px] font-mono text-${api.color}-500 font-bold mt-0.5 w-3 flex-shrink-0`}
                          >
                            {i + 1}.
                          </span>
                          <span className="text-sm text-gray-300 font-mono">{s}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                ))}

                <button
                  onClick={handleOpenSettings}
                  className="w-full py-3 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors text-[11px] font-mono tracking-widest flex items-center justify-center gap-2"
                >
                  <Key size={14} />
                  OPEN SETTINGS TO ENTER KEYS
                </button>
              </div>
            )}

            {step === 2 && (
              <div className="space-y-3">
                <p className="text-sm text-[var(--text-secondary)] font-mono mb-3">
                  These data sources are completely free and require no API keys. They activate
                  automatically on launch, while OpenSky and AIS Stream unlock the richer live
                  aviation and maritime experience.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  {FREE_SOURCES.map((src) => (
                    <div
                      key={src.name}
                      className="border border-[var(--border-primary)]/60 bg-[var(--bg-secondary)]/30 p-3 hover:border-[var(--border-secondary)] transition-colors"
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-green-500">{src.icon}</span>
                        <span className="text-sm font-mono text-[var(--text-primary)] font-medium">
                          {src.name}
                        </span>
                      </div>
                      <p className="text-[13px] text-[var(--text-muted)] font-mono">{src.desc}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-[var(--border-primary)]/80 flex items-center justify-between">
            <button
              onClick={() => setStep(Math.max(0, step - 1))}
              className={`px-4 py-2 border text-sm font-mono tracking-widest transition-all ${
                step === 0
                  ? 'border-[var(--border-primary)] text-[var(--text-muted)] cursor-not-allowed'
                  : 'border-[var(--border-primary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--border-secondary)]'
              }`}
              disabled={step === 0}
            >
              PREV
            </button>

            <div className="flex gap-1.5">
              {[0, 1, 2].map((i) => (
                <div
                  key={i}
                  className={`w-1.5 h-1.5 rounded-full transition-colors ${step === i ? 'bg-cyan-400' : 'bg-[var(--border-primary)]'}`}
                />
              ))}
            </div>

            {step < 2 ? (
              <button
                onClick={() => setStep(step + 1)}
                className="px-4 py-2 border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 text-sm font-mono tracking-widest transition-all"
              >
                NEXT
              </button>
            ) : (
              <button
                onClick={handleDismiss}
                className="px-4 py-2 bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/30 text-sm font-mono tracking-widest transition-all"
              >
                LAUNCH
              </button>
            )}
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
});

export function useOnboarding() {
  const [showOnboarding, setShowOnboarding] = useState(false);

  useEffect(() => {
    const done = localStorage.getItem(STORAGE_KEY);
    if (!done) {
      setShowOnboarding(true);
    }
  }, []);

  return { showOnboarding, setShowOnboarding };
}

export default OnboardingModal;
