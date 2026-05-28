'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Terminal,
  Bot,
  Network,
  Scale,
  KeyRound,
  Cpu,
  Layers,
  GitBranch,
  Shield,
  Plane,
  Clock,
  Satellite,
  Bug,
  Heart,
} from 'lucide-react';

const CURRENT_VERSION = '0.9.81';
const STORAGE_KEY = `shadowbroker_changelog_v${CURRENT_VERSION}`;
const RELEASE_TITLE = 'Signed Auto-Update + Update Button Race Fix';

const HEADLINE_FEATURES = [
  {
    icon: <KeyRound size={20} className="text-purple-400" />,
    accent: 'purple' as const,
    title: 'Signed Auto-Update Going Forward (one manual hop)',
    subtitle: 'After installing v0.9.81, the in-app Update button finally works end-to-end. This release establishes a fresh signing key — every release from here is a one-click upgrade.',
    details: [
      'tauri.conf.json now carries a fresh minisign pubkey (the previous keypair was generated before v0.9.79 shipped but the matching private key was lost before any release was actually signed, so no release before v0.9.81 has working auto-update).',
      'The v0.9.81 release artifacts ship with a signed latest.json + .sig files so every install on v0.9.81 or later can verify and apply the next release automatically via the Tauri updater plugin.',
      'One-time cost: if you are upgrading from v0.9.79 or v0.9.8, the click-Update path falls back to a manual download because the new pubkey does not match the one baked into your install. Click the MANUAL DOWNLOAD button in the update dialog → grab the .msi from the release page → run it → from then on auto-update works in-app.',
    ],
    callToAction: 'CLICK UPDATE → DOWNLOAD MSI ONCE → AUTO-UPDATE FOREVER',
  },
  {
    icon: <Network size={20} className="text-amber-400" />,
    accent: 'cyan' as const,
    title: 'AIS Maritime Resilience — Outage Banner + AISHub Fallback',
    subtitle: 'When AISStream’s WebSocket goes offline (as happened upstream in May 2026), the ships layer no longer goes silently empty.',
    details: [
      'AIS proxy health surfaces in /api/health: connected, last_msg_age_seconds, proxy_spawn_count. A dismissible amber banner explains the outage (“Ship data temporarily unavailable — AISStream upstream is offline”) instead of letting users assume their install is broken.',
      'AISHub REST fallback (free tier at aishub.net/api). Polls every 20 minutes when the primary is disconnected and merges vessels into the same store with source: “aishub” so existing tooling attributes the provider.',
      'Live data wins races: if the WebSocket reconnects mid-poll, fresh AISStream updates aren’t overwritten by stale REST records. Opt-in via AISHUB_USERNAME; cadence configurable via AISHUB_POLL_INTERVAL_MINUTES (clamped [1, 360]).',
    ],
    callToAction: 'SET AISHUB_USERNAME \u2192 RESTART BACKEND',
  },
  {
    icon: <Shield size={20} className="text-cyan-400" />,
    accent: 'cyan' as const,
    title: 'Data-Layer Repair \u2014 UAP Cutoff + GPS Jamming Detection',
    subtitle: 'Two long-broken layers fixed at the source. UFO sightings are actually recent now; GPS jamming zones actually fire.',
    details: [
      'UAP sightings: the Hugging Face NUFORC mirror fallback had no date cutoff, so when the live nuforc.org scrape failed the layer served 3-year-old reports as \u201crecent\u201d. Now drops rows older than 60 days and logs loudly when the mirror is fully stale. Scheduler moved daily \u2192 weekly (Mondays 12:00 UTC).',
      'GPS jamming: three stacked filters meant the layer almost never lit up. nac_p == 0 (\u201cGPS lock lost\u201d) was filtered out as if it were an old transponder \u2014 it\u2019s actually the strongest jamming signal. Now counted. MIN_AIRCRAFT lowered 5 \u2192 3 so sparser hotspots clear; MIN_RATIO lowered 0.30 \u2192 0.20.',
      'Both layers now surface their own outages via assert_canary so operators see broken vs empty, not silently stale.',
    ],
    callToAction: 'TOGGLE UAP \u2022 GPS JAMMING LAYERS',
  },
];

const NEW_FEATURES = [
  {
    icon: <Plane size={18} className="text-orange-400" />,
    title: 'Cumulative Fuel & CO2 per Flight',
    desc: 'Aircraft tooltip now shows how much fuel each plane has actually burned in the air since first observation, not just the per-hour rate. 15-minute gap between sightings resets the session; 24-hour clamp protects against clock skew; per-icao prune every 5 minutes keeps memory bounded.',
  },
  {
    icon: <Plane size={18} className="text-cyan-400" />,
    title: 'Per-Flight Source Attribution',
    desc: 'Every aircraft record now carries a source field (adsb.lol, OpenSky, airplanes.live, adsb.fi) so consumers can attribute the data provider. Pre-fix, adsb.lol records were unmarked while OpenSky records were explicitly tagged, making it look like adsb.lol was unused even though it is the primary source.',
  },
  {
    icon: <Network size={18} className="text-green-400" />,
    title: 'Cross-Node DM Mailbox Replication',
    desc: 'Direct messages now replicate across mesh nodes when one party is offline. Per-(sender, recipient) anti-spam cap enforced as a network rule (not client-side) so source-code tampering cannot bypass it.',
  },
  {
    icon: <Clock size={18} className="text-amber-400" />,
    title: 'Infonet Sync — HTTP 429 Honored',
    desc: 'When an upstream peer returns Retry-After, the node now waits exactly that long instead of retrying every 60 seconds and keeping the upstream rate-limit bucket permanently full. Exponential backoff on consecutive failures capped at 30 minutes.',
  },
];

const BUG_FIXES = [
  'Update button no longer throws "admin_session_required" on desktop installs. The initial updateAction now syncs to Tauri detection at React-init time (window.__TAURI__ is injected before mount), so a click before the async runtime probe completes opens the GitHub release page in a browser instead of POSTing to /api/system/update.',
  'Desktop installer now bundles defusedxml + PySocks (declared in pyproject.toml but missing from the venv shipped with v0.9.79 and the initial v0.9.8 publish). Fixes the bundled-backend launch crash reported in #319 and #296 (managed_backend_exited_early:exit code: 103).',
  'UAP layer no longer serves 3-year-old NUFORC sightings via the Hugging Face static-mirror fallback (60-day cutoff now applied to the fallback path too).',
  'GPS jamming detection now counts nac_p == 0 (the actual GPS-lost signal) instead of filtering it out as an old-transponder artifact.',
  'GPS jamming thresholds lowered (MIN_AIRCRAFT 5 → 3, MIN_RATIO 0.30 → 0.20) so sparser hotspots clear the bar without losing the 1-aircraft noise cushion.',
  'AIS layer surfaces an outage banner when the AISStream WebSocket upstream is offline, instead of silently showing an empty ocean.',
  'Flight emissions tooltip now shows cumulative fuel/CO2 since first observation, not just the per-hour rate.',
  'Per-aircraft observation tracker (15-min reopen gap, 24-hour clamp) survives trail-rendering cache pruning so cumulative counters do not reset mid-flight.',
  'UAP scheduler moved daily → weekly (Mondays 12:00 UTC) to match the layer’s rolling-window cadence and reduce upstream load.',
];

const CONTRIBUTORS = [
  {
    name: '@Alienmajik',
    desc: 'Raspberry Pi 5 support — ARM64 packaging, headless deployment notes, and runtime tuning for Pi-class hardware',
  },
  {
    name: '@wa1id',
    desc: 'CCTV ingestion fix — fresh SQLite connections per ingest, persistent DB path, startup hydration, cluster clickability',
    pr: '#92',
  },
  {
    name: '@AlborzNazari',
    desc: 'Spain DGT + Madrid CCTV sources and STIX 2.1 threat intelligence export endpoint',
    pr: '#91',
  },
  {
    name: '@adust09',
    desc: 'Power plants layer, East Asia intel coverage (JSDF bases, ICAO enrichment, Taiwan news sources, military classification)',
    pr: '#71, #72, #76, #77, #87',
  },
  {
    name: '@Xpirix',
    desc: 'LocateBar style and interaction improvements',
    pr: '#78',
  },
  {
    name: '@imqdcr',
    desc: 'Ship toggle split into 4 categories + stable MMSI/callsign entity IDs for map markers',
    pr: '#52',
  },
  {
    name: '@csysp',
    desc: 'Dismissible threat alerts + stable entity IDs for GDELT & News popups + UI declutter',
    pr: '#48, #61, #63',
  },
  {
    name: '@suranyami',
    desc: 'Parallel multi-arch Docker builds (11min \u2192 3min) + runtime BACKEND_URL fix',
    pr: '#35, #44',
  },
  {
    name: '@chr0n1x',
    desc: 'Kubernetes / Helm chart architecture for high-availability deployments',
  },
  {
    name: '@johan-martensson',
    desc: 'COSMO-SkyMed satellite classification fix + yfinance batch download optimization',
    pr: '#96, #98',
  },
  {
    name: '@singularfailure',
    desc: 'Spanish CCTV feeds + image loading fix',
    pr: '#93',
  },
  {
    name: '@smithbh',
    desc: 'Makefile-based taskrunner with LAN/local access options',
    pr: '#103',
  },
  {
    name: '@OrfeoTerkuci',
    desc: 'UV project management setup',
    pr: '#102',
  },
  {
    name: '@deuza',
    desc: 'dos2unix fix for Mac/Linux quick start',
    pr: '#101',
  },
  {
    name: '@tm-const',
    desc: 'CI/CD workflow updates',
    pr: '#108, #109',
  },
  {
    name: '@Elhard1',
    desc: 'start.sh shell script fix',
    pr: '#111',
  },
  {
    name: '@ttulttul',
    desc: 'Podman compose support + frontend production CSS fix',
    pr: '#23',
  },
];

export function useChangelog() {
  const [show, setShow] = useState(false);
  useEffect(() => {
    const seen = localStorage.getItem(STORAGE_KEY);
    if (!seen) setShow(true);
  }, []);
  return { showChangelog: show, setShowChangelog: setShow };
}

interface ChangelogModalProps {
  onClose: () => void;
}

const ChangelogModal = React.memo(function ChangelogModal({ onClose }: ChangelogModalProps) {
  const handleDismiss = () => {
    localStorage.setItem(STORAGE_KEY, 'true');
    onClose();
  };

  return (
    <AnimatePresence>
      <motion.div
        key="changelog-backdrop"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[10000]"
        onClick={handleDismiss}
      />
      <motion.div
        key="changelog-modal"
        initial={{ opacity: 0, scale: 0.9, y: 20 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.9, y: 20 }}
        transition={{ type: 'spring', damping: 25, stiffness: 300 }}
        className="fixed inset-0 z-[10001] flex items-center justify-center pointer-events-none"
      >
        <div
          className="w-[700px] max-h-[90vh] bg-[var(--bg-secondary)]/98 border border-cyan-900/50 pointer-events-auto flex flex-col overflow-hidden"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="p-5 pb-3 border-b border-[var(--border-primary)]/80">
            <div className="flex items-center justify-between">
              <div>
                <div className="flex items-center gap-3">
                  <div className="px-2.5 py-1 bg-cyan-500/15 border border-cyan-500/30 text-xs font-mono font-bold text-cyan-400 tracking-widest">
                    v{CURRENT_VERSION}
                  </div>
                  <h2 className="text-base font-bold tracking-[0.15em] text-[var(--text-primary)] font-mono">
                    WHAT&apos;S NEW
                  </h2>
                </div>
                <p className="text-[11px] text-cyan-500/70 font-mono tracking-widest mt-1">
                  {RELEASE_TITLE.toUpperCase()}
                </p>
              </div>
              <button
                onClick={handleDismiss}
                className="w-8 h-8 border border-[var(--border-primary)] hover:border-red-500/50 flex items-center justify-center text-[var(--text-muted)] hover:text-red-400 transition-all hover:bg-red-950/20"
              >
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto styled-scrollbar p-5 space-y-5">
            {/* === HEADLINE PAIR: OpenClaw API + InfoNet === */}
            {HEADLINE_FEATURES.map((h, idx) => {
              const isPurple = h.accent === 'purple';
              const cardClass = isPurple
                ? 'border border-purple-500/30 bg-purple-950/20 p-4 space-y-3'
                : 'border border-cyan-500/30 bg-cyan-950/20 p-4 space-y-3';
              const iconWrapClass = isPurple
                ? 'w-9 h-9 border border-purple-500/40 bg-purple-500/10 flex items-center justify-center flex-shrink-0'
                : 'w-9 h-9 border border-cyan-500/40 bg-cyan-500/10 flex items-center justify-center flex-shrink-0';
              const titleClass = isPurple
                ? 'text-sm font-mono text-purple-300 font-bold tracking-wide'
                : 'text-sm font-mono text-cyan-300 font-bold tracking-wide';
              const subtitleClass = isPurple
                ? 'text-xs font-mono text-purple-500/80 mt-0.5'
                : 'text-xs font-mono text-cyan-500/80 mt-0.5';
              const ctaClass = isPurple
                ? 'text-[11px] font-mono text-purple-400 tracking-[0.25em] font-bold'
                : 'text-[11px] font-mono text-cyan-400 tracking-[0.25em] font-bold';

              return (
                <div key={idx} className={cardClass}>
                  <div className="flex items-center gap-3">
                    <div className={iconWrapClass}>{h.icon}</div>
                    <div>
                      <div className={titleClass}>{h.title}</div>
                      <div className={subtitleClass}>{h.subtitle}</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {h.details.map((para, i) => (
                      <p
                        key={i}
                        className="text-xs font-mono text-[var(--text-secondary)] leading-relaxed"
                      >
                        {para}
                      </p>
                    ))}
                  </div>

                  {!isPurple && (
                    <div className="flex items-start gap-2 p-2.5 border border-red-500/30 bg-red-950/20">
                      <span className="text-red-400 text-xs mt-0.5 flex-shrink-0 font-bold">!!</span>
                      <div className="space-y-1.5">
                        <span className="text-[11px] font-mono text-red-400/90 leading-relaxed block font-bold">
                          EXPERIMENTAL TESTNET &mdash; NO PRIVACY GUARANTEE
                        </span>
                        <span className="text-[11px] font-mono text-amber-400/80 leading-relaxed block">
                          InfoNet messages are obfuscated but NOT encrypted end-to-end. The Mesh
                          network (Meshtastic/APRS) is NOT private &mdash; radio transmissions are
                          inherently public. The privacy primitive contracts are scaffolded but not
                          yet wired. Treat all channels as open and public for now.
                        </span>
                      </div>
                    </div>
                  )}

                  <div className="text-center pt-1">
                    <span className={ctaClass}>{h.callToAction}</span>
                  </div>
                </div>
              );
            })}

            {/* === Required-config callout: OpenSky API === */}
            <div className="border border-amber-500/40 bg-amber-950/20 p-3 flex items-start gap-3">
              <Plane size={18} className="text-amber-400 mt-0.5 flex-shrink-0" />
              <div className="space-y-1">
                <div className="text-xs font-mono text-amber-300 font-bold tracking-wide uppercase">
                  Required: OpenSky API credentials for airplane telemetry
                </div>
                <div className="text-xs font-mono text-amber-200/80 leading-relaxed">
                  Airplane telemetry now requires an OpenSky Network OAuth2 client. Set{' '}
                  <span className="text-amber-100 font-bold">OPENSKY_CLIENT_ID</span> and{' '}
                  <span className="text-amber-100 font-bold">OPENSKY_CLIENT_SECRET</span> in your{' '}
                  <span className="text-amber-100 font-bold">.env</span>. Free registration:{' '}
                  <a
                    href="https://opensky-network.org/index.php?option=com_users&view=registration"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-amber-100 font-bold underline underline-offset-2 hover:text-amber-50"
                  >
                    opensky-network.org/register
                  </a>
                  . Without these the flights layer falls back to ADS-B-only coverage with
                  significant gaps in Africa, Asia, and Latin America, and the startup environment
                  check will surface a critical warning.
                </div>
              </div>
            </div>

            {/* === Other New Features === */}
            <div>
              <div className="text-xs font-mono tracking-[0.2em] text-cyan-400 font-bold mb-3 flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                NEW CAPABILITIES
              </div>
              <div className="space-y-2">
                {NEW_FEATURES.map((f) => (
                  <div
                    key={f.title}
                    className="flex items-start gap-3 p-3 border border-[var(--border-primary)]/50 bg-[var(--bg-primary)]/30 hover:border-[var(--border-secondary)] transition-colors"
                  >
                    <div className="mt-0.5 flex-shrink-0">{f.icon}</div>
                    <div>
                      <div className="text-[13px] font-mono text-[var(--text-primary)] font-bold">
                        {f.title}
                      </div>
                      <div className="text-xs font-mono text-[var(--text-muted)] leading-relaxed mt-0.5">
                        {f.desc}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Bug Fixes */}
            <div>
              <div className="text-xs font-mono tracking-[0.2em] text-green-400 font-bold mb-3 flex items-center gap-2">
                <Bug size={14} className="text-green-400" />
                FIXES &amp; IMPROVEMENTS
              </div>
              <div className="space-y-1.5">
                {BUG_FIXES.map((fix, i) => (
                  <div key={i} className="flex items-start gap-2 px-3 py-1.5">
                    <span className="text-green-500 text-xs mt-0.5 flex-shrink-0">+</span>
                    <span className="text-xs font-mono text-[var(--text-secondary)] leading-relaxed">
                      {fix}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Contributors */}
            <div>
              <div className="text-xs font-mono tracking-[0.2em] text-pink-400 font-bold mb-3 flex items-center gap-2">
                <Heart size={14} className="text-pink-400" />
                COMMUNITY CONTRIBUTORS
              </div>
              <div className="space-y-1.5">
                {CONTRIBUTORS.map((c, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 px-3 py-2 border border-pink-500/20 bg-pink-500/5"
                  >
                    <span className="text-pink-400 text-xs mt-0.5 flex-shrink-0">
                      &hearts;
                    </span>
                    <div>
                      <span className="text-[13px] font-mono text-pink-300 font-bold">
                        {c.name}
                      </span>
                      <span className="text-xs font-mono text-[var(--text-muted)]">
                        {' '}
                        &mdash; {c.desc}
                      </span>
                      {c.pr && (
                        <span className="text-[11px] font-mono text-[var(--text-muted)]">
                          {' '}
                          (PR {c.pr})
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="p-4 border-t border-[var(--border-primary)]/80 flex items-center justify-center">
            <button
              onClick={handleDismiss}
              className="px-8 py-2.5 bg-cyan-500/15 border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/25 text-xs font-mono tracking-[0.2em] transition-all"
            >
              ACKNOWLEDGED
            </button>
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
});

export default ChangelogModal;
