<template>
  <div class="agent-mode">
    <div class="am-toggle" role="group" aria-label="Audience">
      <span :class="{ on: !agents }" @click="setMode(false)">For humans</span>
      <button
        type="button"
        role="switch"
        class="am-switch"
        :aria-checked="agents"
        aria-label="For agents"
        @click="setMode(!agents)"
      ><i /></button>
      <span :class="{ on: agents }" @click="setMode(true)">For agents</span>
    </div>

    <!-- Human view: the existing homepage content, unchanged -->
    <div v-show="!agents">
      <slot />
    </div>

    <!-- Agent view -->
    <div v-if="agents" class="am-panel">
      <div class="am-code" aria-hidden="true">{{ backgroundCode }}</div>

      <div class="am-card">
        <p class="am-prompt">&gt; @agents, check my stack<span class="am-cursor" /></p>

        <div class="am-instr">
          <code>Set up CyberOwl AI by reading {{ skillUrl }} and following its instructions.</code>
          <button type="button" class="am-copy" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button>
        </div>

        <div class="am-captcha">
          <div class="am-cap-head">
            <strong>Prove you're not human</strong>
            <span>Patch every dependency.</span>
          </div>
          <div class="am-grid" role="group" aria-label="Patch every dependency">
            <button
              v-for="(patched, i) in tiles"
              :key="deps[i]"
              type="button"
              class="am-tile"
              :class="{ ok: patched }"
              :aria-pressed="patched"
              :aria-label="`${deps[i]}, ${patched ? 'patched' : 'vulnerable'}`"
              @click="flip(i)"
            >
              <span class="am-icon">{{ patched ? '✓' : '⚠' }}</span>{{ deps[i] }}
            </button>
          </div>
          <div class="am-cap-foot">
            <div>
              <button type="button" title="Reset puzzle" @click="reset">↺</button>
              <button type="button" title="About this puzzle" @click="status = 'Patching one breaks another. No solution.'">?</button>
            </div>
            <span class="am-status" role="status">{{ status || `${patchedCount} / 9 patched` }}</span>
            <button type="button" class="am-verify" @click="status = 'Human detected.'">Verify</button>
          </div>
        </div>

      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'

const skillUrl = 'https://cyberowlai.com/skill/SKILL.md'
const deps = ['openssl', 'log4j', 'lodash', 'nginx', 'django', 'node', 'redis', 'curl', 'react']
// 3 vulnerable tiles + every click flips 2 tiles => the vulnerable count stays odd, so it never reaches 0.
const START = [false, true, true, true, false, true, true, true, false]

const agents = ref(false)
const tiles = ref([...START])
const status = ref('')
const copied = ref(false)
const patchedCount = computed(() => tiles.value.filter(Boolean).length)

const backgroundCode = (
  'const stack = scan(["package.json", "poetry.lock", "Dockerfile", ".github/workflows"]); ' +
  'const alerts = await fetch("https://cyberowlai.com/alerts.json"); ' +
  'for (const src of ["US-CERT", "CERT-FR", "MA-CERT", "HK-CERT", "CA-CCS", "EU-CERT", "VulDB", "ZDI"]) { triage(alerts.sources[src]); } ' +
  'const hits = alerts.filter(a => stack.uses(a.product)).sort(by_severity); ' +
  '// relevance > noise. your stack > the whole internet. ' +
  'if (hits.some(is_zero_day)) { flag("critical"); } ' +
  'report(hits, { confidence: "tiered", fix: suggest_upgrade }); ' +
  'while (human.is_shipping) { watch(certs); match(stack); warn_early(); } '
).repeat(10)

function setMode(value) {
  agents.value = value
  const url = new URL(window.location.href)
  if (value) url.searchParams.set('audience', 'agents')
  else url.searchParams.delete('audience')
  window.history.replaceState(window.history.state, '', url)
}

function flip(i) {
  const next = [...tiles.value]
  next[i] = !next[i]
  next[(i + 1) % 9] = !next[(i + 1) % 9]
  tiles.value = next
  status.value = ''
}

function reset() {
  tiles.value = [...START]
  status.value = ''
}

async function copy() {
  try {
    await navigator.clipboard.writeText(`Set up CyberOwl AI by reading ${skillUrl} and following its instructions.`)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {
    /* clipboard unavailable */
  }
}

onMounted(() => {
  agents.value = new URLSearchParams(window.location.search).get('audience') === 'agents'
})
</script>

<style lang="scss" scoped>
$brand: #3eaf7c;
$mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

.am-toggle {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 10px;
  margin: 0 0 2rem;
  font-family: $mono;
  font-size: 0.85rem;
  color: var(--vp-c-text-mute, #888);

  span { cursor: pointer; }
  span.on { color: var(--vp-c-text, inherit); font-weight: 600; }
}

.am-switch {
  position: relative;
  width: 46px;
  height: 24px;
  padding: 0;
  border: 1px solid var(--vp-c-border, #ddd);
  border-radius: 6px;
  background: transparent;
  cursor: pointer;

  i {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 18px;
    height: 16px;
    border-radius: 3px;
    background: var(--vp-c-text-mute, #999);
    transition: left 0.2s ease, background 0.2s ease;
  }

  &[aria-checked='true'] i { left: 23px; background: $brand; }
}

.am-panel {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--vp-c-border, #ddd);
  border-radius: 10px;
  padding: 2.5rem 1rem;
}

.am-code {
  position: absolute;
  inset: 0;
  padding: 1rem;
  font-family: $mono;
  font-size: 0.72rem;
  line-height: 1.6;
  word-break: break-all;
  opacity: 0.18;
  pointer-events: none;
  animation: am-scroll 60s linear infinite;
}

@keyframes am-scroll { to { transform: translateY(-50%); } }

.am-card {
  position: relative;
  max-width: 440px;
  margin: 0 auto;
  padding: 1.25rem;
  border: 1px solid var(--vp-c-border, #ddd);
  border-radius: 10px;
  background: var(--vp-c-bg, #fff);
}

.am-prompt {
  margin: 0 0 1rem;
  font-family: $mono;
  font-size: 1.1rem;
}

.am-cursor {
  display: inline-block;
  width: 8px;
  height: 1.1em;
  margin-left: 3px;
  vertical-align: text-bottom;
  background: $brand;
  animation: am-blink 1s steps(1) infinite;
}

@keyframes am-blink { 50% { opacity: 0; } }

.am-instr {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 1.25rem;

  code {
    padding: 0;
    background: none;
    font-size: 0.8rem;
    line-height: 1.5;
    word-break: break-all;
  }
}

.am-copy,
.am-cap-foot button {
  border: 1px solid var(--vp-c-border, #ddd);
  border-radius: 5px;
  padding: 2px 8px;
  background: transparent;
  color: inherit;
  font-size: 0.75rem;
  cursor: pointer;
}

.am-captcha {
  width: 280px;
  margin: 0 auto;
  overflow: hidden;
  border: 2px solid var(--vp-c-border, #ddd);
  border-radius: 6px;
  font-family: $mono;
}

.am-cap-head {
  padding: 12px 14px;
  background: $brand;
  color: #fff;

  strong { display: block; font-size: 1rem; font-weight: 500; }
  span { font-size: 0.7rem; opacity: 0.9; }
}

.am-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2px;
  background: var(--vp-c-border, #ddd);
}

.am-tile {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 4px;
  aspect-ratio: 1 / 1;
  border: 0;
  background: #fbe9eb;
  color: #c0392b;
  font-family: $mono;
  font-size: 0.7rem;
  cursor: pointer;
  transition: background 0.15s ease;

  &.ok { background: $brand; color: #fff; }
}

.am-icon { font-size: 1.15rem; }

.am-cap-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  padding: 8px 10px;
  font-size: 0.7rem;

  div { display: flex; gap: 4px; }
}

.am-status { color: var(--vp-c-text-mute, #888); text-align: center; }

.am-cap-foot .am-verify {
  border-color: $brand;
  background: $brand;
  color: #fff;
  font-weight: 600;
}

html.dark .am-tile:not(.ok) { background: #3a1d22; color: #ff6b6b; }
</style>
