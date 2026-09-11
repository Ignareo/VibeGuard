#!/usr/bin/env node
// VibeGuard precheck hook for Kimi Code CLI.
// Reads the hook payload from stdin, scans the submitted text (user prompt or
// bash command) for secrets, and blocks (exit 2) with a redacted reason when
// something matches. Fail-open by design: any error exits 0.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pluginRoot =
  process.env.KIMI_PLUGIN_ROOT ||
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadRules() {
  const cfgPath = path.join(pluginRoot, 'patterns.json');
  let cfg = {};
  try {
    cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
  } catch {
    // Missing/unreadable config: no-op (same safety model as opencode-vibeguard).
  }
  if (cfg.enabled === false) process.exit(0);

  const rules = [];
  for (const kw of cfg.keywords ?? []) {
    const value = typeof kw === 'string' ? kw : kw?.value;
    if (typeof value === 'string' && value.length > 0) {
      rules.push({ name: typeof kw === 'object' && kw?.label ? kw.label : 'keyword', test: (t) => t.includes(value) });
    }
  }
  for (const entry of cfg.regex ?? []) {
    const pattern = typeof entry === 'string' ? entry : entry?.pattern;
    try {
      const re = new RegExp(pattern);
      rules.push({ name: typeof entry === 'object' && entry?.label ? entry.label : 'regex', test: (t) => re.test(t) });
    } catch {
      // Ignore invalid patterns.
    }
  }
  return rules;
}

// Built-in detectors for common credential shapes. Never include the matched
// secret itself in any output.
const BUILTIN = [
  { name: 'private-key-block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/ },
  { name: 'openai-style-key', re: /\bsk-[A-Za-z0-9_-]{16,}\b/ },
  { name: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/ },
  { name: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/ },
  { name: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'volcengine-ark-key', re: /\bark-[0-9a-f-]{20,}\b/ },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
];

function extractText(payload) {
  const event = payload?.hook_event_name;
  if (event === 'UserPromptSubmit' || event === 'UserPromptQueued' || event === 'TurnStarted') {
    const prompt = payload?.prompt ?? payload?.user_prompt ?? payload?.text ?? '';
    // Kimi Code sends prompt as content parts: [{type:"text", text:"..."}].
    if (Array.isArray(prompt)) {
      return prompt.map((p) => (typeof p === 'string' ? p : p?.text ?? '')).join('\n');
    }
    return typeof prompt === 'string' ? prompt : '';
  }
  if (event === 'PreToolUse') {
    const cmd = payload?.tool_input?.command;
    return typeof cmd === 'string' ? cmd : '';
  }
  return '';
}

let input = '';
process.stdin.on('data', (chunk) => (input += chunk));
process.stdin.on('end', () => {
  let payload = {};
  try {
    payload = JSON.parse(input);
  } catch {
    process.exit(0);
  }

  const text = extractText(payload);
  if (!text) process.exit(0);

  const rules = [...loadRules(), ...BUILTIN.map((b) => ({ name: b.name, test: (t) => b.re.test(t) }))];
  const hit = rules.find((r) => r.test(text));
  if (hit) {
    console.error(
      `[vibeguard-precheck] blocked: sensitive content detected (${hit.name}). ` +
        `Remove the secret from your input, or route this session through the VibeGuard proxy (vibeguard kimi) to redact it automatically.`
    );
    process.exit(2);
  }
  process.exit(0);
});
