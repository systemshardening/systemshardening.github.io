(function () {
  'use strict';

  if (!window.speechSynthesis) return;

  /* ── Language → spoken label map ── */
  var LANG_LABELS = {
    bash: 'shell command snippet',
    sh: 'shell command snippet',
    shell: 'shell command snippet',
    zsh: 'shell command snippet',
    powershell: 'shell command snippet',
    yaml: 'configuration snippet',
    yml: 'configuration snippet',
    json: 'configuration snippet',
    toml: 'configuration snippet',
    ini: 'configuration snippet',
    conf: 'configuration snippet',
    config: 'configuration snippet',
    hcl: 'configuration snippet',
    tf: 'configuration snippet',
    tfvars: 'configuration snippet',
    xml: 'configuration snippet',
    dockerfile: 'configuration snippet',
    nginx: 'configuration snippet',
    apache: 'configuration snippet',
    wat: 'code snippet',
  };

  function getCodeLabel(preEl) {
    var code = preEl.querySelector('code');
    if (!code) return 'code snippet';
    var cls = code.className || '';
    var m = cls.match(/language-(\w+)/);
    if (!m) return 'code snippet';
    return LANG_LABELS[m[1].toLowerCase()] || 'code snippet';
  }

  /* ── DOM walker: collect speakable segments ── */
  function extractSegments(root) {
    var segments = [];

    function walk(node) {
      if (node.nodeType !== 1) return; // Element nodes only
      var tag = node.tagName.toLowerCase();

      // Code blocks → label only, no recursion
      if (tag === 'pre') {
        segments.push(getCodeLabel(node));
        return;
      }

      // Permalink anchors injected by markdown-it-anchor → skip
      if (tag === 'a' && node.classList.contains('header-anchor')) return;

      // Tables → skip (read poorly as audio)
      if (tag === 'table') {
        segments.push('table omitted');
        return;
      }

      // Headings → read clean text
      if (/^h[1-6]$/.test(tag)) {
        var txt = (node.innerText || node.textContent || '').replace(/[¶#§]/g, '').trim();
        if (txt) segments.push(txt);
        return;
      }

      // Block text elements → read inner text including inline code values
      if (['p', 'li', 'dt', 'dd', 'blockquote'].indexOf(tag) !== -1) {
        // Clone only to strip permalink anchors; inline <code> text is kept
        var clone = node.cloneNode(true);
        clone.querySelectorAll('.header-anchor').forEach(function (el) { el.remove(); });
        var text = (clone.innerText || clone.textContent || '').replace(/[¶#§]/g, '').trim();
        if (text) segments.push(text);
        return;
      }

      // Recurse into everything else (section, div, article, etc.)
      for (var i = 0; i < node.childNodes.length; i++) {
        walk(node.childNodes[i]);
      }
    }

    for (var i = 0; i < root.childNodes.length; i++) {
      walk(root.childNodes[i]);
    }
    return segments;
  }

  /* ── Voice selection: prefer female English ── */
  var FEMALE_HINTS = [
    'samantha', 'victoria', 'karen', 'moira', 'veena', 'tessa',
    'fiona', 'allison', 'ava', 'susan', 'zira', 'hazel', 'linda',
    'female', 'woman',
    'google uk english female',
    'microsoft zira',
    'google us english',
  ];

  var selectedVoice = null;

  function pickVoice() {
    var voices = speechSynthesis.getVoices();
    var en = voices.filter(function (v) { return v.lang && v.lang.startsWith('en'); });
    for (var i = 0; i < en.length; i++) {
      var name = en[i].name.toLowerCase();
      for (var j = 0; j < FEMALE_HINTS.length; j++) {
        if (name.indexOf(FEMALE_HINTS[j]) !== -1) return en[i];
      }
    }
    // Fallback: en-US then any English then anything
    return en.find(function (v) { return v.lang === 'en-US'; }) || en[0] || voices[0] || null;
  }

  function initVoice() { selectedVoice = pickVoice(); }
  initVoice();
  if ('onvoiceschanged' in speechSynthesis) {
    speechSynthesis.onvoiceschanged = initVoice;
  }

  /* ── Build utterance list (chunked for browser reliability) ── */
  var CHUNK_CHARS = 180;

  function buildUtterances(segments) {
    var utts = [];
    var chunk = '';

    function flush() {
      var t = chunk.trim();
      if (!t) return;
      var utt = new SpeechSynthesisUtterance(t);
      if (selectedVoice) utt.voice = selectedVoice;
      utt.lang = 'en-US';
      utt.rate = 0.92;
      utt.pitch = 1.05;
      utts.push(utt);
      chunk = '';
    }

    for (var i = 0; i < segments.length; i++) {
      var seg = segments[i];
      if (chunk.length + seg.length > CHUNK_CHARS) flush();
      chunk += seg + '. ';
    }
    flush();
    return utts;
  }

  /* ── Playback state machine ── */
  var utterances = [];
  var currentIndex = 0;
  var state = 'stopped'; // 'stopped' | 'playing' | 'paused'

  function updateBtn(btn) {
    if (!btn) return;
    var icon = btn.querySelector('.tts-icon');
    var label = btn.querySelector('.tts-label');
    if (state === 'playing') {
      icon.textContent = '⏸';
      label.textContent = 'Pause';
      btn.setAttribute('aria-label', 'Pause audio');
      btn.classList.add('tts-btn--active');
    } else if (state === 'paused') {
      icon.textContent = '▶';
      label.textContent = 'Resume';
      btn.setAttribute('aria-label', 'Resume audio');
      btn.classList.add('tts-btn--active');
    } else {
      icon.textContent = '▶';
      label.textContent = 'Listen';
      btn.setAttribute('aria-label', 'Listen to article');
      btn.classList.remove('tts-btn--active');
    }
  }

  function speakFrom(idx, btn) {
    if (idx >= utterances.length) {
      state = 'stopped';
      currentIndex = 0;
      updateBtn(btn);
      return;
    }
    currentIndex = idx;
    var utt = utterances[idx];
    utt.onend = function () { speakFrom(idx + 1, btn); };
    utt.onerror = function () { speakFrom(idx + 1, btn); };
    speechSynthesis.speak(utt);
  }

  /* ── Public API ── */
  function toggle(btn) {
    if (!window.speechSynthesis) return;

    if (state === 'playing') {
      speechSynthesis.cancel();
      state = 'paused';
      updateBtn(btn);
      return;
    }

    if (state === 'paused') {
      state = 'playing';
      updateBtn(btn);
      speakFrom(currentIndex, btn);
      return;
    }

    // Stopped → start
    speechSynthesis.cancel();
    var contentEl = document.querySelector('.article-content');
    if (!contentEl) return;

    if (!selectedVoice) initVoice();

    var segments = extractSegments(contentEl);
    utterances = buildUtterances(segments);
    currentIndex = 0;
    state = 'playing';
    updateBtn(btn);
    speakFrom(0, btn);
  }

  function stop(btn) {
    speechSynthesis.cancel();
    state = 'stopped';
    currentIndex = 0;
    updateBtn(btn);
  }

  window.addEventListener('pagehide', function () { speechSynthesis.cancel(); });
  window.addEventListener('beforeunload', function () { speechSynthesis.cancel(); });

  window.ArticleTTS = { toggle: toggle, stop: stop };

  /* ── Wire button on load ── */
  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('tts-btn');
    if (!btn) return;
    btn.addEventListener('click', function () { toggle(btn); });
  });
})();
