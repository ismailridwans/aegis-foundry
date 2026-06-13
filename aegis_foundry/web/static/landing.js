/* ============================================================================
   AEGIS FOUNDRY — landing page script

   Design note: the scroll-critical work (reveals, nav, the pipeline forge-line
   scrub, count-up/typewriter triggers) is driven by scroll + resize EVENTS,
   plus one call on boot. Events fire reliably even when requestAnimationFrame
   is throttled (background tab, headless), so the page never gets stuck with
   content faded out. A tiny rAF loop is used ONLY for the cosmetic mouse
   parallax, where smoothing matters and a paused frame is invisible anyway.

   Reveals are polled with getBoundingClientRect rather than IntersectionObserver
   because the pipeline section is `position: sticky` inside an `overflow: hidden`
   stage — a context where IO callbacks are unreliable.
   ========================================================================== */

(function () {
  'use strict';

  /* ── Helpers ────────────────────────────────────────────────────────────── */

  function qs(sel, root) { return (root || document).querySelector(sel); }
  function qsa(sel, root) { return Array.from((root || document).querySelectorAll(sel)); }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function clamp(v, lo, hi) { return v < lo ? lo : v > hi ? hi : v; }

  var prefersReduced = window.matchMedia &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ── Elements ───────────────────────────────────────────────────────────── */

  var nav       = qs('#nav');
  var skyPar    = qs('#sky-par');
  var forgeLine = qs('#forge-line');
  var forgeGlow = qs('#forge-glow');
  var pipeTrack = qs('#pipeline');
  var pipeNodes = qsa('.pipe-node');
  var caps      = qsa('.cap');
  var metrics   = qs('#metrics');
  var termEl    = qs('#terminal');

  var revealEls = qsa('.reveal').concat(qsa('[data-stagger]'));

  /* ── State ──────────────────────────────────────────────────────────────── */

  var mouseX = 0, mouseY = 0, cPX = 0, cPY = 0;
  var scrollPar = 0;
  var pathLen = 0;
  var countStarted = false;
  var termStarted  = false;

  var CAP_THRESHOLDS = [0, 0.28, 0.56, 0.82];

  /* ── Forge line init (needs layout + fonts) ─────────────────────────────── */

  function initForgeLine() {
    if (!forgeLine) return;
    pathLen = forgeLine.getTotalLength();
    forgeLine.style.strokeDasharray = pathLen;
    if (forgeGlow) forgeGlow.style.strokeDasharray = pathLen;
    onScroll(); // paint the correct offset immediately
  }

  /* ── Count-up ───────────────────────────────────────────────────────────── */

  function animateCount(el) {
    var from     = parseFloat(el.dataset.countFrom) || 0;
    var to       = parseFloat(el.dataset.countTo)   || 0;
    var decimals = parseInt(el.dataset.decimals, 10) || 0;
    var suffix   = el.dataset.suffix || '';
    if (prefersReduced) { el.textContent = to.toFixed(decimals) + suffix; return; }

    var duration = 1900, startTs = null;
    function frame(ts) {
      if (startTs === null) startTs = ts;
      var p = Math.min((ts - startTs) / duration, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = (from + (to - from) * eased).toFixed(decimals) + suffix;
      if (p < 1) requestAnimationFrame(frame);
    }
    /* setTimeout fallback in case rAF is throttled: jump to final value. */
    requestAnimationFrame(frame);
    setTimeout(function () { el.textContent = to.toFixed(decimals) + suffix; }, duration + 400);
  }

  function startCounts() { qsa('[data-count-to]', metrics).forEach(animateCount); }

  /* ── Typewriter terminal ─────────────────────────────────────────────────── */

  var LINES = [
    { t: '$ aegis-foundry run --advisory CISA-AA26-117A',               c: 't-brand'   },
    { t: '', c: 'gap' },
    { t: '[intel-scout]    loading advisories…',                   c: 't-dim'     },
    { t: '[intel-scout]    T1059.001 PowerShell — risk 8.5',       c: 't-cyan'    },
    { t: '[intel-scout]    T1003.001 LSASS — already covered ✓', c: 't-dim'  },
    { t: '', c: 'gap' },
    { t: '[cartographer]   scanning 4 existing saved-searches',         c: 't-dim'     },
    { t: '[cartographer]   GAP: T1059.001 not covered',                 c: 't-rose'    },
    { t: '', c: 'gap' },
    { t: '[author]         drafting SPL v1…',                      c: 't-dim'     },
    { t: '[author]         validate → PASS (round 1)',             c: 't-emerald' },
    { t: '', c: 'gap' },
    { t: '[backtest]       replaying 90 days…',                    c: 't-dim'     },
    { t: '[backtest]       5,818 hits  recall=1.00  precision=0.003',   c: 't-gold'    },
    { t: '', c: 'gap' },
    { t: '[forecaster]     | apply CDTSM forecast_k=14',                c: 't-dim'     },
    { t: '[forecaster]     382.3 alerts/week — OVER BUDGET',       c: 't-rose'    },
    { t: '', c: 'gap' },
    { t: '[optimizer]      tightening rule…  pass 1/3',            c: 't-dim'     },
    { t: '[optimizer]      SPL v2 forecast: 2.7/week ✓',           c: 't-emerald' },
    { t: '', c: 'gap' },
    { t: '[governor]       7/7 policy checks PASS',                     c: 't-emerald' },
    { t: '[governor]       ⏳ awaiting human approval…',       c: 't-gold'    },
    { t: '[governor]       ✓ approved by human:operator',          c: 't-bright'  },
    { t: '', c: 'gap' },
    { t: '[deployer]       savedsearch T1059.001-powershell-v2 created', c: 't-cyan'   },
    { t: '', c: 'gap' },
    { t: '[verifier]       week-1: 3.0/week  forecast: 2.7  drift: 1.11', c: 't-violet' },
    { t: '[verifier]       within 90% confidence band — action: ok ✓', c: 't-emerald' },
    { t: '', c: 'gap' },
    { t: 'pipeline DONE  ·  9 agents  ·  1 detection forged',  c: 't-bright'  },
  ];

  function renderLineInstant(body, d) {
    if (d.c === 'gap') {
      var g = document.createElement('span');
      g.style.display = 'block'; g.style.height = '0.6em';
      body.appendChild(g);
      return;
    }
    var s = document.createElement('span');
    s.className = d.c; s.textContent = d.t;
    body.appendChild(s);
  }

  function startTypewriter() {
    var body = qs('#term-body');
    if (!body) return;
    body.innerHTML = '';

    if (prefersReduced) { LINES.forEach(function (d) { renderLineInstant(body, d); }); return; }

    var i = 0;
    function nextLine() {
      if (i >= LINES.length) {
        var cur = document.createElement('span');
        cur.className = 't-cursor';
        body.appendChild(cur);
        return;
      }
      var d = LINES[i++];
      if (d.c === 'gap') {
        var gap = document.createElement('span');
        gap.style.display = 'block'; gap.style.height = '0.6em';
        body.appendChild(gap);
        body.scrollTop = body.scrollHeight;
        setTimeout(nextLine, 55);
        return;
      }
      var span = document.createElement('span');
      span.className = d.c;
      body.appendChild(span);

      var ci = 0, text = d.t;
      var speed = text.charAt(0) === '$' ? 30 : 10;
      var pause = d.c === 't-dim' ? 65 : 165;
      function typeChar() {
        if (ci < text.length) {
          span.textContent += text.charAt(ci++);
          body.scrollTop = body.scrollHeight;
          setTimeout(typeChar, speed);
        } else {
          setTimeout(nextLine, pause);
        }
      }
      typeChar();
    }
    nextLine();
  }

  /* ── Scroll-driven core (runs on scroll, resize, and once on boot) ──────── */

  function updateReveals(vh) {
    if (!revealEls.length) return;
    var trigger = vh * 0.86;
    var remaining = [];
    for (var i = 0; i < revealEls.length; i++) {
      var el = revealEls[i];
      if (el.getBoundingClientRect().top < trigger) el.classList.add('entered');
      else remaining.push(el);
    }
    revealEls = remaining;
  }

  function updateNav() {
    if (!nav) return;
    if (window.scrollY > 80) nav.classList.add('visible');
    else nav.classList.remove('visible');
  }

  function updatePipeline(vh) {
    if (!pipeTrack || !forgeLine || pathLen === 0) return;
    var rect   = pipeTrack.getBoundingClientRect();
    var trackH = rect.height - vh;
    var p      = clamp(-rect.top / Math.max(trackH, 1), 0, 1);

    var offset = pathLen * (1 - p);
    forgeLine.style.strokeDashoffset = offset;
    if (forgeGlow) forgeGlow.style.strokeDashoffset = offset;

    var n = pipeNodes.length;
    for (var i = 0; i < n; i++) {
      pipeNodes[i].classList.toggle('lit', p >= (i / Math.max(n - 1, 1)) - 0.001);
    }

    var active = 0;
    for (var j = 0; j < CAP_THRESHOLDS.length; j++) {
      if (p >= CAP_THRESHOLDS[j]) active = j;
    }
    for (var k = 0; k < caps.length; k++) {
      caps[k].classList.toggle('on', k === active);
    }
  }

  function updateTriggers(vh) {
    if (!countStarted && metrics && metrics.getBoundingClientRect().top < vh * 0.82) {
      countStarted = true; startCounts();
    }
    if (!termStarted && termEl && termEl.getBoundingClientRect().top < vh * 0.80) {
      termStarted = true; startTypewriter();
    }
  }

  function onScroll() {
    var vh = window.innerHeight;
    scrollPar = -window.scrollY * 0.12;
    applyParallax();
    updateNav();
    updateReveals(vh);
    updatePipeline(vh);
    updateTriggers(vh);
  }

  /* ── Mouse parallax (rAF, cosmetic only) ────────────────────────────────── */

  function applyParallax() {
    if (!skyPar) return;
    skyPar.style.transform =
      'translate3d(' + cPX.toFixed(2) + 'px,' + (cPY + scrollPar).toFixed(2) + 'px,0)';
  }

  if (!prefersReduced && skyPar) {
    window.addEventListener('mousemove', function (e) {
      mouseX = (e.clientX / window.innerWidth  - 0.5) * 14;
      mouseY = (e.clientY / window.innerHeight - 0.5) * 14;
    }, { passive: true });

    (function parallaxLoop() {
      cPX = lerp(cPX, mouseX, 0.06);
      cPY = lerp(cPY, mouseY, 0.06);
      applyParallax();
      requestAnimationFrame(parallaxLoop);
    })();
  }

  /* ── Wire events ────────────────────────────────────────────────────────── */

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });

  function boot() {
    initForgeLine();
    var hero = qs('.hero [data-stagger]');
    if (hero) hero.classList.add('entered');
    onScroll();
  }

  if (document.readyState === 'complete') boot();
  else window.addEventListener('load', boot);

  /* Run once immediately too (don't wait for load) so above-fold reveals show. */
  onScroll();

  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(initForgeLine);
  }

})();
