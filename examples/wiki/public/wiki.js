/* SPDX-License-Identifier: Apache-2.0 */
/* global document, window, navigator, IntersectionObserver, location */
"use strict";
// pkijs.com client enhancements. One readable vanilla file, served
// content-hashed (lib/assets.js). Everything here is additive: the site
// reads, navigates, and searches (the /search form) without JavaScript.
//
//   1. Copy buttons on code blocks.
//   2. Heading anchor links copy the deep-link URL to the clipboard.
//   3. An "On this page" rail built from the rendered primitive sections,
//      with IntersectionObserver scroll-spy (only at >= 1280px via CSS).
//   4. Symbol autocomplete over /symbols.json with a "/" focus hotkey.

(function () {

  // ---- clipboard helper (secure-context API with a fallback) ----
  function copyText(text, onDone) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { onDone(true); }, function () { onDone(false); });
      return;
    }
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "absolute";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    var ok;
    try { ok = document.execCommand("copy"); } catch (_e) { ok = false; }
    document.body.removeChild(ta);
    onDone(ok);
  }

  // ---- 1. copy buttons on every code block in main ----
  function attachCopyButtons() {
    var pres = document.querySelectorAll("main pre");
    for (var i = 0; i < pres.length; i++) {
      (function (pre) {
        var code = pre.querySelector("code");
        if (!code) return;
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "copy-btn";
        btn.textContent = "Copy";
        btn.setAttribute("aria-label", "Copy code to clipboard");
        btn.addEventListener("click", function () {
          copyText(code.innerText, function (ok) {
            btn.textContent = ok ? "Copied" : "Error";
            btn.classList.add("is-done");
            window.setTimeout(function () {
              btn.textContent = "Copy";
              btn.classList.remove("is-done");
            }, 1200);
          });
        });
        pre.appendChild(btn);
      })(pres[i]);
    }
  }

  // ---- 2. heading anchors copy the sharable deep link ----
  function attachAnchorCopy() {
    var links = document.querySelectorAll("main section.primitive > h2 > a[href^='#'], main h2[id] > a[href^='#']");
    for (var i = 0; i < links.length; i++) {
      (function (a) {
        a.addEventListener("click", function (ev) {
          ev.preventDefault();
          var frag = a.getAttribute("href");
          var url = location.origin + location.pathname + frag;
          if (window.history && window.history.replaceState) {
            window.history.replaceState(null, "", frag);
          } else {
            location.hash = frag;
          }
          copyText(url, function () {});
        });
      })(links[i]);
    }
  }

  // ---- 3. "On this page" rail + scroll-spy ----
  // Collect the anchored targets: primitive sections carry the id on the
  // <section>, generated reference/concept headings carry it on the <h2>.
  function collectHeadings() {
    var out = [];
    var sections = document.querySelectorAll("main section.primitive[id]");
    var i;
    for (i = 0; i < sections.length; i++) {
      var h = sections[i].querySelector("h2");
      if (h) out.push({ id: sections[i].id, text: h.textContent, el: sections[i] });
    }
    if (out.length) return out;
    var heads = document.querySelectorAll("main h2[id]");
    for (i = 0; i < heads.length; i++) {
      out.push({ id: heads[i].id, text: heads[i].textContent, el: heads[i] });
    }
    return out;
  }

  function buildToc() {
    var heads = collectHeadings();
    if (heads.length < 2) return;
    var rail = document.createElement("aside");
    rail.className = "toc-rail";
    rail.setAttribute("aria-label", "On this page");
    var title = document.createElement("div");
    title.className = "toc-title";
    title.textContent = "On this page";
    rail.appendChild(title);
    var ul = document.createElement("ul");
    var byId = {};
    for (var i = 0; i < heads.length; i++) {
      var li = document.createElement("li");
      var a = document.createElement("a");
      a.href = "#" + heads[i].id;
      a.textContent = heads[i].text;
      li.appendChild(a);
      ul.appendChild(li);
      byId[heads[i].id] = a;
    }
    rail.appendChild(ul);
    var wrap = document.querySelector(".wrap");
    if (!wrap) return;
    wrap.appendChild(rail);

    if (typeof IntersectionObserver !== "function") return;
    var active = null;
    var io = new IntersectionObserver(function (entries) {
      for (var j = 0; j < entries.length; j++) {
        if (!entries[j].isIntersecting) continue;
        var id = entries[j].target.id;
        if (active) active.classList.remove("is-active");
        active = byId[id];
        if (active) active.classList.add("is-active");
      }
    }, { rootMargin: "0px 0px -75% 0px" });
    for (var k = 0; k < heads.length; k++) io.observe(heads[k].el);
  }

  // ---- 4. symbol autocomplete over /symbols.json ----
  function scoreSymbol(bare, q) {
    if (bare === q) return 100;
    if (bare.indexOf(q) === 0) return 80;
    if (bare.indexOf("." + q) !== -1) return 60;
    if (bare.indexOf(q) !== -1) return 40;
    // subsequence: every query char appears in order
    var bi = 0;
    for (var qi = 0; qi < q.length; qi++) {
      bi = bare.indexOf(q.charAt(qi), bi);
      if (bi === -1) return 0;
      bi += 1;
    }
    return 20;
  }

  function attachSymbolSearch() {
    var input = document.getElementById("symq");
    var list = document.getElementById("symq-results");
    if (!input || !list) return;

    var symbols = null;
    var loading = false;
    var pending = [];
    var cursor = -1;

    // Callbacks that arrive while the manifest fetch is in flight are
    // queued, not dropped — a fast typist's last keystroke must still
    // render results once the fetch lands.
    function load(then) {
      if (symbols) { then(); return; }
      pending.push(then);
      if (loading) return;
      loading = true;
      function settle(data) {
        symbols = data;
        var run = pending;
        pending = [];
        for (var i = 0; i < run.length; i++) run[i]();
      }
      fetch("/symbols.json").then(function (r) { return r.json(); }).then(function (data) {
        settle(Array.isArray(data.symbols) ? data.symbols : []);
      }, function () { settle([]); });
    }

    function close() {
      list.hidden = true;
      list.textContent = "";
      cursor = -1;
    }

    function render(matches) {
      list.textContent = "";
      for (var i = 0; i < matches.length; i++) {
        var li = document.createElement("li");
        li.setAttribute("role", "option");
        var a = document.createElement("a");
        a.href = matches[i].page + "#" + matches[i].anchor;
        a.textContent = matches[i].sig;
        var pg = document.createElement("span");
        pg.className = "sym-page";
        pg.textContent = matches[i].title;
        a.appendChild(pg);
        li.appendChild(a);
        list.appendChild(li);
      }
      cursor = matches.length ? 0 : -1;
      highlight();
      list.hidden = matches.length === 0;
    }

    function highlight() {
      var items = list.children;
      for (var i = 0; i < items.length; i++) {
        items[i].classList.toggle("is-active", i === cursor);
      }
    }

    function update() {
      // Lowercase BEFORE stripping the prefix so a mobile keyboard's
      // auto-capitalized "Pki." still strips.
      var q = input.value.toLowerCase().replace(/^\s*pki\./, "").replace(/\s+/g, "");
      if (!q) { close(); return; }
      var scored = [];
      for (var i = 0; i < symbols.length; i++) {
        var s = scoreSymbol(symbols[i].bare.toLowerCase(), q);
        if (s > 0) scored.push({ score: s, sym: symbols[i] });
      }
      scored.sort(function (a, b) { return b.score - a.score || (a.sym.bare < b.sym.bare ? -1 : 1); });
      render(scored.slice(0, 12).map(function (x) { return x.sym; }));
    }

    input.addEventListener("focus", function () { load(function () {}); });
    input.addEventListener("input", function () { load(update); });
    input.addEventListener("keydown", function (ev) {
      var items = list.children;
      if (ev.key === "ArrowDown" && items.length) {
        ev.preventDefault();
        cursor = (cursor + 1) % items.length;
        highlight();
      } else if (ev.key === "ArrowUp" && items.length) {
        ev.preventDefault();
        cursor = (cursor - 1 + items.length) % items.length;
        highlight();
      } else if (ev.key === "Enter" && cursor >= 0 && items[cursor]) {
        ev.preventDefault();
        var a = items[cursor].querySelector("a");
        if (a) location.href = a.href;
      } else if (ev.key === "Escape") {
        close();
        input.blur();
      }
    });
    document.addEventListener("click", function (ev) {
      if (!list.hidden && !list.contains(ev.target) && ev.target !== input) close();
    });

    // Global "/" focuses the symbol box unless typing in another field.
    document.addEventListener("keydown", function (ev) {
      if (ev.key !== "/" || ev.ctrlKey || ev.metaKey || ev.altKey) return;
      var t = ev.target;
      var tag = t && t.tagName ? t.tagName.toLowerCase() : "";
      if (tag === "input" || tag === "textarea" || (t && t.isContentEditable)) return;
      ev.preventDefault();
      input.focus();
    });
  }

  function init() {
    attachCopyButtons();
    attachAnchorCopy();
    buildToc();
    attachSymbolSearch();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
