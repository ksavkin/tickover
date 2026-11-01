// The report's period picker. Two halves: `aggregate` is pure and is what the
// parity test runs under node against `query::compute`; everything after it
// only writes those numbers into markup the Rust side already produced.
(function () {
  var I = { D: 0, H: 1, T: 2, P: 3, M: 4, J: 5, S: 6, IN: 7, OUT: 8, CR: 9, CW: 10, TH: 11, MSG: 12, COST: 13 };

  function zero() {
    return { input: 0, output: 0, cache_read: 0, cache_write: 0, thinking: 0, messages: 0 };
  }
  function add(t, r) {
    t.input += r[I.IN];
    t.output += r[I.OUT];
    t.cache_read += r[I.CR];
    t.cache_write += r[I.CW];
    t.thinking += r[I.TH];
    t.messages += r[I.MSG];
  }
  function sum(t) {
    return t.input + t.output + t.cache_read + t.cache_write + t.thinking;
  }
  // Same two answers as `pricing::cost_summary`: the figure is absent only
  // when nothing was priced, and partial when something with tokens was not.
  function costBox() {
    return { cost: 0, priced: false, partial: false };
  }
  function addCost(c, r) {
    if (r[I.COST] === null) {
      if (r[I.IN] + r[I.OUT] + r[I.CR] + r[I.CW] + r[I.TH] > 0) c.partial = true;
    } else {
      c.cost += r[I.COST];
      c.priced = true;
    }
  }
  function costOf(c) {
    return { cost: c.priced ? c.cost : null, partial: c.priced && c.partial };
  }
  function ranked(map, name) {
    return Object.keys(map)
      .map(function (k) { return [name(k), map[k]]; })
      .sort(function (a, b) {
        return sum(b[1]) - sum(a[1]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
      });
  }
  function monday(day) {
    var d = new Date(day + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() - (d.getUTCDay() + 6) % 7);
    return d.toISOString().slice(0, 10);
  }

  function shift(day, delta) {
    var d = new Date(day + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + delta);
    return d.toISOString().slice(0, 10);
  }
  // A quiet week inside the span is a flat stretch of the trail, not a gap.
  function denseWeeks(weeks) {
    var keys = Object.keys(weeks).sort(), out = [];
    if (keys.length === 0) return out;
    for (var w = keys[0]; w <= keys[keys.length - 1]; w = shift(w, 7)) out.push([w, weeks[w] || 0]);
    return out;
  }

  // Inclusive local dates; `null` leaves that end open.
  function aggregate(data, from, to) {
    var total = zero(), byProvider = {}, models = {}, projects = {}, sessions = {};
    var providerCost = {}, days = {}, weeks = {}, hours = [];
    var cost = costBox(), saved = 0, savedPartial = false;
    for (var h = 0; h < 24; h++) hours.push(0);
    data.rows.forEach(function (r) {
      var day = data.days[r[I.D]];
      if ((from !== null && day < from) || (to !== null && day > to)) return;
      var s = r[I.IN] + r[I.OUT] + r[I.CR] + r[I.CW] + r[I.TH];
      var p = data.providers[r[I.P]].id;
      add(total, r);
      add(byProvider[p] || (byProvider[p] = zero()), r);
      add(models[r[I.M]] || (models[r[I.M]] = zero()), r);
      add(projects[r[I.J]] || (projects[r[I.J]] = zero()), r);
      addCost(cost, r);
      addCost(providerCost[p] || (providerCost[p] = costBox()), r);
      hours[r[I.H]] += s;
      days[day] = (days[day] || 0) + s;
      var w = monday(day);
      weeks[w] = (weeks[w] || 0) + s;
      var rate = data.models[r[I.M]].saved_per_mtok;
      if (rate !== null) saved += (r[I.CR] / 1e6) * rate;
      else if (r[I.CR] > 0) savedPartial = true;
      var e = sessions[r[I.S]];
      if (!e) {
        e = sessions[r[I.S]] = {
          provider: data.providers[data.sessions[r[I.S]][0]].id,
          project: data.projects[data.sessions[r[I.S]][1]],
          totals: zero(), first: r[I.T], last: r[I.T], day: day, box: costBox()
        };
      }
      add(e.totals, r);
      addCost(e.box, r);
      if (r[I.T] < e.first) {
        e.first = r[I.T];
        e.day = day;
      }
      if (r[I.T] > e.last) e.last = r[I.T];
    });
    var sessionList = Object.keys(sessions)
      .map(function (k) {
        var e = sessions[k], c = costOf(e.box);
        return { provider: e.provider, project: e.project, totals: e.totals,
                 first: e.first, last: e.last, first_day: e.day, cost: c.cost, partial: c.partial };
      })
      .sort(function (a, b) { return sum(b.totals) - sum(a.totals); });
    var busiest = null;
    var dayKeys = Object.keys(days).sort();
    dayKeys.forEach(function (d) {
      if (busiest === null || days[d] >= busiest[1]) busiest = [d, days[d]];
    });
    var costs = {};
    Object.keys(providerCost).forEach(function (p) { costs[p] = costOf(providerCost[p]); });
    var c = costOf(cost);
    return {
      total: total,
      by_provider: byProvider,
      provider_costs: costs,
      models: ranked(models, function (k) { return data.models[k].name; }),
      projects: ranked(projects, function (k) { return data.projects[k]; }),
      sessions: sessionList,
      active_hours: hours,
      active_days: dayKeys.length,
      busiest: busiest,
      weeks: denseWeeks(weeks),
      cost: c.cost,
      partial: c.partial,
      saved: saved,
      saved_partial: savedPartial
    };
  }

  // `toFixed` breaks an exact tie upward, Rust's `{:.N}` to the even digit:
  // 1.25 would read 1.3K here and 1.2K in the page around it.
  // A tie has to be read off the exact value: 1.05 * 10 is 10.5 in floats,
  // but 1.05 itself lies just above the tie and rounds up in both languages.
  function fixed(v, digits) {
    var exact = v.toFixed(digits + 60);
    if (!/50{59}$/.test(exact)) return v.toFixed(digits);
    var kept = exact.slice(0, -60).replace(/\.$/, "");
    return (kept.charCodeAt(kept.length - 1) - 48) % 2 === 0 ? kept : v.toFixed(digits);
  }

  // The same strings `fmt_tokens`, `fmt_int`, `fmt_usd` and `session_span`
  // print; the parity test feeds both the same numbers.
  function fmtTokens(n) {
    if (n >= 1e9) return fixed(n / 1e9, 1) + "B";
    if (n >= 1e6) return fixed(n / 1e6, 1) + "M";
    if (n >= 1e3) return fixed(n / 1e3, 1) + "K";
    return String(n);
  }
  function fmtInt(n) {
    return String(n).replace(/\B(?=(\d{3})+$)/g, ",");
  }
  function fmtUsd(v) {
    if (v === null) return "—";
    if (v >= 100) return "$" + fixed(v, 0);
    if (v >= 1) return "$" + fixed(v, 2);
    if (v > 0) return "$" + fixed(v, 3);
    return "$0";
  }
  function fmtHeadlineUsd(v) {
    if (v >= 1000) return "$" + fixed(v / 1000, 1) + "K";
    return v >= 1 ? "$" + fixed(v, 0) : fmtUsd(v);
  }
  function fmtSpan(first, last) {
    if (last <= first) return "1h";
    var hrs = last - first + 1;
    return hrs >= 24 ? Math.floor(hrs / 24) + "d " + (hrs % 24) + "h" : hrs + "h";
  }
  function fmtActiveDays(n) {
    return n + " active " + (n === 1 ? "day" : "days");
  }
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  function fmtDay(day) {
    return day.slice(8, 10) + " " + MONTHS[+day.slice(5, 7) - 1] + " " + day.slice(0, 4);
  }

  var api = { aggregate: aggregate, fmtTokens: fmtTokens, fmtInt: fmtInt, fmtUsd: fmtUsd, fmtHeadlineUsd: fmtHeadlineUsd, fmtSpan: fmtSpan, fmtDay: fmtDay, fmtActiveDays: fmtActiveDays };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
    return;
  }

  var el = document.getElementById("report-data");
  var data = el && JSON.parse(el.textContent);
  var mask = document.getElementById("mask");
  var aliases = Object.create(null);
  if (data) data.projects.forEach(function (name, i) { aliases[name] = "project-" + (i + 1); });

  function applyMask() {
    document.querySelectorAll(".proj").forEach(function (node) {
      var name = node.getAttribute("data-name");
      if (name === null) return;
      node.textContent = mask.checked && aliases[name] ? aliases[name] : name;
    });
  }
  if (mask) mask.addEventListener("change", applyMask);

  var theme = document.getElementById("theme");
  if (theme) theme.addEventListener("click", function () {
    var d = document.documentElement;
    d.classList.toggle("light");
    d.classList.remove("dark");
    if (!d.classList.contains("light")) d.classList.add("dark");
  });

  var picker = document.getElementById("period");
  if (!data || !picker || data.days.length === 0) return;

  function all(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }
  function setText(key, value) {
    all('[data-k="' + key + '"]').forEach(function (n) { n.textContent = value; });
  }
  function setWidth(key, pct) {
    all('[data-w="' + key + '"]').forEach(function (n) { n.style.width = fixed(pct, 0) + "%"; });
  }
  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  // Rows are the Rust row functions' own output with `@name@` holes.
  function row(id, values) {
    return document.getElementById(id).innerHTML.replace(/@(\w+)@/g, function (_, k) {
      return escapeHtml(values[k]);
    });
  }
  function fill(id, html) {
    var node = document.getElementById(id);
    if (node) node.innerHTML = html;
  }
  function pct(part, whole) {
    return whole > 0 ? (part * 100) / whole : 0;
  }
  function cacheHit(t) {
    var denom = t.cache_read + t.input;
    return denom > 0 ? (t.cache_read * 100) / denom : null;
  }
  function usd(cost, partial) {
    return fmtUsd(cost) + (partial ? "*" : "");
  }
  function radius(i, n) {
    if (n === 1) return "3px";
    if (i === 0) return "3px 0 0 3px";
    return i === n - 1 ? "0 3px 3px 0" : "0";
  }

  function drawCards(a) {
    var t = a.total, tokens = sum(t);
    setText("card-tokens", fmtTokens(tokens));
    setText("card-sessions", fmtInt(a.sessions.length));
    setText("card-sessions-note", fmtActiveDays(a.active_days));
    setText("card-messages", fmtInt(t.messages));
    setText("card-messages-note", (a.active_days ? Math.floor(t.messages / a.active_days) : 0) + " / active day");
    setText("card-avg", fmtTokens(t.messages ? Math.floor(tokens / t.messages) : 0));
    var hit = cacheHit(t);
    setText("card-cache", hit === null ? "—" : fixed(hit, 0) + "%");
    if (data.cost_on) {
      setText("card-cost", a.cost === null ? "—" : fmtHeadlineUsd(a.cost) + (a.partial ? "*" : ""));
      setText("card-cost-note", a.partial ? "at list price, partial — unpriced models excluded"
        : a.cost === null ? "no list price for these models" : "at list price");
    }
  }

  function drawTools(a) {
    var ids = Object.keys(a.by_provider).sort();
    var total = sum(a.total) || 1, info = {};
    data.providers.forEach(function (p) { info[p.id] = p; });
    setText("tools-total", fmtTokens(sum(a.total)));
    fill("t-bar", ids.map(function (id, i) {
      var w = (sum(a.by_provider[id]) * 100) / total;
      return row("tpl-seg", { w: fixed(w, 1), c: info[id].color, radius: radius(i, ids.length),
                              name: info[id].name, label: fixed(w, 0) });
    }).join(""));
    fill("t-legend", ids.map(function (id) {
      return row("tpl-legend", { c: info[id].color, name: info[id].name,
                                 w: fixed((sum(a.by_provider[id]) * 100) / total, 0) });
    }).join(""));
    fill("t-rows", ids.map(function (id) {
      var t = a.by_provider[id], s = sum(t) || 1, c = a.provider_costs[id];
      return row("tpl-tool", {
        c: info[id].color, name: info[id].name,
        cr: fixed(pct(t.cache_read, s), 0), cw: fixed(pct(t.cache_write, s), 0),
        inp: fixed(pct(t.input, s), 0), out: fixed(pct(t.output + t.thinking, s), 0),
        tokens: fmtTokens(sum(t)),
        last: data.cost_on ? usd(c.cost, c.partial) : fmtInt(t.messages)
      });
    }).join(""));
    var ctx = document.getElementById("sec-context"), hit = cacheHit(a.total);
    if (ctx) ctx.hidden = hit === null;
    if (hit !== null) {
      setText("ctx-pct", fixed(hit, 0) + "%");
      setText("ctx-saved", fmtTokens(a.total.cache_read));
      setText("ctx-read", fmtTokens(a.total.cache_read));
      setText("ctx-input", fmtTokens(a.total.input));
      setWidth("ctx-read", hit);
      setWidth("ctx-input", 100 - hit);
      fill("c-rows", ids.map(function (id) {
        var pp = cacheHit(a.by_provider[id]);
        if (pp === null) return "";
        return row("tpl-context", { name: info[id].name, pp: fixed(pp, 0),
                                    color: pp < 50 ? "var(--warn)" : "var(--ok)" });
      }).join(""));
    }
  }

  function drawProjectsAndModels(a) {
    var total = sum(a.total) || 1, top = a.projects.slice(0, 6);
    var max = top.length ? sum(top[0][1]) || 1 : 1;
    var rest = a.projects.slice(6).reduce(function (acc, p) { return acc + sum(p[1]); }, 0);
    function projectRow(name, tokens, dimmed) {
      return row("tpl-project", {
        name: name, w: fixed((tokens * 100) / max, 0), share: fixed((tokens * 100) / total, 0),
        v: fmtTokens(tokens), color: dimmed ? "var(--meta)" : "var(--text)",
        fill: dimmed ? "var(--cache-read)" : "var(--input)"
      });
    }
    var html = top.map(function (p) { return projectRow(p[0], sum(p[1]), false); }).join("");
    if (rest > 0) html += projectRow(a.projects.length - top.length + " others", rest, true);
    fill("p-rows", html);
    var maxModel = a.models.length ? sum(a.models[0][1]) || 1 : 1;
    fill("m-rows", a.models.slice(0, 6).map(function (m) {
      return row("tpl-model", { m: m[0], v: fmtTokens(sum(m[1])), w: fixed((sum(m[1]) * 100) / maxModel, 0) });
    }).join(""));
  }

  function drawTrail(a) {
    var svg = document.getElementById("tr-svg");
    if (!svg) return;
    var W = 1072, TOP = 20, BASE = 160, weeks = a.weeks;
    var max = Math.max.apply(null, weeks.map(function (w) { return w[1]; }).concat(1));
    var n = Math.max(weeks.length, 2);
    function x(i) { return (i / (n - 1)) * W; }
    function y(v) { return BASE - (v / max) * (BASE - TOP); }
    var pts = weeks.map(function (w, i) { return fixed(x(i), 1) + "," + fixed(y(w[1]), 1); });
    document.getElementById("tr-line").setAttribute("points", pts.join(" "));
    document.getElementById("tr-area").setAttribute("d",
      "M0," + BASE + " " + pts.map(function (p) { return "L" + p + " "; }).join("") + "L" + W + "," + BASE + " Z");
    var peak = 0;
    weeks.forEach(function (w, i) { if (w[1] >= weeks[peak][1]) peak = i; });
    var px = fixed(x(peak), 0), py = fixed(y(weeks[peak][1]), 1);
    var mark = document.getElementById("tr-mark");
    mark.setAttribute("x1", px);
    mark.setAttribute("x2", px);
    var dot = document.getElementById("tr-dot");
    dot.setAttribute("cx", px);
    dot.setAttribute("cy", py);
    var label = "week of " + fmtDay(weeks[peak][0]) + " — " + fmtTokens(weeks[peak][1]) + " tokens";
    dot.firstElementChild.textContent = label;
    svg.setAttribute("aria-label", "Weekly token totals, peaking at " + fmtTokens(weeks[peak][1]) +
      " the week of " + fmtDay(weeks[peak][0]) + ".");
    setText("tr-note", "tokens per week, " + weeks.length + " weeks");
    function month(day) { return MONTHS[+day.slice(5, 7) - 1] + " " + day.slice(0, 4); }
    setText("tr-first", month(weeks[0][0]));
    setText("tr-last", month(weeks[weeks.length - 1][0]));
  }

  function drawHabits(a) {
    var max = Math.max.apply(null, a.active_hours.concat(1));
    var total = a.active_hours.reduce(function (x, y) { return x + y; }, 0) || 1;
    var peak = 0;
    a.active_hours.forEach(function (v, h) {
      var bar = document.querySelector('[data-hr="' + h + '"]');
      if (bar) {
        bar.style.height = fixed(Math.max((v / max) * 124, 3), 0) + "px";
        bar.title = (h < 10 ? "0" : "") + h + ":00 — " + fmtTokens(v);
      }
      if (v > a.active_hours[peak]) peak = h;
    });
    setText("hb-peak", (peak < 10 ? "0" : "") + peak + ":00");
    setText("hb-share", fixed((a.active_hours[peak] * 100) / total, 0));
  }

  function drawSessions(a, whole) {
    var info = {};
    data.providers.forEach(function (p) { info[p.id] = p; });
    setText("s-note", whole ? "single sessions, all time" : "single sessions, inside this period");
    fill("s-rows", a.sessions.slice(0, 5).map(function (s, i) {
      return row("tpl-session", {
        i: i + 1, proj: s.project, prov: info[s.provider].name,
        date: fmtDay(s.first_day),
        span: fmtSpan(s.first, s.last), tok: fmtTokens(sum(s.totals)),
        cost: data.cost_on ? usd(s.cost, s.partial) : "—"
      });
    }).join(""));
  }

  function drawWrapped(a, whole) {
    setText("w-label", whole ? "SO FAR" : "IN THIS PERIOD");
    setText("w-total", fmtTokens(sum(a.total)));
    setText("w-days", fmtActiveDays(a.active_days));
    setText("w-busiest", a.busiest ? fmtDay(a.busiest[0]).slice(0, 6) + " — " + fmtTokens(a.busiest[1]) : "—");
    setText("w-model", a.models.length ? a.models[0][0] : "");
    var proj = a.projects.length ? a.projects[0][0] : "";
    setText("w-project", proj);
    all('[data-k="w-project"]').forEach(function (n) { n.setAttribute("data-name", proj); });
    setText("w-saved", "≈ " + fmtUsd(a.saved) + (a.saved_partial ? "*" : ""));
  }

  var first = data.days[0], last = data.generated;
  var fromInput = document.getElementById("p-from"), toInput = document.getElementById("p-to");
  var empty = document.getElementById("period-empty");

  function draw(from, to) {
    var whole = from === null && to === null;
    var a = aggregate(data, from, to), none = sum(a.total) === 0 && a.total.messages === 0;
    all(".pf").forEach(function (n) { n.classList.toggle("off", none); });
    empty.hidden = !none;
    setText("range", fmtDay(from || first) + " — " + fmtDay(to || last));
    if (!none) {
      drawCards(a);
      drawTools(a);
      drawProjectsAndModels(a);
      drawTrail(a);
      drawHabits(a);
      drawSessions(a, whole);
      drawWrapped(a, whole);
      applyMask();
    }
  }

  // Counted from the day the report was generated, not from the browser's
  // clock: an old report keeps showing the period it says it shows.
  function preset(key) {
    if (key === "all") return [null, null];
    if (key === "month") return [last.slice(0, 8) + "01", last];
    return [shift(last, 1 - Number(key)), last];
  }
  function select(from, to, key) {
    if (from !== null && to !== null && from > to) {
      var swap = from; from = to; to = swap;
    }
    fromInput.value = from || first;
    toInput.value = to || last;
    all("#period [data-p]").forEach(function (b) {
      b.setAttribute("aria-pressed", String(b.getAttribute("data-p") === key));
    });
    var fragment = from === null && to === null ? "" : "#from=" + (from || first) + "&to=" + (to || last);
    try {
      history.replaceState(null, "", fragment || "#");
    } catch (e) {
      // Some browsers refuse `replaceState` on file:// pages.
      location.hash = fragment;
    }
    draw(from, to);
  }

  fromInput.min = toInput.min = first;
  fromInput.max = toInput.max = last;
  all("#period [data-p]").forEach(function (b) {
    b.addEventListener("click", function () {
      var key = b.getAttribute("data-p"), p = preset(key);
      select(p[0], p[1], key);
    });
  });
  function typed() {
    if (fromInput.value && toInput.value) select(fromInput.value, toInput.value, null);
  }
  fromInput.addEventListener("change", typed);
  toInput.addEventListener("change", typed);
  setText("p-note", "whole hours, UTC" + data.tz);
  picker.hidden = false;

  var hash = /^#from=(\d{4}-\d{2}-\d{2})&to=(\d{4}-\d{2}-\d{2})$/.exec(location.hash);
  if (hash) select(hash[1], hash[2], null);
  else {
    fromInput.value = first;
    toInput.value = last;
  }
})();
