// The report's interactive controller. Two halves: pure aggregation and
// formatting helpers (tested under node against `query::compute` in
// `tests/report_js.rs`), and DOM wiring over `<template>` rows and inline SVG
// charts rendered identically by `report.rs`.
(function () {
  var I = { D: 0, H: 1, T: 2, P: 3, M: 4, J: 5, S: 6, IN: 7, OUT: 8, CR: 9, CW: 10, TH: 11, MSG: 12, COST: 13 };
  var AUTO_PING_PROJECT = "Tickover auto-ping";
  var UNMAPPED_WORKTREE_PROJECT = "Agent worktrees";
  var SERIES_PALETTE = ["#56d4bd", "#d97757", "#a78bfa", "#dfa93f", "#6cb6ff", "#f0883e"];
  var OTHER_COLOR = "#5c6370";

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
  function shift(day, delta) {
    var d = new Date(day + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + delta);
    return d.toISOString().slice(0, 10);
  }
  function daysBetween(from, to) {
    var a = Date.parse(from + "T00:00:00Z");
    var b = Date.parse(to + "T00:00:00Z");
    return Math.floor((b - a) / 86400000);
  }
  function monday(day) {
    var d = new Date(day + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() - (d.getUTCDay() + 6) % 7);
    return d.toISOString().slice(0, 10);
  }
  function weekdayMon0(day) {
    return (new Date(day + "T12:00:00Z").getUTCDay() + 6) % 7;
  }
  function prevPeriod(from, to, first, last) {
    if (from === null && to === null) return null;
    var effFrom = from || first;
    var effTo = to || last;
    if (!effFrom || !effTo) return null;
    var span = daysBetween(effFrom, effTo) + 1;
    if (span <= 0) return null;
    return [shift(effFrom, -span), shift(effFrom, -1)];
  }
  function planRatio(cost, partial, plans, activeProviders, spanDays) {
    if (cost === null || !plans || !activeProviders || spanDays <= 0) {
      return { ratio: null, partial: false, monthlySum: 0 };
    }
    var monthlySum = 0;
    activeProviders.forEach(function (id) {
      var p = plans[id];
      if (typeof p === "number" && isFinite(p) && p > 0) monthlySum += p;
    });
    if (monthlySum <= 0) return { ratio: null, partial: false, monthlySum: 0 };
    var prorated = monthlySum * (spanDays / 30);
    if (prorated <= 0) return { ratio: null, partial: false, monthlySum: 0 };
    return { ratio: cost / prorated, partial: partial, monthlySum: monthlySum };
  }
  function csvCell(v) {
    var s = v === null || v === undefined ? "" : String(v);
    if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }
  function csvRow(fields) {
    return fields.map(csvCell).join(",");
  }
  function buildCsv(a, data) {
    var lines = [csvRow([
      "Provider", "Model", "Input", "Output", "Cache Write", "Cache Read",
      "Cache Hit %", "Total Tokens", "Cost USD", "Share %", "Cost Per Msg USD"
    ])];
    var totalCost = data.cost_on && a.cost !== null && a.cost > 0 ? a.cost : null;
    var provInfo = {};
    data.providers.forEach(function (p) { provInfo[p.id] = p; });
    Object.keys(a.by_provider).sort().forEach(function (pid) {
      var t = a.by_provider[pid];
      var pc = a.provider_costs[pid];
      var hit = cacheHit(t);
      var share = totalCost !== null && pc.cost !== null ? (pc.cost * 100 / totalCost).toFixed(1) : "";
      var cpm = data.cost_on && pc.cost !== null && t.messages > 0 ? (pc.cost / t.messages).toFixed(4) : "";
      lines.push(csvRow([
        provInfo[pid].name, "(all)", t.input, t.output + t.thinking, t.cache_write, t.cache_read,
        hit === null ? "" : hit.toFixed(1), sum(t),
        data.cost_on && pc.cost !== null ? pc.cost.toFixed(4) : "", share, cpm
      ]));
      (a.provider_models[pid] || []).forEach(function (entry) {
        var mName = entry[0], mt = entry[1], mc = entry[2];
        var mHit = cacheHit(mt);
        var mShare = totalCost !== null && mc.cost !== null ? (mc.cost * 100 / totalCost).toFixed(1) : "";
        var mCpm = data.cost_on && mc.cost !== null && mt.messages > 0 ? (mc.cost / mt.messages).toFixed(4) : "";
        lines.push(csvRow([
          provInfo[pid].name, mName, mt.input, mt.output + mt.thinking, mt.cache_write, mt.cache_read,
          mHit === null ? "" : mHit.toFixed(1), sum(mt),
          data.cost_on && mc.cost !== null ? mc.cost.toFixed(4) : "", mShare, mCpm
        ]));
      });
    });
    return lines.join("\n") + "\n";
  }

  // Inclusive local dates; `null` leaves that end open.
  function aggregate(data, from, to) {
    var total = zero(), byProvider = {}, models = {}, projects = {}, sessions = {};
    var providerCost = {}, providerModels = {}, projectCost = {}, projectDaily = {};
    var daily = {}, dailySeries = {}, weekdayHours = [];
    var cost = costBox(), crBox = costBox(), crHasUsage = false, crPricedUsage = false;
    var saved = 0, savedPartial = false;
    for (var w = 0; w < 7; w++) {
      var rowHrs = [];
      for (var h = 0; h < 24; h++) rowHrs.push(0);
      weekdayHours.push(rowHrs);
    }
    data.rows.forEach(function (r) {
      var day = data.days[r[I.D]];
      if ((from !== null && day < from) || (to !== null && day > to)) return;
      var s = r[I.IN] + r[I.OUT] + r[I.CR] + r[I.CW] + r[I.TH];
      var p = data.providers[r[I.P]].id;
      var mName = data.models[r[I.M]].name;
      var jName = data.projects[r[I.J]];
      add(total, r);
      add(byProvider[p] || (byProvider[p] = zero()), r);
      add(models[r[I.M]] || (models[r[I.M]] = zero()), r);
      add(projects[r[I.J]] || (projects[r[I.J]] = zero()), r);
      addCost(cost, r);
      addCost(providerCost[p] || (providerCost[p] = costBox()), r);
      addCost(projectCost[jName] || (projectCost[jName] = costBox()), r);

      var pm = providerModels[p] || (providerModels[p] = {});
      var pmEntry = pm[mName] || (pm[mName] = { totals: zero(), box: costBox() });
      add(pmEntry.totals, r);
      addCost(pmEntry.box, r);

      if (data.cost_on) {
        if (r[I.CR] > 0) crHasUsage = true;
        var crRate = data.models[r[I.M]].cr_per_mtok;
        if (crRate === null) {
          if (r[I.CR] > 0) crBox.partial = true;
        } else {
          crBox.cost += (r[I.CR] / 1e6) * crRate;
          if (r[I.CR] > 0) crPricedUsage = true;
          crBox.priced = true;
        }
      }

      weekdayHours[weekdayMon0(day)][r[I.H]] += s;
      add(daily[day] || (daily[day] = zero()), r);

      var ds = dailySeries[day] || (dailySeries[day] = {
        tokens: 0, box: costBox(), by_provider: {}, by_model: {}, by_project: {}
      });
      ds.tokens += s;
      addCost(ds.box, r);
      var addBucket = function (map, key) {
        var b = map[key] || (map[key] = { tokens: 0, box: costBox() });
        b.tokens += s;
        addCost(b.box, r);
      };
      addBucket(ds.by_provider, p);
      addBucket(ds.by_model, mName);
      addBucket(ds.by_project, jName);

      var pd = projectDaily[jName] || (projectDaily[jName] = {});
      pd[day] = (pd[day] || 0) + (data.cost_on && r[I.COST] !== null ? r[I.COST] : s);

      var rate = data.models[r[I.M]].saved_per_mtok;
      if (rate !== null) saved += (r[I.CR] / 1e6) * rate;
      else if (r[I.CR] > 0) savedPartial = true;

      var e = sessions[r[I.S]];
      if (!e) {
        e = sessions[r[I.S]] = {
          provider: data.providers[data.sessions[r[I.S]][0]].id,
          project: data.projects[data.sessions[r[I.S]][1]],
          models: {}, totals: zero(), first: r[I.T], last: r[I.T], day: day, box: costBox()
        };
      }
      e.models[mName] = (e.models[mName] || 0) + s;
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
        var topModel = "", topTok = -1;
        Object.keys(e.models).sort().forEach(function (m) {
          if (e.models[m] > topTok) { topTok = e.models[m]; topModel = m; }
        });
        return {
          provider: e.provider, project: e.project, top_model: topModel, totals: e.totals,
          first: e.first, last: e.last, first_day: e.day, cost: c.cost, partial: c.partial
        };
      })
      .sort(function (a, b) { return sum(b.totals) - sum(a.totals); });

    var dayKeys = Object.keys(daily).sort();
    var provCosts = {};
    Object.keys(providerCost).forEach(function (p) { provCosts[p] = costOf(providerCost[p]); });
    var projCosts = {};
    Object.keys(projectCost).forEach(function (p) { projCosts[p] = costOf(projectCost[p]); });
    var provModelsOut = {};
    Object.keys(providerModels).forEach(function (p) {
      provModelsOut[p] = Object.keys(providerModels[p])
        .map(function (m) {
          var entry = providerModels[p][m];
          return [m, entry.totals, costOf(entry.box)];
        })
        .sort(function (a, b) {
          return sum(b[1]) - sum(a[1]) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
        });
    });
    var c = costOf(cost);
    var crcCost = (data.cost_on && (crPricedUsage || (!crHasUsage && crBox.priced))) ? crBox.cost : null;
    var crc = { cost: crcCost, partial: crcCost !== null && crBox.partial };
    return {
      total: total,
      by_provider: byProvider,
      provider_costs: provCosts,
      provider_models: provModelsOut,
      models: ranked(models, function (k) { return data.models[k].name; }),
      projects: ranked(projects, function (k) { return data.projects[k]; }),
      project_costs: projCosts,
      project_daily: projectDaily,
      sessions: sessionList,
      weekday_hours: weekdayHours,
      daily: daily,
      daily_series: dailySeries,
      active_days: dayKeys.length,
      cost: c.cost,
      partial: c.partial,
      cr_cost: crc.cost,
      cr_partial: crc.partial,
      saved: saved,
      saved_partial: savedPartial
    };
  }

  // `toFixed` breaks an exact tie upward, Rust's `{:.N}` to the even digit.
  function fixed(v, digits) {
    var exact = v.toFixed(digits + 60);
    if (!/50{59}$/.test(exact)) return v.toFixed(digits);
    var kept = exact.slice(0, -60).replace(/\.$/, "");
    return (kept.charCodeAt(kept.length - 1) - 48) % 2 === 0 ? kept : v.toFixed(digits);
  }

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
  var DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function fmtDay(day) {
    return day.slice(8, 10) + " " + MONTHS[+day.slice(5, 7) - 1] + " " + day.slice(0, 4);
  }
  function cacheHit(t) {
    var denom = t.cache_read + t.input + t.cache_write;
    return denom > 0 ? (t.cache_read * 100) / denom : null;
  }

  var api = {
    aggregate: aggregate, prevPeriod: prevPeriod, planRatio: planRatio,
    csvRow: csvRow, buildCsv: buildCsv, cacheHit: cacheHit,
    fmtTokens: fmtTokens, fmtInt: fmtInt, fmtUsd: fmtUsd, fmtHeadlineUsd: fmtHeadlineUsd,
    fmtSpan: fmtSpan, fmtDay: fmtDay, fmtActiveDays: fmtActiveDays
  };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
    return;
  }

  var el = document.getElementById("report-data");
  var data = el && JSON.parse(el.textContent);
  var mask = document.getElementById("mask");
  var compareEl = document.getElementById("compare");
  var UNMASKED_PROJECTS = { "Tickover auto-ping": true, "Agent worktrees": true };
  var aliases = Object.create(null);
  if (data) {
    var aliasIndex = 0;
    data.projects.forEach(function (name) {
      if (UNMASKED_PROJECTS[name]) aliases[name] = name;
      else aliases[name] = "project-" + (++aliasIndex);
    });
  }
  function displayProject(name) {
    return mask && mask.checked && aliases[name] ? aliases[name] : name;
  }
  function applyMask() {
    document.querySelectorAll(".proj").forEach(function (node) {
      var name = node.getAttribute("data-name");
      if (name === null) return;
      node.textContent = displayProject(name);
    });
  }

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
  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  function row(id, values) {
    return document.getElementById(id).innerHTML.replace(/@(\w+)@/g, function (_, k) {
      return escapeHtml(values[k]);
    });
  }
  function fill(id, html) {
    var node = document.getElementById(id);
    if (node) node.innerHTML = html;
  }
  function usd(cost, partial) {
    return fmtUsd(cost) + (cost !== null && partial ? "*" : "");
  }
  function fmtDelta(cur, prev) {
    if (cur === null || prev === null || prev <= 0 || !isFinite(cur) || !isFinite(prev)) return "";
    var pct = Math.round(((cur - prev) * 100) / prev);
    if (pct > 0) return "↑ " + pct + "% vs prev";
    if (pct < 0) return "↓ " + Math.abs(pct) + "% vs prev";
    return "0% vs prev";
  }

  var first = data.days[0], last = data.generated;
  var curFrom = null, curTo = null;
  var chartMetric = data.cost_on ? "cost" : "tokens";
  var chartGroup = "provider";
  var sortCol = data.cost_on ? "cost" : "total";
  var sortAsc = false;
  var allExpanded = false;
  var lastAgg = null;

  function setDelta(key, text) {
    setText(key, text);
    all('[data-k="' + key + '"]').forEach(function (n) {
      n.classList.remove("delta-up", "delta-dn");
      if (text.indexOf("↑") === 0) n.classList.add("delta-up");
      else if (text.indexOf("↓") === 0) n.classList.add("delta-dn");
    });
  }

  function drawCards(a, prevA, spanDays) {
    var t = a.total, tokens = sum(t);
    var star = a.partial ? "*" : "";
    if (data.cost_on) {
      setText("card-cost", a.cost === null ? "—" : fmtHeadlineUsd(a.cost) + star);
      setText("card-cost-note", a.partial ? "API-equivalent, partial — unpriced models excluded"
        : a.cost === null ? "no list price for these models" : "API-equivalent, not your bill");
    } else {
      setText("card-cost", "off");
      setText("card-cost-note", "cost accounting disabled");
    }
    setDelta("delta-cost", prevA && data.cost_on ? fmtDelta(a.cost, prevA.cost) : "");

    setText("card-tokens", fmtTokens(tokens));
    setDelta("delta-tokens", prevA ? fmtDelta(tokens, sum(prevA.total)) : "");
    var tokShare = tokens > 0 ? fixed((t.cache_read * 100) / tokens, 0) : null;
    var usdShare = data.cost_on && a.cost !== null && a.cost > 0 && a.cr_cost !== null
      ? fixed((a.cr_cost * 100) / a.cost, 0) : null;
    var crNote = tokShare === null ? "in + out + cache"
      : usdShare !== null ? "cache read " + tokShare + "% tok · " + usdShare + "% $" + (a.partial || a.cr_partial ? "*" : "")
      : "cache read " + tokShare + "% tok";
    setText("card-tokens-note", crNote);

    setText("card-days", fmtInt(a.active_days));
    setDelta("delta-days", prevA ? fmtDelta(a.active_days, prevA.active_days) : "");
    setText("card-days-note", fmtInt(a.sessions.length) + " sessions · " + fmtInt(t.messages) + " msgs");

    var perDayVal = a.active_days > 0
      ? (data.cost_on && a.cost !== null ? a.cost / a.active_days : tokens / a.active_days) : null;
    var prevPerDay = prevA && prevA.active_days > 0
      ? (data.cost_on && prevA.cost !== null ? prevA.cost / prevA.active_days : sum(prevA.total) / prevA.active_days) : null;
    setText("card-per-day", perDayVal === null ? "—"
      : data.cost_on && a.cost !== null ? fmtUsd(perDayVal) + star : fmtTokens(Math.round(perDayVal)));
    setDelta("delta-per-day", prevA ? fmtDelta(perDayVal, prevPerDay) : "");
    setText("card-per-day-note", data.cost_on ? "API-equiv / active day" : "tokens / active day");

    var paceVal = spanDays > 0
      ? (data.cost_on && a.cost !== null ? (a.cost / spanDays) * 30 : (tokens / spanDays) * 30) : null;
    var prevPace = prevA && spanDays > 0
      ? (data.cost_on && prevA.cost !== null ? (prevA.cost / spanDays) * 30 : (sum(prevA.total) / spanDays) * 30) : null;
    setText("card-pace", paceVal === null ? "—"
      : (data.cost_on && a.cost !== null ? fmtHeadlineUsd(paceVal) + star : fmtTokens(Math.round(paceVal))) + "/mo");
    setDelta("delta-pace", prevA ? fmtDelta(paceVal, prevPace) : "");
    setText("card-pace-note", "at " + spanDays + "d pace");

    var activeProviders = data.providers.map(function (p) { return p.id; });
    var pr = data.cost_on ? planRatio(a.cost, a.partial, data.plans, activeProviders, spanDays) : { ratio: null, monthlySum: 0 };
    var prevPr = prevA && data.cost_on
      ? planRatio(prevA.cost, prevA.partial, data.plans, activeProviders, spanDays) : { ratio: null };
    setText("card-plan", pr.ratio === null ? "—" : "×" + fixed(pr.ratio, 1) + (pr.partial ? "*" : ""));
    setDelta("delta-plan", prevA ? fmtDelta(pr.ratio, prevPr.ratio) : "");
    setText("card-plan-note", !data.cost_on ? "cost off"
      : pr.monthlySum > 0 ? "API-equiv ÷ " + fmtUsd(pr.monthlySum) + "/mo (not savings)"
      : "set [plans] in prices.toml");
  }

  function drawChart(a, effFrom, effTo) {
    var spanDays = daysBetween(effFrom, effTo) + 1;
    var weekly = spanDays > 90;
    var keys = [], cursor = weekly ? monday(effFrom) : effFrom, endKey = weekly ? monday(effTo) : effTo;
    while (cursor <= endKey) {
      keys.push(cursor);
      cursor = shift(cursor, weekly ? 7 : 1);
    }
    var provColor = {}, provName = {};
    data.providers.forEach(function (p) { provColor[p.id] = p.color; provName[p.id] = p.name; });
    var buckets = {};
    keys.forEach(function (k) { buckets[k] = {}; });
    var totals = {};
    Object.keys(a.daily_series).forEach(function (day) {
      var bk = weekly ? monday(day) : day;
      if (!buckets[bk]) return;
      var ds = a.daily_series[day];
      var src = chartGroup === "provider" ? ds.by_provider : chartGroup === "model" ? ds.by_model : ds.by_project;
      Object.keys(src).forEach(function (item) {
        var entry = src[item];
        var val = chartMetric === "cost" ? (entry.box.priced ? entry.box.cost : 0) : entry.tokens;
        buckets[bk][item] = (buckets[bk][item] || 0) + val;
        totals[item] = (totals[item] || 0) + val;
      });
    });
    var rankedKeys = Object.keys(totals).sort(function (x, y) {
      return totals[y] - totals[x] || (x < y ? -1 : x > y ? 1 : 0);
    });
    var series = rankedKeys.slice(0, 6);
    var hasOther = rankedKeys.length > 6;
    if (hasOther) {
      series.push("other");
      keys.forEach(function (bk) {
        var otherSum = 0;
        rankedKeys.slice(6).forEach(function (k) { otherSum += buckets[bk][k] || 0; });
        if (otherSum > 0) buckets[bk]["other"] = otherSum;
      });
    }
    var colorOf = function (s, idx) {
      if (s === "other") return OTHER_COLOR;
      if (chartGroup === "provider" && provColor[s]) return provColor[s];
      return SERIES_PALETTE[idx % SERIES_PALETTE.length];
    };
    var labelOf = function (s) {
      if (s === "other") return "Other";
      if (chartGroup === "provider" && provName[s]) return provName[s];
      if (chartGroup === "project") return displayProject(s);
      return s;
    };
    var maxVal = 0;
    keys.forEach(function (bk) {
      var colSum = 0;
      series.forEach(function (s) { colSum += buckets[bk][s] || 0; });
      if (colSum > maxVal) maxVal = colSum;
    });
    if (maxVal <= 0) maxVal = 1;

    var W = 1072, H = 200, L = 56, R = 1064, TOP = 16, BASE = 180;
    var plotW = R - L, plotH = BASE - TOP;
    var fmtY = function (v) { return chartMetric === "cost" ? fmtUsd(v) : fmtTokens(Math.round(v)); };
    var svgHtml = "";
    [0, 1, 2, 3].forEach(function (step) {
      var frac = step / 3;
      var y = BASE - frac * plotH;
      svgHtml += '<line x1="' + L + '" y1="' + y.toFixed(1) + '" x2="' + R + '" y2="' + y.toFixed(1) + '" stroke="var(--' + (step === 0 ? "hairline" : "track") + ')" stroke-width="1"/>';
      svgHtml += '<text x="' + (L - 8) + '" y="' + (y + 3).toFixed(1) + '" text-anchor="end" font-size="10" fill="var(--meta)" font-family="ui-monospace,monospace">' + escapeHtml(fmtY(maxVal * frac)) + '</text>';
    });
    var n = Math.max(keys.length, 1), slot = plotW / n, barW = Math.max(2, Math.min(28, slot * 0.72));
    keys.forEach(function (bk, i) {
      var x = L + i * slot + (slot - barW) / 2, curY = BASE, parts = [];
      series.forEach(function (s, idx) {
        var v = buckets[bk][s] || 0;
        if (v <= 0) return;
        var h = (v / maxVal) * plotH;
        curY -= h;
        svgHtml += '<rect x="' + x.toFixed(1) + '" y="' + curY.toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + h.toFixed(1) + '" fill="' + colorOf(s, idx) + '" rx="1"/>';
        parts.push(labelOf(s) + ": " + fmtY(v));
      });
      var tip = (weekly ? "week of " : "") + fmtDay(bk) + " — " + (parts.length ? parts.join(", ") : fmtY(0));
      svgHtml += '<rect x="' + (L + i * slot).toFixed(1) + '" y="' + TOP + '" width="' + slot.toFixed(1) + '" height="' + plotH + '" fill="transparent"><title>' + escapeHtml(tip) + '</title></rect>';
    });
    fill("ch-svg", svgHtml);
    fill("ch-legend", series.map(function (s, idx) {
      var val = s === "other" ? rankedKeys.slice(6).reduce(function (acc, k) { return acc + (totals[k] || 0); }, 0) : (totals[s] || 0);
      return row("tpl-legend", { c: colorOf(s, idx), name: labelOf(s), v: fmtY(val) });
    }).join(""));
    setText("ch-note", (chartMetric === "cost" ? "API-equiv USD" : "tokens") + " per " + (weekly ? "week" : "day") + ", " + keys.length + (weekly ? " weeks" : " days"));
    setText("ch-first", fmtDay(keys[0]));
    setText("ch-mid", fmtDay(keys[Math.floor(keys.length / 2)]));
    setText("ch-last", fmtDay(keys[keys.length - 1]));
  }

  function metricVal(t, cost, totalCost, col) {
    if (col === "name") return 0;
    if (col === "in") return t.input;
    if (col === "out") return t.output + t.thinking;
    if (col === "cw") return t.cache_write;
    if (col === "cr") return t.cache_read;
    if (col === "hit") { var h = cacheHit(t); return h === null ? -1 : h; }
    if (col === "total") return sum(t);
    if (col === "cost" || col === "share") return cost === null ? -1 : cost;
    if (col === "cpm") return cost !== null && t.messages > 0 ? cost / t.messages : -1;
    return sum(t);
  }

  function drawBreakdown(a) {
    var totalCost = data.cost_on && a.cost !== null && a.cost > 0 ? a.cost : null;
    var provInfo = {};
    data.providers.forEach(function (p) { provInfo[p.id] = p; });
    var cmp = function (nameA, tA, cA, nameB, tB, cB) {
      var d;
      if (sortCol === "name") {
        d = nameA < nameB ? -1 : nameA > nameB ? 1 : 0;
      } else {
        var vA = metricVal(tA, cA, totalCost, sortCol), vB = metricVal(tB, cB, totalCost, sortCol);
        d = vB - vA || (sum(tB) - sum(tA)) || (nameA < nameB ? -1 : nameA > nameB ? 1 : 0);
      }
      return sortAsc ? -d : d;
    };
    var provIds = Object.keys(a.by_provider).sort(function (pa, pb) {
      return cmp(provInfo[pa].name, a.by_provider[pa], a.provider_costs[pa].cost,
        provInfo[pb].name, a.by_provider[pb], a.provider_costs[pb].cost);
    });
    var fmtCells = function (t, cObj) {
      var hit = cacheHit(t);
      var share = totalCost !== null && cObj.cost !== null ? fixed((cObj.cost * 100) / totalCost, 0) + "%" : "—";
      var cpm = data.cost_on && cObj.cost !== null && t.messages > 0 ? usd(cObj.cost / t.messages, cObj.partial) : "—";
      return {
        in: fmtTokens(t.input), out: fmtTokens(t.output + t.thinking),
        cw: fmtTokens(t.cache_write), cr: fmtTokens(t.cache_read),
        hit: hit === null ? "—" : fixed(hit, 0) + "%", tot: fmtTokens(sum(t)),
        cost: data.cost_on ? usd(cObj.cost, cObj.partial) : "—", share: share, cpm: cpm
      };
    };
    var html = "";
    provIds.forEach(function (pid) {
      var cells = fmtCells(a.by_provider[pid], a.provider_costs[pid]);
      cells.id = pid;
      cells.arrow = allExpanded ? "▾" : "▸";
      cells.c = provInfo[pid].color;
      cells.name = provInfo[pid].name;
      html += row("tpl-bd-prov", cells);
      var mList = (a.provider_models[pid] || []).slice().sort(function (ma, mb) {
        return cmp(ma[0], ma[1], ma[2].cost, mb[0], mb[1], mb[2].cost);
      });
      mList.forEach(function (entry) {
        var mc = fmtCells(entry[1], entry[2]);
        mc.parent = pid;
        mc.closed = allExpanded ? "" : " is-closed";
        mc.m = entry[0];
        html += row("tpl-bd-model", mc);
      });
    });
    fill("bd-body", html);
    all("#bd-body .prov-row").forEach(function (tr) {
      tr.addEventListener("click", function () {
        var pid = tr.getAttribute("data-prov");
        var opening = tr.getAttribute("aria-expanded") !== "true";
        tr.setAttribute("aria-expanded", String(opening));
        var arrow = tr.querySelector(".bd-arrow");
        if (arrow) arrow.textContent = opening ? "▾" : "▸";
        all('#bd-body .model-row[data-parent="' + pid + '"]').forEach(function (mr) {
          mr.classList.toggle("is-closed", !opening);
        });
      });
    });
  }

  function sparkPts(dailyMap, keys) {
    if (!dailyMap || keys.length === 0) return "0,14 64,14";
    var vals = keys.map(function (k) { return dailyMap[k] || 0; });
    var max = Math.max.apply(null, vals.concat(0));
    if (max <= 0) return "0,14 64,14";
    var n = Math.max(vals.length, 2);
    return vals.map(function (v, i) {
      var x = (i / (n - 1)) * 62 + 1;
      var y = 14 - (v / max) * 12;
      return x.toFixed(1) + "," + y.toFixed(1);
    }).join(" ");
  }

  function drawProjects(a, effFrom, effTo) {
    var keys = [];
    for (var d = effFrom; d <= effTo; d = shift(d, 1)) keys.push(d);
    var totalTokens = sum(a.total) || 1;
    var totalCost = data.cost_on && a.cost !== null && a.cost > 0 ? a.cost : null;
    var pingEntry = null, user = [];
    a.projects.forEach(function (p) {
      if (p[0] === AUTO_PING_PROJECT) pingEntry = p;
      else user.push(p);
    });
    user.sort(function (x, y) {
      if (data.cost_on) {
        var cx = a.project_costs[x[0]] ? a.project_costs[x[0]].cost : null;
        var cy = a.project_costs[y[0]] ? a.project_costs[y[0]].cost : null;
        if (cx !== null && cy !== null && cy !== cx) return cy - cx;
        if ((cy !== null) !== (cx !== null)) return cy !== null ? 1 : -1;
      }
      return sum(y[1]) - sum(x[1]) || (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0);
    });
    var top = user.slice(0, 10);
    var metricOf = function (name, t) {
      if (totalCost !== null && a.project_costs[name] && a.project_costs[name].cost !== null) {
        return a.project_costs[name].cost;
      }
      return totalCost !== null ? 0 : sum(t);
    };
    var maxBar = top.length ? Math.max(metricOf(top[0][0], top[0][1]), 1e-9) : 1;
    var denom = totalCost !== null ? totalCost : totalTokens;
    var pRow = function (name, tokens, cObj, dimmed, showSpark) {
      var mVal = totalCost !== null ? (cObj.cost || 0) : tokens;
      return row("tpl-project", {
        name: name,
        pts: showSpark ? sparkPts(a.project_daily[name], keys) : "0,14 64,14",
        sparkop: showSpark ? "1" : "0",
        w: fixed(Math.min(100, (mVal * 100) / maxBar), 0),
        cost: data.cost_on ? usd(cObj.cost, cObj.partial) : "—",
        tok: fmtTokens(tokens),
        share: fixed((mVal * 100) / denom, 0),
        color: dimmed ? "var(--meta)" : "var(--text)",
        fill: dimmed ? "var(--cache-read)" : "var(--input)"
      });
    };
    var html = top.map(function (p) {
      return pRow(p[0], sum(p[1]), a.project_costs[p[0]] || { cost: null, partial: false }, false, true);
    }).join("");
    if (user.length > 10) {
      var restTok = 0, restCost = 0, restPriced = false, restPartial = false;
      user.slice(10).forEach(function (p) {
        var t = sum(p[1]);
        restTok += t;
        var c = a.project_costs[p[0]];
        if (c && c.cost !== null) { restCost += c.cost; restPriced = true; if (c.partial) restPartial = true; }
        else if (t > 0) restPartial = true;
      });
      html += pRow((user.length - 10) + " others", restTok, { cost: restPriced ? restCost : null, partial: restPriced && restPartial }, true, false);
    }
    fill("p-rows", html);
    var pingEl = document.getElementById("p-ping");
    if (pingEntry && sum(pingEntry[1]) > 0) {
      pingEl.hidden = false;
      fill("p-ping", pRow(pingEntry[0], sum(pingEntry[1]), a.project_costs[pingEntry[0]] || { cost: null, partial: false }, true, false));
    } else {
      pingEl.hidden = true;
      fill("p-ping", "");
    }
  }

  function drawSessions(a, whole) {
    var info = {};
    data.providers.forEach(function (p) { info[p.id] = p; });
    setText("s-note", whole ? "top 10 in all history" : "top 10 in this period");
    var list = a.sessions.slice().sort(function (x, y) {
      if (data.cost_on) {
        if (x.cost !== null && y.cost !== null && y.cost !== x.cost) return y.cost - x.cost;
        if ((y.cost !== null) !== (x.cost !== null)) return y.cost !== null ? 1 : -1;
      }
      return sum(y.totals) - sum(x.totals);
    });
    fill("s-rows", list.slice(0, 10).map(function (s, i) {
      return row("tpl-session", {
        i: i + 1, proj: s.project, prov: info[s.provider].name,
        model: s.top_model || "—", date: fmtDay(s.first_day),
        span: fmtSpan(s.first, s.last), tok: fmtTokens(sum(s.totals)),
        cost: data.cost_on ? usd(s.cost, s.partial) : "—"
      });
    }).join(""));
  }

  function drawHabits(a) {
    var max = 0, total = 0, peakW = 0, peakH = 0;
    for (var w = 0; w < 7; w++) {
      for (var h = 0; h < 24; h++) {
        var v = a.weekday_hours[w][h];
        total += v;
        if (v > max) { max = v; peakW = w; peakH = h; }
      }
    }
    var denom = max || 1, totalSafe = total || 1;
    for (var w = 0; w < 7; w++) {
      for (var h = 0; h < 24; h++) {
        var v = a.weekday_hours[w][h];
        var level = v === 0 ? 0 : Math.min(4, 1 + Math.floor((v / denom) * 3.999));
        var cell = document.querySelector('[data-wh="' + w + "-" + h + '"]');
        if (cell) {
          cell.style.background = "var(--heat" + level + ")";
          cell.title = DAYS[w] + " " + (h < 10 ? "0" : "") + h + ":00 — " + fmtTokens(v);
        }
      }
    }
    setText("hb-peak", DAYS[peakW] + " " + (peakH < 10 ? "0" : "") + peakH + ":00");
    setText("hb-share", fixed((a.weekday_hours[peakW][peakH] * 100) / totalSafe, 0));
  }

  function draw(from, to) {
    curFrom = from;
    curTo = to;
    var whole = from === null && to === null;
    var effFrom = from || first, effTo = to || last;
    var spanDays = Math.max(1, daysBetween(effFrom, effTo) + 1);
    var a = aggregate(data, from, to), none = sum(a.total) === 0 && a.total.messages === 0;
    lastAgg = a;
    all(".pf").forEach(function (n) { n.classList.toggle("off", none); });
    document.getElementById("period-empty").hidden = !none;
    setText("range", fmtDay(effFrom) + " — " + fmtDay(effTo));
    if (!none) {
      var prev = compareEl && compareEl.checked ? prevPeriod(from, to, first, last) : null;
      var prevA = prev ? aggregate(data, prev[0], prev[1]) : null;
      if (prevA && sum(prevA.total) === 0 && prevA.total.messages === 0) prevA = null;
      drawCards(a, prevA, spanDays);
      drawChart(a, effFrom, effTo);
      drawBreakdown(a);
      drawProjects(a, effFrom, effTo);
      drawSessions(a, whole);
      drawHabits(a);
      applyMask();
    }
  }

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
    try { history.replaceState(null, "", fragment || "#"); } catch (e) { location.hash = fragment; }
    draw(from, to);
  }

  var fromInput = document.getElementById("p-from"), toInput = document.getElementById("p-to");
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
  if (mask) mask.addEventListener("change", function () {
    applyMask();
    if (lastAgg) drawChart(lastAgg, curFrom || first, curTo || last);
  });
  if (compareEl) compareEl.addEventListener("change", function () { draw(curFrom, curTo); });

  all("#chart-metric [data-m]").forEach(function (b) {
    b.addEventListener("click", function () {
      chartMetric = b.getAttribute("data-m");
      all("#chart-metric [data-m]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      if (lastAgg) drawChart(lastAgg, curFrom || first, curTo || last);
    });
  });
  all("#chart-group [data-g]").forEach(function (b) {
    b.addEventListener("click", function () {
      chartGroup = b.getAttribute("data-g");
      all("#chart-group [data-g]").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      if (lastAgg) drawChart(lastAgg, curFrom || first, curTo || last);
    });
  });
  all("#bd-table th[data-sort]").forEach(function (th) {
    th.addEventListener("click", function () {
      var col = th.getAttribute("data-sort");
      if (sortCol === col) sortAsc = !sortAsc;
      else { sortCol = col; sortAsc = col === "name"; }
      if (lastAgg) drawBreakdown(lastAgg);
    });
  });
  var toggleBtn = document.getElementById("bd-toggle-all");
  if (toggleBtn) toggleBtn.addEventListener("click", function () {
    allExpanded = !allExpanded;
    toggleBtn.textContent = allExpanded ? "Collapse all" : "Expand all";
    if (lastAgg) drawBreakdown(lastAgg);
  });
  var csvBtn = document.getElementById("export-csv");
  if (csvBtn) csvBtn.addEventListener("click", function () {
    if (!lastAgg) return;
    var csv = buildCsv(lastAgg, data);
    var blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var aTag = document.createElement("a");
    aTag.href = url;
    aTag.download = "tickover-breakdown-" + (curFrom || first) + "-" + (curTo || last) + ".csv";
    document.body.appendChild(aTag);
    aTag.click();
    document.body.removeChild(aTag);
    URL.revokeObjectURL(url);
  });

  setText("p-note", "whole hours, UTC" + data.tz);
  picker.hidden = false;

  var hash = /^#from=(\d{4}-\d{2}-\d{2})&to=(\d{4}-\d{2}-\d{2})$/.exec(location.hash);
  if (hash) select(hash[1], hash[2], null);
  else select(null, null, "all");
})();
