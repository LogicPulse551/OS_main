"""Render an offline, per-role view of recorded events and their source snapshots."""

from collections import defaultdict
from html import escape
import json
import re


_STYLE = """
:root { color-scheme: light; --ink:#172e30; --muted:#455e61; --line:#b9cdca; --paper:#fff; --accent:#096a62; }
* { box-sizing:border-box }
body { margin:0; background:#f4f7f5; color:var(--ink); font:16px/1.55 Inter,"Microsoft YaHei",sans-serif }
main { max-width:76rem; margin:auto; padding:2.75rem clamp(.85rem,4vw,3.4rem) 4rem }
h1,h2,h3,p { margin:.45rem 0 }
h1 { font-size:clamp(1.65rem,4vw,2.65rem); line-height:1.23 }
h2 { font-size:1.4rem } h3 { font-size:1.1rem }
header { padding-bottom:1.15rem; border-bottom:2px solid var(--ink) }
section { margin:1.8rem 0 }
a { color:var(--accent); text-underline-offset:.18em; overflow-wrap:anywhere }
a:hover { text-decoration-thickness:2px } :focus-visible { outline:3px solid #a24a08; outline-offset:3px }
code,pre,kbd { font-family:"IBM Plex Mono",Consolas,monospace; font-size:.90em }
code { overflow-wrap:anywhere } .sub,.sub code { color:var(--muted) }
.result { font-weight:700 } .violation { color:#973b23 }
.summary { display:flex; flex-wrap:wrap; gap:.3rem 1.7rem }
.lanes { display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,21rem),1fr)); gap:1rem; align-items:start }
.lane,.pane { min-width:0; overflow-wrap:anywhere; background:var(--paper); border:1px solid var(--line); border-radius:.55rem; padding:1rem }
.lane h3 { margin:0 } ol { list-style:none; padding:0; margin:1rem 0 0 }
.controls { margin-top:.65rem; display:flex; align-items:center; gap:.35rem; flex-wrap:wrap }
button { font:inherit; font-size:.85rem; border:1px solid #9bb5ae; background:var(--paper); border-radius:.3rem; color:var(--ink); cursor:pointer; padding:.25rem .55rem }
button:disabled { opacity:.5; cursor:default }
.node { padding:.6rem .7rem; border:1px solid var(--line); border-radius:.3rem; scroll-margin-block:1.2rem }
.node.current,.node:target,details:target { border-color:var(--accent); background:#eaf5ef }
.node-links { display:flex; flex-wrap:wrap; gap:.3rem 1rem; font-size:.85rem }
.step { margin:.25rem 0; color:var(--muted); font-size:.8rem }
.event { border:1px solid var(--line); background:var(--paper); border-radius:.3rem; margin:.4rem 0; padding:.45rem .7rem }
summary { cursor:pointer; overflow-wrap:anywhere } summary::marker { color:var(--accent) }
.source { overflow-x:auto; padding:.4rem 0; background:#f2f5f2 }
.line { display:block; white-space:pre; min-width:max-content; padding:0 .5rem }
.line b { display:inline-block; min-width:3em; margin-right:.8em; text-align:right; color:var(--muted); font-weight:400 }
.marked,.line:target { background:#d5ebdc; box-shadow:inset 3px 0 var(--accent) }
.record { overflow-x:auto; white-space:pre-wrap; overflow-wrap:anywhere }
.visually-hidden { position:absolute; height:1px; width:1px; overflow:hidden; clip-path:inset(50%) }
[hidden] { display:none!important }
@media print { main { max-width:none; padding:0 } .controls { display:none } .lanes { display:block } .lane { margin:.5rem 0 } }
"""

_PLAYER = """
for (const lane of document.querySelectorAll('.lane')) {
  const controls = lane.querySelector('.controls');
  const nodes = Array.from(lane.querySelectorAll('.node'));
  if (!nodes.length) continue;
  controls.hidden = false;
  const previous = controls.querySelector('.previous');
  const next = controls.querySelector('.next');
  const play = controls.querySelector('.play');
  const position = controls.querySelector('output');
  let selected = 0, timer = null;
  function select(step) {
    selected = step;
    nodes.forEach((node, index) => {
      node.classList.toggle('current', index === selected);
      if (index === selected) node.setAttribute('aria-current','step');
      else node.removeAttribute('aria-current');
    });
    previous.disabled = selected === 0;
    next.disabled = selected === nodes.length - 1;
    position.textContent = (step + 1) + ' / ' + nodes.length + '　' + nodes[step].querySelector('strong').textContent;
  }
  function pause() {
    clearInterval(timer);
    timer = null;
    play.textContent = '播放此角色';
    play.setAttribute('aria-pressed', 'false');
  }
  previous.addEventListener('click', () => { pause(); select(selected - 1); });
  next.addEventListener('click', () => { pause(); select(selected + 1); });
  play.addEventListener('click', () => {
    if (timer !== null) { pause(); return; }
    if (selected === nodes.length - 1) select(0);
    if (nodes.length === 1) return;
    play.textContent = '暂停';
    play.setAttribute('aria-pressed', 'true');
    timer = setInterval(() => {
      select(selected + 1);
      if (selected === nodes.length - 1) pause();
    }, 1300);
  });
  nodes.forEach((node, index) => node.addEventListener('focusin', () => { pause(); select(index); }));
  document.addEventListener('visibilitychange', () => { if (document.hidden) pause(); });
  select(0);
  play.disabled = nodes.length === 1;
}
function reveal() {
  const target = document.getElementById(location.hash.slice(1));
  if (!target) return;
  const details = target.closest('details');
  if (details) details.open = true;
}
window.addEventListener('hashchange', reveal);
reveal();
"""


def _e(value):
    return escape(str(value), quote=True)


def _source(source, anchor):
    file = _e(source["file"])
    symbol = _e(source["symbol"])
    line = source["line"]
    kind = "事件行" if source["exact_line"] else "函数定位"
    location = f'{file} · {symbol}' + (f' · 第 {_e(line)} 行' if line else "")
    rows = []
    for row in source["lines"]:
        number = row["number"]
        marked = ' marked' if number == line else ''
        rows.append(f'<span class="line{marked}" id="{anchor}-L{_e(number)}"><b>{_e(number)}</b>{_e(row["text"])}</span>')
    snippet = f'<pre class="source">{"".join(rows)}</pre>' if rows else '<p>调试信息只定位到函数。</p>'
    return (f'<details class="event" id="{anchor}"><summary>{kind} · <code>{location}</code></summary>'
            f'<p>源码 SHA-256　<code>{_e(source["sha256"])}</code></p>'
            f'{snippet}</details>')


def _property_details(data):
    if not isinstance(data, dict):
        return ""
    if data.get("oracle") == "regmap-two-masked-updates" and "observed" in data and "legal_results" in data:
        allowed = " 或 ".join(f'<code>{_e(value)}</code>' for value in data["legal_results"])
        return (f'<section class="pane"><h2>两次写入都保留了吗？</h2>'
                f'<p>实际读回的寄存器终值为 <code>{_e(data["observed"])}</code>。'
                f'两次更新按先后顺序执行时，允许的终值为 {allowed}。</p></section>')
    if data.get("oracle") == "regmap-critical-region" and "max_depth" in data and "final_depth" in data:
        events = data.get("events", ())
        depths = " → ".join(str(event["depth"]) for event in events)
        history = f'<p>按临界区观察器自身的事件编号，区内线程数依次为 <code>{_e(depths)}</code>。</p>' if events else ""
        return (f'<section class="pane"><h2>两个线程同时进入临界区了吗？</h2>'
                f'<p>同时处于受检临界区的线程最多有 <strong>{_e(data["max_depth"])}</strong> 个，'
                f'互斥要求同时最多有 1 个。记录结束时仍在临界区的线程有 {_e(data["final_depth"])} 个。</p>{history}</section>')
    return ""


def render_report(report):
    """Render only identities and relationships supplied by the verified report adapter."""
    nodes = report["nodes"]
    sources = report["sources"]
    source_anchors = {key: f'source-{index}' for index, key in enumerate(sources, 1)}
    node_anchors = {node["id"]: f'event-{i}' for i, node in enumerate(nodes, 1)}
    roles = defaultdict(list)
    for node in nodes:
        roles[node["role"]].append(node)
    preceding = defaultdict(list)
    for edge in report["edges"]:
        if edge["kind"] == "role_order":
            preceding[edge["to"]].append(edge["from"])

    title = _e(report["title"])
    observed = report["property_violation"]
    verdict = {True:"观察到性质违例", False:"本次执行未观察到性质违例", None:"本次执行未得出性质结果"}[observed]
    origin = {"reference":"原始执行", "reexecution":"实际重执行"}[report["origin"]]
    parts = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             f'<title>{title}</title><style>{_STYLE}</style></head><body><main>',
             f'<header><h1>{title}</h1><p class="summary"><span>{origin}</span>'
             f'<span class="result{" violation" if observed else ""}">{verdict}</span>'
             f'<span>{len(nodes)} 个关键事件</span></p>',
             f'<p class="sub">用例　<code>{_e(report["case"])}</code><br>'
             f'该轨迹的运行标识　<code>{_e(report["run_id"])}</code></p></header>']
    parts.append(_property_details(report.get("property")))
    replay = report["reexecution"]
    if replay:
        outcome = {True:"关键路径匹配", False:"关键路径未完整匹配", None:"未判定关键路径匹配"}[replay["full_match"]]
        receipt = (replay.get("evidence") or {}).get("href", "")
        receipt_link = (f'　<a href="{_e(receipt)}">查看当次重执行的比较记录</a>'
                        if re.fullmatch(r"events/[0-9a-f]{64}/comparison\.json", receipt) else "")
        parts.append(f'<section class="pane"><h2>实际重执行记录</h2><p>{outcome}。'
                     f'归档分类　<code>{_e(replay["classification"])}</code></p>'
                     f'<p class="sub">重执行标识　<code>{_e(replay["run_id"])}</code>{receipt_link}</p></section>')
    else:
        parts.append('<p>本报告只收录原始执行记录。</p>')
    selection = _e(report.get("selection",""))
    parts.append(f'<section><h2>关键路径</h2><p>{selection}</p><p class="sub">箭头表示同一角色内已记录的事件顺序。'
                 '播放会逐步高亮该角色的归档记录，各角色单独浏览。</p><div class="lanes">')
    evidence_rows = []
    for role, lane in roles.items():
        parts.append(f'<article class="lane"><h3>角色 {_e(role)}</h3><div class="controls" hidden>'
                     '<button type="button" class="previous">上一步</button><button type="button" class="play" aria-pressed="false">播放此角色</button>'
                     '<button type="button" class="next">下一步</button><output aria-live="polite"></output></div><ol>')
        for node in lane:
            anchor = node_anchors[node["id"]]
            parts.append('<li>')
            for prev in preceding[node["id"]]:
                parts.append(f'<div class="step"><a href="#{node_anchors[prev]}">前一事件</a> ↓</div>')
            labels = {"kconc_operation":"执行测试操作","kconc_observe":"观察临界区状态","kconc_regmap_checkpoint":"经过测试检查点",
                      "regmap_read":"读取寄存器","regmap_write":"写入寄存器","regmap_update_bits_base":"按掩码更新寄存器",
                      "regmap_ram_read":"从 RAM 总线读取","regmap_ram_write":"向 RAM 总线写入"}
            label = _e(labels.get(node["label"], node["label"]))
            parts.append(f'<div class="node" id="{anchor}"><strong>{label}</strong><div class="node-links">')
            source_id = node["source_id"]
            if source_id is not None:
                source = sources[source_id]
                source_anchor = source_anchors[source_id]
                hint = "事件行" if source["exact_line"] else "函数定位"
                parts.append(f'<a href="#{source_anchor}">{hint} · <code>{_e(source["symbol"])}</code></a>')
            else:
                parts.append('<span class="sub">此事件无源码定位</span>')
            parts.append(f'<a href="#proof-{anchor}">查看原始记录</a></div></div></li>')
            evidence = node["evidence"]
            locator = evidence["locator"]
            if not isinstance(locator, str):
                locator = json.dumps(locator, ensure_ascii=False)
            detail = (f'<details class="event" id="proof-{anchor}"><summary>角色 {_e(role)} · {label}</summary>'
                      f'<p>文件　<code>{_e(evidence["file"])}</code><br>记录位置　<code>{_e(locator)}</code>'
                      f'<br>文件 SHA-256　<code>{_e(evidence["sha256"])}</code></p>')
            href = evidence.get("href", "")
            if re.fullmatch(r"events/[0-9a-f]{64}/[AB]\.events\.jsonl", href):
                detail += f'<p><a href="{_e(href)}">打开此角色的原始事件文件</a></p>'
            if "record" in evidence:
                raw = json.dumps(evidence["record"], ensure_ascii=False, indent=2)
                detail += f'<pre class="record">{_e(raw)}</pre>'
            mapping = node.get("source_evidence") or {}
            if mapping:
                detail += (f'<p>调试信息映射　<code>{_e(mapping["file"])}</code> · <code>{_e(mapping["locator"])}</code>'
                           f'<br>映射文件 SHA-256　<code>{_e(mapping["sha256"])}</code></p>')
                mapped_file = mapping.get("href","")
                if re.fullmatch(r"events/[0-9a-f]{64}/source-map\.jsonl", mapped_file):
                    detail += f'<p><a href="{_e(mapped_file)}">打开源码映射文件</a></p>'
            evidence_rows.append(detail + f'<a href="#{anchor}">返回事件</a></details>')
        parts.append('</ol></article>')
    parts.append('</div></section><section><h2>源码快照</h2>')
    parts.extend(_source(source, source_anchors[key]) for key, source in sources.items())
    parts.append('</section><section><h2>事件出处</h2>')
    parts.extend(evidence_rows)
    parts.append(f'</section></main><script>{_PLAYER}</script></body></html>')
    return "\n".join(parts)
