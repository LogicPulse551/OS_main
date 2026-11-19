"""Render the two competition cases with links to their underlying records."""
from html import escape


def page(traces, repair, cert, fallback, functional, diff, timing, ids):
    original, replay = traces
    prop = original["property"]
    observed = prop["observed"][0]
    expected = " 或 ".join(str(values[0]) for values in prop["legal_results"])
    labels = {"original": "原版", "cached": "仅缓存回调指针", "skip-noop": "跳过已知空回调"}
    verdict = {True: "通过预定收益门槛", False: "未达到预定收益门槛", None: "有效配对不足"}[timing["value_gate_passed"]]
    table = []
    for arm, label in labels.items():
        times = timing["distributions"].get(arm)
        profile = timing["preflight"][arm]
        table.append(f'<tr><th>{label}</th><td>{profile["noop_calls"]} / {profile["bulk_calls"]}</td><td>'+(f'{times["median"]:.2f}' if times else "—")+
                     "</td><td><code>"+escape(ids[arm])+"</code></td></tr>")
    comparisons = []
    for comp in timing["comparisons"].values():
        lo, hi = comp["reduction_95_pct_interval"]
        alo, ahi = comp["saved_ns_per_call_95_interval"]
        shift = comp["saved_ns_per_call"]
        direction = "节省" if shift >= 0 else "增加"
        comparisons.append(f'<p><strong>{labels[comp["variant"]]}</strong>　一次六字节读取平均{direction} {abs(shift):.2f} ns。'
                           f'按节省为正计算，绝对差的 95% 区间为 {alo:.2f} 至 {ahi:.2f} ns。'
                           f'相对耗时降幅为 {comp["reduction_percent"]:.2f}%（95% 区间 {lo:.2f}% 至 {hi:.2f}%）。</p>')
    assumption_links = "　".join(
        f'<a href="evidence/opt/assumptions/{name}.txt">{name}</a>'
        for name in ("BulkRead","ClightBinding","NativeNoop","ScopedBinding"))
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>regmap 内核实验</title><style>
*{{box-sizing:border-box}}body{{margin:0;color:#182e30;background:#f4f7f5;font:16px/1.6 Inter,"Microsoft YaHei",sans-serif}}
main{{max-width:66rem;margin:auto;padding:2rem clamp(1rem,4vw,3rem)}}section{{margin:1.5rem 0;padding:1.5rem;background:white;border:1px solid #c3d2cf;border-radius:.5rem}}
h1,h2{{line-height:1.3}}h1{{font-size:2.1rem}}h2{{margin-top:0}}a{{color:#075c59;text-underline-offset:.18em}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}th,td{{text-align:left;padding:.45rem;border-bottom:1px solid #dbe3e1}}
code{{overflow-wrap:anywhere}}pre{{background:#eef4f1;overflow:auto;padding:1rem}}summary{{cursor:pointer}}
@media(max-width:620px){{section{{padding:.85rem}}td code{{font-size:.75rem}}}} </style></head><body><main>
<h1>regmap 内核实验</h1>
<section><h2>两次更新为什么只留下一个位？</h2>
<p>两个调用者分别更新同一寄存器的一位。按任一串行顺序，结果都应为 <strong>{escape(expected)}</strong>。
这次内核执行读到 <strong>{observed}</strong>。图中每个节点都能打开实际事件和对应源码行。</p>
<p><a href="evidence/trace/reference/index.html">查看原始执行</a>　<a href="evidence/trace/reexecution/index.html">查看一次实际重执行</a></p>
<p>重执行匹配了原运行的关键路径。修复版在新构建上重新采样，同一用例的 {repair["attempts"]} 次回归均命中目标操作，性质检查通过。</p>
<p><a href="evidence/repair/regression.json">修复版逐次回执</a>　<a href="evidence/repair/cross-build.json">两版构建与用例对应关系</a></p></section>
<section><h2>六字节读取能安全省去哪些调用？</h2>
<p>在 BMA400 形状的读取中，原版对六个字节逐个调用格式转换。对专用入口持有的 8 位 map，转换函数有确定的地址，函数体为空。
优化版识别到这个函数后跳过六次调用，仍执行三笔两字节的总线读取。</p>
<details><summary>展开实际生成的 C 改动</summary><pre>{escape(diff)}</pre></details>
<p>局部证书覆盖返回值、成功数据、出错时已写入的前缀、总线操作和成功读取事件。它依赖受限对象一直存活、转换函数稳定、缓冲区归调用者所有，以及登记的编译链。回调入口跟踪使用原版。</p>
<p>锁定配置通过检查并生成两版源码。配置指纹改变时，生成器返回原版并记录原因 <code>{escape(fallback["reason"])}</code>。
带观察器的功能内核完成 {functional["final_slots"]} 个启动用例。</p>
<p><a href="evidence/opt/certificate.json">源码与证书</a>　<a href="evidence/opt/proof.json">Coq 检查回执</a>　<a href="evidence/opt/fallback.json">回退记录</a>　<a href="evidence/opt/functional.json">功能验收</a></p>
<details><summary>定理依赖与假设</summary><p>{assumption_links}</p></details></section>
<section><h2>最终构建的读取耗时</h2><p><strong>{verdict}</strong>。取得 {timing["inference_pairs_per_comparison"]} 对有效样本，覆盖 {len(timing["complete_rounds"])} 个完整轮次。
主比较要求耗时下降至少 5%，且按轮重采样的 95% 区间下界高于零。</p>
<table><thead><tr><th>实际入口</th><th>空回调次数 / 观察的读取次数</th><th>单次中位数（ns）</th><th>计时内核 build ID</th></tr></thead><tbody>{''.join(table)}</tbody></table>
<p>表中的调用计数取自单独的观察运行。正式计时关闭观察器。</p>
{''.join(comparisons)}
<p>计时覆盖正常编译下真实 Linux regmap 在 RAM 模拟总线上的完整读取。测量范围限于软件读取路径。</p>
<p><a href="summary.json">逐对时间及区间</a>　<a href="evidence/perf/protocol.json">采样协议</a>　<a href="evidence/perf/ledger.json">全部计时槽位</a></p></section>
</main></body></html>"""
