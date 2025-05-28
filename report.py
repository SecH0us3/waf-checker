import html as html_lib
from collections import Counter

def render_report(results):
    status_counter = Counter()
    total_requests = len(results)
    for r in results:
        status_counter[r["status"]] += 1
    # Сводная панель с прогресс-барами
    summary_html = f"""
    <div class='mb-3'>
        <div class='d-flex align-items-center mb-1'>
            <div style='min-width:90px;text-align:left;'><b>Total</b></div>
            <div style='height:24px;width:100%;min-width:2px;line-height:24px;padding-left:8px;text-align:left;display:inline-block;border-radius:4px;background:#d5d6d7;color:#222;font-weight:bold;'>
                {total_requests}
            </div>
        </div>
    """
    for code, count in sorted(status_counter.items(), key=lambda x: (str(x[0]))):
        if isinstance(code, int) and 300 <= code < 400:
            status_class = "status-redirect"
        elif code == 403:
            status_class = "status-green"
        elif isinstance(code, int) and (200 <= code < 300 or 500 <= code < 600):
            status_class = "status-red"
        elif isinstance(code, int) and 400 <= code < 500:
            status_class = "status-orange"
        else:
            status_class = "status-gray"
        percent = (count / total_requests * 100) if total_requests else 0
        summary_html += (
            f"<div class='d-flex align-items-center mb-1'>"
            f"  <div style='min-width:90px;text-align:left;'><b>Status {code}</b></div>"
            f"  <div class='{status_class}' style='height:24px;width:{percent:.2f}%;min-width:2px;line-height:24px;padding-left:8px;text-align:left;display:inline-block;border-radius:4px;'>"
            f"    {count}"
            f"  </div>"
            f"</div>"
        )
    summary_html += "</div>"
    # Основная таблица
    html = f"""
    <h3>Results</h3>
    {summary_html}
    <table border='1' cellpadding='5' class='w-100'>
        <tr><th>Category</th><th>Method</th><th>Status</th><th>Payload</th></tr>
    """
    for r in results:
        status_class = ""
        if r["is_redirect"]:
            status_class = "status-redirect"
        elif r["status"] == 403:
            status_class = "status-green"
        elif isinstance(r["status"], int) and (200 <= r["status"] < 300 or 500 <= r["status"] < 600):
            status_class = "status-red"
        elif isinstance(r["status"], int) and 400 <= r["status"] < 500:
            status_class = "status-orange"
        else:
            status_class = "status-gray"
        html_payload = html_lib.escape(r['payload'])
        html += f"<tr><td>{r['category']}</td><td>{r['method']}</td><td class='{status_class}'>{r['status']}</td><td><code>{html_payload}</code></td></tr>"
    html += "</table>"
    return html
