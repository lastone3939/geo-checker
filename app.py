import json
import re
import sqlite3
import os
import time
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from urllib.parse import urlparse, urljoin

import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request, abort
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app, origins=["https://web-production-d89ed.up.railway.app", "http://localhost:5002"])

# ===== レート制限（EDoS対策） =====
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# 1日の分析上限（API費用保護）
DAILY_LIMIT = int(os.environ.get("DAILY_ANALYSIS_LIMIT", "500"))

# ===== ログDB初期化 =====
DB_PATH = os.environ.get("DB_PATH", "geo_logs.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "zettai2026")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER,
            grade TEXT,
            ip TEXT,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_analysis(url, score, grade, ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO analyses (url, score, grade, ip, created_at) VALUES (?,?,?,?,?)",
            (url, score, grade, ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

init_db()

# Gemini API設定
genai.configure(api_key=os.environ.get("GEMINI_API_KEY", ""))
model = genai.GenerativeModel("gemini-2.5-flash")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10


def fetch_page(url):
    """サイトのHTMLを取得"""
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    resp.encoding = resp.apparent_encoding or "utf-8"
    return resp.text


def check_robots_txt(base_url):
    """robots.txtからAIボットのアクセス状況を確認"""
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp = requests.get(robots_url, headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code != 200:
            return {"exists": False, "content": "", "bots": {}}
        content = resp.text
        bots = {}
        for bot in ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "Googlebot"]:
            # 各ボットのAllow/Disallow状況を解析
            bot_section = False
            rules = []
            for line in content.split("\n"):
                line = line.strip()
                if line.lower().startswith("user-agent:"):
                    agent = line.split(":", 1)[1].strip()
                    bot_section = agent == bot or agent == "*"
                elif bot_section and line.lower().startswith(("allow:", "disallow:")):
                    rules.append(line)
                elif line == "" and bot_section and rules:
                    break
            # ボット名で専用セクションがあるか再チェック
            has_specific = any(
                line.strip().lower() == f"user-agent: {bot.lower()}"
                for line in content.split("\n")
            )
            if has_specific:
                specific_rules = []
                in_section = False
                for line in content.split("\n"):
                    line = line.strip()
                    if line.lower() == f"user-agent: {bot.lower()}":
                        in_section = True
                    elif in_section and line.lower().startswith("user-agent:"):
                        break
                    elif in_section and line.lower().startswith(("allow:", "disallow:")):
                        specific_rules.append(line)
                bots[bot] = {
                    "has_specific_rules": True,
                    "rules": specific_rules,
                    "blocked": any("disallow: /" == r.lower().strip() for r in specific_rules),
                }
            else:
                bots[bot] = {
                    "has_specific_rules": False,
                    "rules": [],
                    "blocked": False,
                }
        return {"exists": True, "content": content[:2000], "bots": bots}
    except Exception:
        return {"exists": False, "content": "", "bots": {}}


def check_llms_txt(base_url):
    """llms.txtの有無を確認"""
    try:
        resp = requests.get(urljoin(base_url, "/llms.txt"), headers=HEADERS, timeout=TIMEOUT)
        if resp.status_code == 200 and len(resp.text.strip()) > 0:
            return {"exists": True, "content": resp.text[:2000]}
        return {"exists": False, "content": ""}
    except Exception:
        return {"exists": False, "content": ""}


def extract_structured_data(soup):
    """JSON-LD構造化データを抽出"""
    scripts = soup.find_all("script", type="application/ld+json")
    data = []
    for s in scripts:
        try:
            parsed = json.loads(s.string)
            data.append(parsed)
        except (json.JSONDecodeError, TypeError):
            pass
    return data


def extract_meta_info(soup):
    """メタ情報を抽出"""
    title = soup.title.string.strip() if soup.title and soup.title.string else ""
    meta_desc = ""
    og_title = ""
    og_desc = ""
    canonical = ""
    tag = soup.find("meta", attrs={"name": "description"})
    if tag and tag.get("content"):
        meta_desc = tag["content"]
    tag = soup.find("meta", attrs={"property": "og:title"})
    if tag and tag.get("content"):
        og_title = tag["content"]
    tag = soup.find("meta", attrs={"property": "og:description"})
    if tag and tag.get("content"):
        og_desc = tag["content"]
    tag = soup.find("link", attrs={"rel": "canonical"})
    if tag and tag.get("href"):
        canonical = tag["href"]
    return {
        "title": title,
        "meta_description": meta_desc,
        "og_title": og_title,
        "og_description": og_desc,
        "canonical": canonical,
    }


def extract_headings(soup):
    """h1〜h3タグを抽出"""
    headings = {}
    for level in ["h1", "h2", "h3"]:
        tags = soup.find_all(level)
        headings[level] = [t.get_text(strip=True) for t in tags[:20]]
    return headings


def check_faq_content(soup, html):
    """FAQ/Q&A形式のコンテンツがあるか確認"""
    indicators = {
        "has_faq_schema": False,
        "has_qa_elements": False,
        "has_faq_section": False,
    }
    # FAQ構造化データ
    for s in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(s.string)
            text = json.dumps(data).lower()
            if "faqpage" in text or "question" in text:
                indicators["has_faq_schema"] = True
        except (json.JSONDecodeError, TypeError):
            pass
    # FAQ要素（details/summary, accordion的な構造）
    if soup.find_all("details") or soup.find_all("summary"):
        indicators["has_qa_elements"] = True
    # FAQセクション
    faq_pattern = re.compile(r"(よくある質問|FAQ|Q&A|質問と回答)", re.IGNORECASE)
    if faq_pattern.search(html[:50000]):
        indicators["has_faq_section"] = True
    return indicators


def analyze_with_gemini(site_data, retries=3, backoff=2):
    """Gemini APIで分析（リトライ付き）"""
    prompt = f"""あなたはGEO（Generative Engine Optimization）の専門家です。
以下のサイト情報を分析し、AI検索エンジン（ChatGPT、Claude、Perplexity、Gemini）に引用・参照されやすいサイトかを評価してください。

## 分析対象サイト情報

URL: {site_data['url']}

### robots.txt
存在: {site_data['robots']['exists']}
AIボット状況: {json.dumps(site_data['robots']['bots'], ensure_ascii=False, indent=2)}

### llms.txt
存在: {site_data['llms_txt']['exists']}
内容: {site_data['llms_txt']['content'][:500] if site_data['llms_txt']['exists'] else 'なし'}

### 構造化データ（JSON-LD）
{json.dumps(site_data['structured_data'][:5], ensure_ascii=False, indent=2) if site_data['structured_data'] else 'なし'}

### メタ情報
{json.dumps(site_data['meta'], ensure_ascii=False, indent=2)}

### 見出し構造
{json.dumps(site_data['headings'], ensure_ascii=False, indent=2)}

### FAQ/Q&Aコンテンツ
{json.dumps(site_data['faq'], ensure_ascii=False, indent=2)}

## 評価基準と出力形式

以下の5カテゴリで評価してください（各0〜100点）:

1. **ai_crawler_access**（AIクローラーアクセス）: robots.txtでAIボットをブロックしていないか、適切にアクセスを許可しているか
2. **llms_txt**（LLMs.txt対応）: llms.txtファイルが存在し、AI向けにサイト情報を提供しているか
3. **structured_data**（構造化データ）: JSON-LDで適切な構造化データがマークアップされているか
4. **content_citability**（引用されやすさ）: FAQ形式、明確な見出し構造、引用しやすいコンテンツ構造か
5. **meta_optimization**（メタ情報最適化）: title、description、OGPが適切に設定されているか

## 採点ルール
- 辛口で採点すること（甘くしない）
- overall_scoreは各カテゴリの加重平均（ai_crawler_access: 25%, llms_txt: 15%, structured_data: 25%, content_citability: 20%, meta_optimization: 15%）
- gradeはoverall_scoreに基づく: 90〜=A+, 80〜89=A, 70〜79=B, 60〜69=C, 50〜59=D, 〜49=F

必ず以下のJSON形式のみで回答してください（説明文なし、JSONのみ）:
{{
  "overall_score": 75,
  "grade": "B",
  "summary": "サイト全体の評価（2〜3文の日本語）",
  "categories": {{
    "ai_crawler_access": {{
      "score": 80,
      "title": "AIクローラーアクセス",
      "status": "good",
      "detail": "詳細説明（日本語）",
      "recommendations": ["改善提案1", "改善提案2"]
    }},
    "llms_txt": {{
      "score": 30,
      "title": "LLMs.txt対応",
      "status": "bad",
      "detail": "詳細説明（日本語）",
      "recommendations": ["改善提案1"]
    }},
    "structured_data": {{
      "score": 60,
      "title": "構造化データ",
      "status": "warning",
      "detail": "詳細説明（日本語）",
      "recommendations": ["改善提案1"]
    }},
    "content_citability": {{
      "score": 70,
      "title": "引用されやすさ",
      "status": "good",
      "detail": "詳細説明（日本語）",
      "recommendations": ["改善提案1"]
    }},
    "meta_optimization": {{
      "score": 85,
      "title": "メタ情報最適化",
      "status": "good",
      "detail": "詳細説明（日本語）",
      "recommendations": ["改善提案1"]
    }}
  }},
  "top_actions": [
    {{ "priority": "high", "action": "具体的なアクション（日本語）" }},
    {{ "priority": "medium", "action": "具体的なアクション（日本語）" }},
    {{ "priority": "low", "action": "具体的なアクション（日本語）" }}
  ],
  "practical_guide": {{
    "llms_txt_sample": "llms.txtが存在しない、または不十分な場合に、このサイト専用のllms.txtサンプルコードを生成してください。存在して十分な場合はnullにしてください。サイトのURL・構造・コンテンツを反映した実用的なものにしてください。",
    "schema_suggestion": "構造化データ（JSON-LD）が不足している場合に、追加すべきJSON-LDのサンプルコードを生成してください。十分な場合はnullにしてください。サイトの内容に合ったFAQPage、Organization、WebSiteなどを提案してください。",
    "faq_ideas": ["このサイトのテーマに合った、AIに引用されやすいFAQ案を3〜5個生成してください。サイト固有の内容を反映した具体的な質問にしてください。"],
    "quick_wins": [
      {{
        "title": "今日できること（30分以内で完了する具体的タスク名）",
        "steps": ["具体的な手順1（コピペで実行可能なレベルで）", "具体的な手順2"],
        "impact": "high"
      }}
    ]
  }}
}}

## practical_guideの生成ルール
- llms_txt_sample: llms.txtが存在しない or 内容が薄い場合のみ生成。Markdownベースでサイト構造を反映したサンプルを書く。既にあって十分ならnullにする。
- schema_suggestion: JSON-LDが不足している場合のみ生成。そのサイトに適した構造化データ（FAQPage、Organization、LocalBusiness等）のサンプルコードを書く。十分ならnullにする。
- faq_ideas: 必ず3〜5個。サイトのテーマ・業種に合わせた具体的FAQ案。「〇〇とは？」のような一般的すぎるものは避け、サイト固有の質問にする。
- quick_wins: 1〜3個。30分以内で実行可能な具体的タスク。stepsは実際にコピペで実行できるレベルの具体性。impactはhigh/medium/lowから選択。

statusの基準: score 70以上=good, 50〜69=warning, 49以下=bad
"""
    last_error = None
    for attempt in range(retries):
        try:
            response = model.generate_content(
                prompt,
                request_options={"timeout": 60},
            )
            text = response.text.strip()

            # JSONブロックを抽出（ネストされたコードブロックに対応）
            import re as _re
            m = _re.search(r'```json\s*([\s\S]*?)```', text)
            if m:
                text = m.group(1).strip()
            else:
                m = _re.search(r'```\s*([\s\S]*?)```', text)
                if m:
                    text = m.group(1).strip()

            # JSONとして試行
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                start = text.find('{')
                end = text.rfind('}')
                if start != -1 and end != -1:
                    return json.loads(text[start:end+1])
                raise

        except Exception as e:
            err_str = str(e)
            last_error = e
            # レート制限 or 過負荷 → リトライ
            if any(kw in err_str for kw in ("429", "quota", "RESOURCE_EXHAUSTED", "overloaded", "503")):
                if attempt < retries - 1:
                    wait = backoff * (attempt + 1)
                    time.sleep(wait)
                    continue
                raise RuntimeError("APIの利用制限に達しました。しばらく待ってから再度お試しください。") from e
            # 認証エラー → リトライ不要
            if any(kw in err_str for kw in ("401", "403", "API_KEY", "invalid", "INVALID_ARGUMENT")):
                raise RuntimeError("APIキーが無効です。管理者にお問い合わせください。") from e
            # その他 → リトライ
            if attempt < retries - 1:
                time.sleep(backoff)
                continue
            raise

    raise last_error


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
@limiter.limit("5 per minute;20 per hour;50 per day")
def analyze():
    # 1日の全体上限チェック（API費用保護）
    try:
        conn = sqlite3.connect(DB_PATH)
        today = datetime.now().strftime("%Y-%m-%d")
        count = conn.execute(
            "SELECT COUNT(*) FROM analyses WHERE created_at LIKE ?", (f"{today}%",)
        ).fetchone()[0]
        conn.close()
        if count >= DAILY_LIMIT:
            return jsonify({"error": "本日の分析上限（{}件）に達しました。明日またお試しください。".format(DAILY_LIMIT)}), 429
    except Exception:
        pass

    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URLを入力してください"}), 400

    # URLの正規化
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    try:
        # 1. サイト取得
        html = fetch_page(url)
        soup = BeautifulSoup(html, "html.parser")

        # 2. robots.txtチェック
        robots = check_robots_txt(base_url)

        # 3. llms.txtチェック
        llms_txt = check_llms_txt(base_url)

        # 4. 構造化データ抽出
        structured_data = extract_structured_data(soup)

        # 5. メタ情報抽出
        meta = extract_meta_info(soup)

        # 6. 見出し構造抽出
        headings = extract_headings(soup)

        # 7. FAQ/Q&Aコンテンツ確認
        faq = check_faq_content(soup, html)

        # 収集データをまとめる
        site_data = {
            "url": url,
            "robots": robots,
            "llms_txt": llms_txt,
            "structured_data": structured_data,
            "meta": meta,
            "headings": headings,
            "faq": faq,
        }

        # Geminiで分析
        result = analyze_with_gemini(site_data)
        result["analyzed_url"] = url

        # ログ記録
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        log_analysis(url, result.get("overall_score"), result.get("grade"), ip)

        return jsonify(result)

    except requests.exceptions.Timeout:
        return jsonify({"error": "サイトの取得がタイムアウトしました（10秒）"}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "サイトに接続できませんでした。URLを確認してください"}), 502
    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"サイトからエラーが返されました: {e.response.status_code}"}), 502
    except json.JSONDecodeError:
        return jsonify({"error": "AI分析結果の解析に失敗しました。もう一度お試しください"}), 500
    except Exception as e:
        return jsonify({"error": f"分析中にエラーが発生しました: {str(e)}"}), 500


@app.route("/admin/logs")
def admin_logs():
    token = request.args.get("token", "")
    if token != ADMIN_TOKEN:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, url, score, grade, ip, created_at FROM analyses ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    total = len(rows)
    avg = round(sum(r[2] for r in rows if r[2]) / total, 1) if total else 0
    html = f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<title>GEOチェッカー 管理ログ</title>
<style>
body{{font-family:'Noto Sans JP',sans-serif;background:#F8FAFC;color:#111;padding:2rem}}
h1{{font-size:1.5rem;font-weight:700;margin-bottom:1rem}}
.stats{{display:flex;gap:1.5rem;margin-bottom:1.5rem}}
.stat{{background:#fff;border:1px solid #E2E8F0;border-radius:8px;padding:1rem 1.5rem}}
.stat-num{{font-size:2rem;font-weight:800;color:#2563EB}}
.stat-label{{font-size:.85rem;color:#6B7280}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
th{{background:#F1F5F9;padding:.75rem 1rem;text-align:left;font-size:.85rem;color:#374151}}
td{{padding:.75rem 1rem;border-top:1px solid #F1F5F9;font-size:.9rem}}
.grade{{font-weight:700;padding:.2rem .5rem;border-radius:4px;font-size:.85rem}}
.A{{background:#DCFCE7;color:#16A34A}}.B{{background:#FEF9C3;color:#CA8A04}}
.C,.D{{background:#FEE2E2;color:#DC2626}}.F{{background:#111;color:#fff}}
</style></head><body>
<h1>📊 GEOチェッカー 分析ログ</h1>
<div class="stats">
  <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">総分析数</div></div>
  <div class="stat"><div class="stat-num">{avg}</div><div class="stat-label">平均スコア</div></div>
</div>
<table>
<tr><th>#</th><th>URL</th><th>スコア</th><th>グレード</th><th>IP</th><th>日時</th></tr>
"""
    for r in rows:
        rid, url, score, grade, ip, created_at = r
        grade_cls = (grade or "F")[0]
        html += f'<tr><td>{rid}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{url}</td><td>{score or "-"}</td><td><span class="grade {grade_cls}">{grade or "-"}</span></td><td>{ip or "-"}</td><td>{created_at}</td></tr>'
    html += "</table></body></html>"
    return html


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "リクエストが多すぎます。しばらく待ってから再度お試しください。"}), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
