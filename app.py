import json
import re
import sqlite3
import os
import time
import threading
import uuid
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from io import BytesIO
from dotenv import load_dotenv
load_dotenv()
from urllib.parse import urlparse, urljoin, unquote

import requests
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request, abort, send_file
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

# Google Places API
GOOGLE_PLACES_API_KEY = os.environ.get("GOOGLE_PLACES_API_KEY", "")

# SMTP設定（メール送信）
SMTP_HOST = os.environ.get("SMTP_HOST", "sv14580.xserver.jp")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "omakaseaio@givefast.jp")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "omakaseaio@givefast.jp")

# ===== ログDB初期化 =====
DB_PATH = os.environ.get("DB_PATH", "geo_logs.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # 必ず環境変数で設定すること

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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gbp_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            business_name TEXT,
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

def log_gbp_analysis(url, business_name, score, grade, ip):
    """GBP分析ログを記録"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO gbp_analyses (url, business_name, score, grade, ip, created_at) VALUES (?,?,?,?,?,?)",
            (url, business_name, score, grade, ip, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

init_db()

# 診断ジョブ管理
ANALYZE_JOBS = {}  # job_id -> {status, result, error, created_at}

# 動画生成ジョブ管理
VIDEO_JOBS = {}  # job_id -> {status, progress, video_path, error, created_at}
VIDEO_DIR = Path(tempfile.gettempdir()) / "gbp_videos"
VIDEO_DIR.mkdir(exist_ok=True)

# Gemini REST API設定（gRPC不使用・軽量）
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_REST_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

def call_gemini(prompt: str, retries: int = 3, backoff: int = 2) -> dict:
    """Gemini REST APIを直接呼び出す（gRPC不使用）"""
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 8192},
    }
    last_error = None
    for attempt in range(retries):
        try:
            resp = requests.post(
                GEMINI_REST_URL,
                params={"key": GEMINI_API_KEY},
                json=payload,
                timeout=90,
            )
            if resp.status_code == 429:
                raise RuntimeError("APIの利用制限に達しました。しばらく待ってから再度お試しください。")
            if resp.status_code in (401, 403):
                raise RuntimeError("APIキーが無効です。管理者にお問い合わせください。")
            resp.raise_for_status()
            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            # JSONブロック抽出
            m = re.search(r'```json\s*([\s\S]*?)```', text)
            if m:
                text = m.group(1).strip()
            else:
                m = re.search(r'```\s*([\s\S]*?)```', text)
                if m:
                    text = m.group(1).strip()
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                start, end = text.find('{'), text.rfind('}')
                if start != -1 and end != -1:
                    return json.loads(text[start:end+1])
                raise
        except (RuntimeError, json.JSONDecodeError):
            raise
        except Exception as e:
            last_error = e
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
                continue
            raise
    raise last_error

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}
TIMEOUT = 10


BLOCKED_IP_RANGES = [
    "127.", "0.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "169.254.", "::1", "fc00:", "fd",
]

def is_safe_url(url: str) -> bool:
    """SSRF対策: 内部IPへのアクセスを拒否"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname or ""
        import socket
        try:
            resolved = socket.gethostbyname(host)
        except socket.gaierror:
            return True  # 名前解決できない場合はfetch時にエラーになる
        for blocked in BLOCKED_IP_RANGES:
            if resolved.startswith(blocked) or resolved == blocked.rstrip("."):
                return False
        return True
    except Exception:
        return False


def fetch_page(url):
    """サイトのHTMLを取得（SSRF対策付き）"""
    if not is_safe_url(url):
        raise ValueError("内部ネットワークへのアクセスは許可されていません")
    resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
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
    return call_gemini(prompt, retries=retries, backoff=backoff)


def resolve_url(url: str) -> str:
    """短縮URLを最終URLに展開（share.google / maps.app.goo.gl 等）"""
    short_hosts = ["share.google", "maps.app.goo.gl", "goo.gl", "g.page"]
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if any(host == h or host.endswith("." + h) for h in short_hosts):
        try:
            r = requests.get(url, allow_redirects=True, timeout=10,
                             headers={"User-Agent": "Mozilla/5.0"})
            return r.url
        except Exception:
            pass
    return url


def validate_gbp_url(url):
    """GoogleマップURLのバリデーション（share.google / maps.app.goo.gl も許可）"""
    parsed = urlparse(url)
    valid_hosts = [
        "maps.google.com", "www.google.com", "google.com",
        "maps.google.co.jp", "www.google.co.jp", "google.co.jp",
        "g.page", "goo.gl", "maps.app.goo.gl", "share.google",
    ]
    host = parsed.netloc.lower()
    if any(host == h or host.endswith("." + h) for h in valid_hosts):
        return True
    return False


def extract_business_name_from_url(url):
    """GoogleマップURLからビジネス名を抽出"""
    parsed = urlparse(url)
    path = unquote(parsed.path)
    # /maps/place/ビジネス名/... パターン
    m = re.search(r'/place/([^/@]+)', path)
    if m:
        name = m.group(1).replace('+', ' ')
        return name
    return None


def fetch_gmaps_page(url):
    """GoogleマップページのHTML断片を取得（限定的）"""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        resp.encoding = resp.apparent_encoding or "utf-8"
        html = resp.text[:50000]
        return html
    except Exception:
        return ""


def analyze_gbp_with_gemini(url, business_name, html_snippet, retries=3, backoff=2):
    """GBP分析用Geminiプロンプト"""
    prompt = f"""あなたはGoogleビジネスプロフィール（GBP）とローカルSEOの専門家です。
以下のGoogleマップURLとそこから取得できた情報を基に、GBPの最適化状況を分析してください。

## 分析対象
GoogleマップURL: {url}
ビジネス名（URLから抽出）: {business_name or '不明'}

## 取得できたHTML断片（参考情報）
{html_snippet[:5000] if html_snippet else 'HTML取得不可（JSレンダリングのため限定的）'}

## 重要な指示
- GoogleマップページはJavaScriptでレンダリングされるため、HTMLからの情報は限定的です
- あなたの知識ベースにあるこのビジネスの情報や、GBP最適化のベストプラクティスを組み合わせて分析してください
- URLとビジネス名から推測できる業種・業態に基づいて、具体的かつ実践的な改善提案を行ってください
- 情報が不足している場合は、一般的なGBP最適化のベストプラクティスに基づいて診断してください

## 評価カテゴリ（各0〜100点）

1. **profile_completeness**（プロフィール完成度）: ビジネス名、カテゴリ、住所、電話番号、営業時間、Webサイト、説明文の充実度
2. **photos_videos**（写真・動画）: 写真数・品質・多様性（外観・内観・商品・スタッフ）
3. **reviews_management**（クチコミ管理）: クチコミ数、平均評価、オーナー返信率と質
4. **posts_activity**（投稿活動）: 投稿頻度、投稿タイプの多様性（最新情報・特典・イベント）
5. **qa_section**（Q&A管理）: Q&Aの有無、ビジネスによる先行Q&A設置
6. **local_seo**（ローカルSEO）: カテゴリ選択最適化、キーワード、属性・サービス設定

## 採点ルール
- 辛口で採点すること（甘くしない）
- URLから直接確認できない項目は、一般的な中小ビジネスの平均的な状態を想定して採点
- overall_scoreは6カテゴリの均等平均
- gradeはoverall_scoreに基づく: 90〜=A+, 80〜89=A, 70〜79=B, 60〜69=C, 50〜59=D, 〜49=F
- statusの基準: score 70以上=good, 50〜69=warning, 49以下=bad

必ず以下のJSON形式のみで回答してください（説明文なし、JSONのみ）:
{{
  "overall_score": 65,
  "grade": "C",
  "business_name": "ビジネス名（推定含む）",
  "summary": "全体評価（2〜3文の日本語）",
  "gbp_news": "2026年3月にGoogleがGemini搭載「Ask Maps」とImmersive Navigationを発表。月間20億人のGoogle MapsがAI会話型に大刷新。GBP最適化の重要性がさらに増しています。",
  "categories": {{
    "profile_completeness": {{
      "score": 70,
      "title": "プロフィール完成度",
      "status": "good",
      "detail": "詳細説明（日本語）",
      "recommendations": ["改善案1", "改善案2"]
    }},
    "photos_videos": {{
      "score": 40,
      "title": "写真・動画",
      "status": "bad",
      "detail": "詳細説明",
      "recommendations": ["改善案1"]
    }},
    "reviews_management": {{
      "score": 55,
      "title": "クチコミ管理",
      "status": "warning",
      "detail": "詳細説明",
      "recommendations": ["改善案1"]
    }},
    "posts_activity": {{
      "score": 30,
      "title": "投稿活動",
      "status": "bad",
      "detail": "詳細説明",
      "recommendations": ["改善案1"]
    }},
    "qa_section": {{
      "score": 20,
      "title": "Q&A管理",
      "status": "bad",
      "detail": "詳細説明",
      "recommendations": ["改善案1"]
    }},
    "local_seo": {{
      "score": 60,
      "title": "ローカルSEO",
      "status": "warning",
      "detail": "詳細説明",
      "recommendations": ["改善案1"]
    }}
  }},
  "top_actions": [
    {{ "priority": "high", "action": "最も効果の高い具体的アクション" }},
    {{ "priority": "high", "action": "2番目に効果の高い具体的アクション" }},
    {{ "priority": "medium", "action": "具体的アクション" }}
  ],
  "practical_guide": {{
    "quick_wins": [
      {{
        "title": "今日できること（具体的タスク名）",
        "steps": ["手順1（具体的に）", "手順2"],
        "impact": "high"
      }}
    ],
    "gbp_post_sample": "そのビジネスに合わせたGBP投稿文サンプル（300文字程度、絵文字・ハッシュタグ付き）。投稿タイプ（最新情報/特典/イベント）も明示。",
    "response_template": "クチコミ返信テンプレート。ポジティブ返信例とネガティブ返信例の両方を含める。ビジネスの業種に合わせた具体的な内容にする。"
  }}
}}

## practical_guideの生成ルール（★超重要★）

### quick_wins の stepsは以下のレベルで具体的に書くこと:
実際の操作画面・ボタン名・入力内容を含める。「〜する」ではなく「〜を押す」「〜と入力する」レベルで。

例（写真追加の場合）:
steps: [
  "ブラウザで business.google.com を開いてログイン",
  "左メニュー「写真」→「写真を追加」ボタンをクリック",
  "外観写真3枚・店内写真3枚・商品/メニュー写真5枚以上をアップロード",
  "写真のファイル名を「店名_外観01.jpg」のように日本語+番号にしてから保存",
  "カバー写真には最も明るく魅力的な外観写真を設定"
]

例（クチコミ返信の場合）:
steps: [
  "business.google.com にログイン→「クチコミ」タブを開く",
  "「返信する」ボタンが表示されている未返信クチコミをすべて確認",
  "★4-5のクチコミには24時間以内に返信（下のテンプレートをコピペ可）",
  "★1-3のクチコミには謝罪・改善策・連絡先を含む返信を48時間以内に投稿",
  "今後は毎週月曜に返信チェックをカレンダーに登録する"
]

例（GBP投稿の場合）:
steps: [
  "business.google.com にログイン→「投稿を追加」ボタンをクリック",
  "投稿タイプ「最新情報」を選択",
  "下のサンプルテキストをコピーして編集（業種・日付・内容を書き換え）",
  "写真1枚以上を添付（600×900px推奨、スマホで撮影してもOK）",
  "「公開」ボタンを押して投稿完了→月2〜4回のペースで継続"
]

- quick_wins: 必ず2〜3個。各タスクは30分以内で完了できるもの。stepsは上記例のように5ステップ程度の詳細な手順。
- gbp_post_sample: そのビジネスの業種・地域に合わせた具体的な投稿文（300文字以内）。絵文字・ハッシュタグあり。投稿タイプ明示。「コピーしてそのまま使える」レベルで。
- response_template: ポジティブ（★4-5）・ネガティブ（★1-2）両パターン。「お客様のお名前」等のプレースホルダー形式で記述。業種に合わせた言葉遣い。
"""
    return call_gemini(prompt, retries=retries, backoff=backoff)


def get_query_from_url(url: str) -> tuple:
    """Google Maps URLからPlace ID / ビジネス名 / 座標を抽出
    戻り値: (place_id_or_none, query_string, lat, lng)
    """
    from urllib.parse import unquote, parse_qs
    place_id = None
    query = ""
    lat, lng = None, None
    # 1. Place ID (ChIJ形式) を dataパラメータから抽出
    pid_m = re.search(r"!1s(ChIJ[A-Za-z0-9_\-]+)", url)
    if pid_m:
        place_id = pid_m.group(1)
    # 2. /place/NAME/ からビジネス名
    name_m = re.search(r"/place/([^/@]+)", url)
    if name_m:
        query = unquote(name_m.group(1)).replace("+", " ")
    # 3. ?q= パラメータ
    if not query:
        parsed_u = urlparse(url)
        qs = parse_qs(parsed_u.query)
        if "q" in qs:
            query = qs["q"][0]
    # 4. 座標抽出
    coord_m = re.search(r"@(-?\d+\.\d+),(-?\d+\.\d+)", url)
    if coord_m:
        lat, lng = float(coord_m.group(1)), float(coord_m.group(2))
    else:
        coord_m2 = re.search(r"!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)", url)
        if coord_m2:
            lat, lng = float(coord_m2.group(1)), float(coord_m2.group(2))
    return place_id, query, lat, lng


def scrape_gbp_photos(url: str, max_photos: int = 12) -> list:
    """Google Places APIで写真URLを取得（Place ID優先 → テキスト検索フォールバック）"""
    if not GOOGLE_PLACES_API_KEY:
        app.logger.error("GOOGLE_PLACES_API_KEY not set")
        return []

    # 短縮URL（share.google / maps.app.goo.gl）を展開
    url = resolve_url(url)
    app.logger.info(f"resolve後URL: {url[:100]}")

    place_id, query, lat, lng = get_query_from_url(url)
    photos = []
    biz_name = ""

    # ルート1: Place IDが取れた場合 → Place Details APIで直接取得（最正確）
    if place_id:
        app.logger.info(f"Places API: Place ID直接取得 {place_id}")
        try:
            resp = requests.get(
                f"https://places.googleapis.com/v1/places/{place_id}",
                headers={
                    "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY,
                    "X-Goog-FieldMask": "displayName,photos",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                d = resp.json()
                photos = d.get("photos", [])
                biz_name = d.get("displayName", {}).get("text", "")
                app.logger.info(f"Place Details OK: {biz_name} / {len(photos)}枚")
            else:
                app.logger.warning(f"Place Details {resp.status_code}, フォールバック")
        except Exception as e:
            app.logger.warning(f"Place Details失敗: {e}, フォールバック")

    # ルート2: テキスト検索（位置情報付き）
    if not photos:
        if not query:
            query = extract_business_name_from_url(url) or "restaurant"
        app.logger.info(f"Places APIテキスト検索: query={query} lat={lat} lng={lng}")
        search_body = {"textQuery": query, "pageSize": 1}
        if lat and lng:
            search_body["locationBias"] = {
                "circle": {
                    "center": {"latitude": lat, "longitude": lng},
                    "radius": 300.0
                }
            }
        try:
            resp = requests.post(
                "https://places.googleapis.com/v1/places:searchText",
                headers={
                    "Content-Type": "application/json",
                    "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY,
                    "X-Goog-FieldMask": "places.id,places.displayName,places.photos",
                },
                json=search_body,
                timeout=15,
            )
            resp.raise_for_status()
            places = resp.json().get("places", [])
            if places:
                photos = places[0].get("photos", [])
                biz_name = places[0].get("displayName", {}).get("text", "")
                app.logger.info(f"Text Search OK: {biz_name} / {len(photos)}枚")
        except Exception as e:
            app.logger.error(f"Places API text search error: {e}")
            return []

    photo_urls = []
    for photo in photos[:max_photos]:
        name = photo.get("name", "")
        if name:
            photo_urls.append(
                f"https://places.googleapis.com/v1/{name}/media"
                f"?maxWidthPx=1280&maxHeightPx=720&key={GOOGLE_PLACES_API_KEY}&skipHttpRedirect=false"
            )
    return photo_urls


def _REMOVED_playwright_scrape(url: str, max_photos: int = 12) -> list:
    """(旧) PlaywrightでGoogleマップから写真URLを取得"""
    from playwright.sync_api import sync_playwright

    photo_urls = []
    seen = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                    "--single-process",
                ]
            )
            ctx = browser.new_context(
                user_agent="Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                viewport={"width": 390, "height": 844},
                locale="ja-JP",
            )
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(3000)

            # 写真タブを探してクリック
            for selector in [
                "button[aria-label*='写真']",
                "button[aria-label*='Photo']",
                "[jsaction*='pane.rating.morePhotos']",
                "a[href*='photos']",
            ]:
                try:
                    el = page.locator(selector).first
                    if el.is_visible(timeout=2000):
                        el.click()
                        page.wait_for_timeout(2000)
                        break
                except Exception:
                    pass

            # スクロールして追加写真を読み込む
            for _ in range(4):
                page.keyboard.press("End")
                page.wait_for_timeout(800)

            # lh3.googleusercontent.com の画像URLを収集
            imgs = page.evaluate("""() => {
                const imgs = document.querySelectorAll('img');
                const urls = [];
                imgs.forEach(img => {
                    const src = img.src || img.getAttribute('src') || '';
                    if (src.includes('googleusercontent.com') && src.length > 50) {
                        urls.push(src);
                    }
                });
                // CSSのbackground-imageも探す
                document.querySelectorAll('[style]').forEach(el => {
                    const style = el.getAttribute('style') || '';
                    const m = style.match(/url\\(["']?(https:\\/\\/[^"')]+googleusercontent[^"')]+)["']?\\)/);
                    if (m) urls.push(m[1]);
                });
                return urls;
            }""")

            for src in imgs:
                high_res = re.sub(r"=(?:s\d+|w\d+-h\d+)[^&\"' ]*", "=w1200-h800", src)
                if high_res not in seen and len(high_res) > 60:
                    seen.add(high_res)
                    photo_urls.append(high_res)
                    if len(photo_urls) >= max_photos:
                        break

            ctx.close()
            browser.close()

    except Exception as e:
        app.logger.error(f"scrape_gbp_photos error: {e}")

    app.logger.info(f"scrape_gbp_photos: {len(photo_urls)}枚取得")
    return photo_urls


def download_photo(url: str, dest: Path) -> bool:
    """写真をダウンロード"""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=15)
        resp.raise_for_status()

        from PIL import Image
        img = Image.open(BytesIO(resp.content)).convert("RGB")
        img = img.resize((1280, 720), Image.LANCZOS)
        img.save(dest, "JPEG", quality=90)
        return True
    except Exception as e:
        app.logger.error(f"download_photo error: {e}")
        return False


def create_slideshow_video(photo_paths: list, output_path: Path, duration: float = 20.0, sparkle: bool = False) -> bool:
    """FFmpegでスライドショー動画を生成（GBP規格: MP4 H.264 720p 最大30秒）"""
    n = len(photo_paths)
    if n == 0:
        return False

    total = min(duration, 28.0)
    per_slide = round(total / n, 2)
    fps = 25

    try:
        # 各画像を個別セグメントに変換してからconcatで結合（最もシンプル・確実）
        segment_paths = []
        for i, p in enumerate(photo_paths):
            seg = output_path.parent / f"seg_{i:03d}.mp4"
            cmd = [
                "ffmpeg", "-y",
                "-loop", "1", "-i", str(p),
                "-vf", "scale=1280:720:force_original_aspect_ratio=decrease,"
                       "pad=1280:720:(ow-iw)/2:(oh-ih)/2:black,setsar=1",
                "-c:v", "libx264", "-preset", "ultrafast",
                "-pix_fmt", "yuv420p",
                "-t", str(per_slide),
                "-r", str(fps),
                str(seg),
            ]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode != 0:
                app.logger.error(f"segment {i} ffmpeg error: {r.stderr[-300:]}")
                return False
            segment_paths.append(seg)

        # concat list
        concat_file = output_path.parent / "concat.txt"
        with open(concat_file, "w") as f:
            for seg in segment_paths:
                f.write(f"file '{seg}'\n")

        # 結合
        cmd2 = [
            "ffmpeg", "-y",
            "-f", "concat", "-safe", "0", "-i", str(concat_file),
            "-c:v", "libx264", "-preset", "fast",
            "-pix_fmt", "yuv420p",
            "-movflags", "+faststart",
            str(output_path),
        ]
        r2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=120)
        if r2.returncode != 0:
            app.logger.error(f"concat ffmpeg error: {r2.stderr[-300:]}")
            return False

        if sparkle and output_path.exists():
            tmp_path = output_path.parent / "tmp_base.mp4"
            import shutil; shutil.copy2(str(output_path), str(tmp_path))
            sparkle_cmd = [
                "ffmpeg", "-y", "-i", str(tmp_path),
                "-vf", (
                    "eq=brightness=0.08:saturation=1.4:contrast=1.05,"
                    "geq=lum='min(255,lum(X\,Y)+if(gt(random(1),0.9975),220,0))'"
                    ":cb='cb(X\,Y)':cr='cr(X\,Y)'"
                ),
                "-c:v", "libx264", "-preset", "fast",
                "-pix_fmt", "yuv420p", "-movflags", "+faststart",
                str(output_path),
            ]
            r3 = subprocess.run(sparkle_cmd, capture_output=True, text=True, timeout=120)
            if r3.returncode != 0:
                app.logger.error(f"sparkle error: {r3.stderr[-200:]}")
                shutil.copy2(str(tmp_path), str(output_path))
            try: tmp_path.unlink()
            except: pass

        return output_path.exists() and output_path.stat().st_size > 1000

    except Exception as e:
        app.logger.error(f"create_slideshow_video error: {e}")
        return False


def run_analyze_job(job_id: str, url: str, job_type: str):
    """GEO/GBP診断をバックグラウンドで実行"""
    try:
        ANALYZE_JOBS[job_id]["status"] = "running"
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        if job_type == "geo":
            html = fetch_page(url)
            soup = BeautifulSoup(html, "html.parser")
            robots = check_robots_txt(base_url)
            llms_txt = check_llms_txt(base_url)
            structured_data = extract_structured_data(soup)
            meta = extract_meta_info(soup)
            headings = extract_headings(soup)
            faq = check_faq_content(soup, html)
            site_data = {
                "url": url, "robots": robots, "llms_txt": llms_txt,
                "structured_data": structured_data, "meta": meta,
                "headings": headings, "faq": faq,
            }
            result = analyze_with_gemini(site_data)
            result["analyzed_url"] = url
            log_analysis(url, result.get("overall_score"), result.get("grade"), "async")
            ANALYZE_JOBS[job_id]["result"] = result
            ANALYZE_JOBS[job_id]["status"] = "done"

        elif job_type == "gbp":
            url = resolve_url(url)  # share.google / maps.app.goo.gl を展開
            business_name = extract_business_name_from_url(url)
            html_snippet = fetch_gmaps_page(url)
            if html_snippet:
                soup = BeautifulSoup(html_snippet, "html.parser")
                if not business_name and soup.title and soup.title.string:
                    m = re.match(r"^(.+?)\s*[-–]\s*Google", soup.title.string.strip())
                    if m:
                        business_name = m.group(1).strip()
            result = analyze_gbp_with_gemini(url, business_name, html_snippet)
            result["analyzed_url"] = url
            if not result.get("business_name") and business_name:
                result["business_name"] = business_name
            log_gbp_analysis(url, result.get("business_name", business_name or "不明"),
                           result.get("overall_score"), result.get("grade"), "async")
            ANALYZE_JOBS[job_id]["result"] = result
            ANALYZE_JOBS[job_id]["status"] = "done"

    except requests.exceptions.Timeout:
        ANALYZE_JOBS[job_id]["status"] = "error"
        ANALYZE_JOBS[job_id]["error"] = "サイトの取得がタイムアウトしました（10秒）"
    except requests.exceptions.ConnectionError:
        ANALYZE_JOBS[job_id]["status"] = "error"
        ANALYZE_JOBS[job_id]["error"] = "サイトに接続できませんでした。URLを確認してください"
    except Exception as e:
        ANALYZE_JOBS[job_id]["status"] = "error"
        ANALYZE_JOBS[job_id]["error"] = "分析中にエラーが発生しました。しばらくしてから再度お試しください"
        app.logger.error(f"analyze job error ({job_type}): {e}")


def run_video_job(job_id: str, url: str, sparkle: bool = False):
    """バックグラウンドで動画生成ジョブを実行"""
    try:
        url = resolve_url(url)  # share.google / maps.app.goo.gl を展開
        VIDEO_JOBS[job_id]["status"] = "scraping"
        VIDEO_JOBS[job_id]["progress"] = 10

        # 1. 写真URLを取得
        photo_urls = scrape_gbp_photos(url, max_photos=12)

        if not photo_urls:
            VIDEO_JOBS[job_id]["status"] = "error"
            VIDEO_JOBS[job_id]["error"] = "写真が見つかりませんでした。GoogleマップのURLを確認してください。"
            return

        VIDEO_JOBS[job_id]["progress"] = 40
        VIDEO_JOBS[job_id]["status"] = "downloading"

        # 2. 写真をダウンロード
        job_dir = VIDEO_DIR / job_id
        job_dir.mkdir(exist_ok=True)

        photo_paths = []
        for i, photo_url in enumerate(photo_urls):
            dest = job_dir / f"photo_{i:03d}.jpg"
            if download_photo(photo_url, dest):
                photo_paths.append(dest)

        if len(photo_paths) < 1:
            VIDEO_JOBS[job_id]["status"] = "error"
            VIDEO_JOBS[job_id]["error"] = "写真のダウンロードに失敗しました。"
            return

        VIDEO_JOBS[job_id]["progress"] = 70
        VIDEO_JOBS[job_id]["status"] = "encoding"

        # 3. 動画生成
        output_path = job_dir / "slideshow.mp4"
        success = create_slideshow_video(photo_paths, output_path, duration=20.0, sparkle=sparkle)

        if success and output_path.exists():
            VIDEO_JOBS[job_id]["status"] = "done"
            VIDEO_JOBS[job_id]["progress"] = 100
            VIDEO_JOBS[job_id]["video_path"] = str(output_path)
            VIDEO_JOBS[job_id]["photo_count"] = len(photo_paths)
        else:
            VIDEO_JOBS[job_id]["status"] = "error"
            VIDEO_JOBS[job_id]["error"] = "動画の生成に失敗しました。"

    except Exception as e:
        VIDEO_JOBS[job_id]["status"] = "error"
        VIDEO_JOBS[job_id]["error"] = str(e)
        app.logger.error(f"video job error: {e}")


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

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not is_safe_url(url):
        return jsonify({"error": "このURLは診断できません"}), 400

    job_id = str(uuid.uuid4())
    ANALYZE_JOBS[job_id] = {
        "type": "geo",
        "url": url,
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": datetime.now().isoformat()
    }
    t = threading.Thread(target=run_analyze_job, args=(job_id, url, "geo"))
    t.daemon = True
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/analyze-status/<job_id>")
def analyze_status(job_id: str):
    job = ANALYZE_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "ジョブが見つかりません"}), 404
    if job["status"] == "done":
        return jsonify({"status": "done", "result": job["result"]})
    elif job["status"] == "error":
        return jsonify({"status": "error", "error": job["error"]})
    else:
        return jsonify({"status": job["status"]})


@app.route("/api/analyze-gbp", methods=["POST"])
@limiter.limit("5 per minute;20 per hour;50 per day")
def analyze_gbp():
    """GBP（Googleビジネスプロフィール）診断API"""
    # 日次上限チェック
    try:
        conn = sqlite3.connect(DB_PATH)
        today = datetime.now().strftime("%Y-%m-%d")
        count_web = conn.execute(
            "SELECT COUNT(*) FROM analyses WHERE created_at LIKE ?", (f"{today}%",)
        ).fetchone()[0]
        count_gbp = conn.execute(
            "SELECT COUNT(*) FROM gbp_analyses WHERE created_at LIKE ?", (f"{today}%",)
        ).fetchone()[0]
        conn.close()
        if (count_web + count_gbp) >= DAILY_LIMIT:
            return jsonify({"error": "本日の分析上限（{}件）に達しました。明日またお試しください。".format(DAILY_LIMIT)}), 429
    except Exception:
        pass

    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "GoogleマップURLを入力してください"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not validate_gbp_url(url):
        return jsonify({"error": "有効なGoogleマップURLを入力してください（maps.google.com, google.com/maps, g.page等）"}), 400

    job_id = str(uuid.uuid4())
    ANALYZE_JOBS[job_id] = {
        "type": "gbp",
        "url": url,
        "status": "pending",
        "result": None,
        "error": None,
        "created_at": datetime.now().isoformat()
    }
    t = threading.Thread(target=run_analyze_job, args=(job_id, url, "gbp"))
    t.daemon = True
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/api/create-video", methods=["POST"])
@limiter.limit("2 per minute;5 per hour;10 per day")
def create_video():
    """GBP写真からスライドショー動画を生成"""
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "GoogleマップURLを入力してください"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if not validate_gbp_url(url):
        return jsonify({"error": "有効なGoogleマップURLを入力してください"}), 400

    job_id = str(uuid.uuid4())
    VIDEO_JOBS[job_id] = {
        "status": "pending",
        "progress": 0,
        "video_path": None,
        "error": None,
        "created_at": datetime.now().isoformat()
    }

    sparkle = bool(data.get("sparkle", False))
    t = threading.Thread(target=run_video_job, args=(job_id, url, sparkle))
    t.daemon = True
    t.start()

    return jsonify({"job_id": job_id, "message": "動画生成を開始しました"})


@app.route("/api/video-status/<job_id>")
def video_status(job_id: str):
    """動画生成ジョブのステータスを取得"""
    job = VIDEO_JOBS.get(job_id)
    if not job:
        return jsonify({"error": "ジョブが見つかりません"}), 404
    return jsonify({
        "status": job["status"],
        "progress": job["progress"],
        "photo_count": job.get("photo_count"),
        "error": job.get("error"),
        "ready": job["status"] == "done"
    })


@app.route("/api/video-download/<job_id>")
def video_download(job_id: str):
    """生成した動画をダウンロード"""
    job = VIDEO_JOBS.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "動画がまだ準備できていません"}), 404

    video_path = Path(job["video_path"])
    if not video_path.exists():
        return jsonify({"error": "動画ファイルが見つかりません"}), 404

    return send_file(
        str(video_path),
        as_attachment=True,
        download_name="gbp_slideshow.mp4",
        mimetype="video/mp4"
    )


def send_video_email(to_email: str, business_name: str, video_path: Path) -> bool:
    """お客様へ動画をメールで送信"""
    import smtplib, ssl
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders

    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_FROM
        msg['To'] = to_email
        msg['Subject'] = f"【{business_name}】GBPスライドショー動画のお届け"
        body = f"""{business_name} 様

GBPスライドショー動画を作成しましたのでお届けします。

添付のMP4ファイルをGoogleビジネスプロフィールの
「写真」→「動画」からアップロードしてください。

【アップロード手順】
1. business.google.com を開く
2. 「写真を追加」→「動画」を選択
3. 添付ファイルをアップロード

動画のアップロードにより、GoogleマップのSEO評価が向上します。
ご不明な点はお気軽にご連絡ください。

---
株式会社ZETTAI / 清水 望
nozomu.shimizu@zettai.co.jp""".strip()

        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        with open(video_path, 'rb') as f:
            part = MIMEBase('video', 'mp4')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="gbp_slideshow.mp4"')
            msg.attach(part)

        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_email, msg.as_bytes())

        app.logger.info(f"メール送信成功: {to_email}")
        return True
    except Exception as e:
        app.logger.error(f"send_video_email error: {e}")
        return False


@app.route("/api/send-video", methods=["POST"])
@limiter.limit("5 per minute;20 per day")
def send_video():
    """生成した動画をお客様へメール送信"""
    data = request.get_json()
    job_id = data.get("job_id", "")
    to_email = data.get("email", "").strip()
    business_name = data.get("business_name", "お客様").strip()

    if not job_id or not to_email:
        return jsonify({"error": "ジョブIDとメールアドレスが必要です"}), 400
    if "@" not in to_email or "." not in to_email.split("@")[-1]:
        return jsonify({"error": "正しいメールアドレスを入力してください"}), 400

    job = VIDEO_JOBS.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "動画がまだ準備できていません"}), 404

    video_path = Path(job["video_path"])
    if not video_path.exists():
        return jsonify({"error": "動画ファイルが見つかりません"}), 404

    if send_video_email(to_email, business_name, video_path):
        return jsonify({"message": f"{to_email} へ送信しました ✅"})
    return jsonify({"error": "メール送信に失敗しました"}), 500


@app.route("/api/send-report", methods=["POST"])
@limiter.limit("5 per minute;20 per day")
def send_report():
    """分析レポートをHTMLメールで送信"""
    data = request.get_json()
    to_email = data.get("email", "").strip()
    business_name = data.get("business_name", "").strip() or "お客様"
    report_html = data.get("report_html", "").strip()
    report_type = data.get("report_type", "診断レポート")

    if not to_email or not report_html:
        return jsonify({"error": "メールアドレスとレポート内容が必要です"}), 400
    if "@" not in to_email or "." not in to_email.split("@")[-1]:
        return jsonify({"error": "正しいメールアドレスを入力してください"}), 400

    try:
        import smtplib, ssl
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = f"【{business_name}】{report_type}のお届け"

        text_body = f"{business_name} 様\n\n{report_type}をお届けします。\n\n---\n株式会社ZETTAI / 清水 望\nnozomu.shimizu@zettai.co.jp"
        html_body = f"""<html><body style="font-family:sans-serif;max-width:700px;margin:0 auto;padding:20px">
<p>{business_name} 様</p><p>{report_type}をお届けします。</p><hr>
{report_html}
<hr><p>株式会社ZETTAI / 清水 望<br><a href="mailto:nozomu.shimizu@zettai.co.jp">nozomu.shimizu@zettai.co.jp</a></p>
</body></html>"""

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as server:
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_email, msg.as_bytes())

        app.logger.info(f"send_report OK: {to_email}")
        return jsonify({"message": f"{to_email} へ送信しました ✅"})
    except Exception as e:
        app.logger.error(f"send_report error: {e}")
        return jsonify({"error": "メール送信に失敗しました"}), 500


@app.route("/admin/logs")
def admin_logs():
    token = request.args.get("token", "")
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    # Web診断ログ
    web_rows = conn.execute(
        "SELECT id, url, score, grade, ip, created_at FROM analyses ORDER BY id DESC LIMIT 200"
    ).fetchall()
    # GBP診断ログ
    gbp_rows = conn.execute(
        "SELECT id, url, business_name, score, grade, ip, created_at FROM gbp_analyses ORDER BY id DESC LIMIT 200"
    ).fetchall()
    conn.close()
    web_total = len(web_rows)
    web_avg = round(sum(r[2] for r in web_rows if r[2]) / web_total, 1) if web_total else 0
    gbp_total = len(gbp_rows)
    gbp_avg = round(sum(r[3] for r in gbp_rows if r[3]) / gbp_total, 1) if gbp_total else 0
    html = f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<title>AI検索GBP改善君 管理ログ</title>
<style>
body{{font-family:'Noto Sans JP',sans-serif;background:#F8F9FA;color:#202124;padding:2rem}}
h1{{font-size:1.5rem;font-weight:700;margin-bottom:1rem;color:#1A73E8}}
h2{{font-size:1.2rem;font-weight:700;margin:2rem 0 1rem;color:#202124}}
.stats{{display:flex;gap:1.5rem;margin-bottom:1.5rem;flex-wrap:wrap}}
.stat{{background:#fff;border:1px solid #E8EAED;border-radius:8px;padding:1rem 1.5rem}}
.stat-num{{font-size:2rem;font-weight:800;color:#1A73E8}}
.stat-num.green{{color:#34A853}}
.stat-label{{font-size:.85rem;color:#5F6368}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:2rem}}
th{{background:#F1F3F4;padding:.75rem 1rem;text-align:left;font-size:.85rem;color:#3C4043}}
td{{padding:.75rem 1rem;border-top:1px solid #F1F3F4;font-size:.9rem}}
.grade{{font-weight:700;padding:.2rem .5rem;border-radius:4px;font-size:.85rem}}
.A{{background:#E6F4EA;color:#34A853}}.B{{background:#FEF7E0;color:#FBBC04}}
.C,.D{{background:#FCE8E6;color:#EA4335}}.F{{background:#202124;color:#fff}}
</style></head><body>
<h1>AI検索GBP改善君 管理ログ</h1>
<div class="stats">
  <div class="stat"><div class="stat-num">{web_total}</div><div class="stat-label">Web診断数</div></div>
  <div class="stat"><div class="stat-num">{web_avg}</div><div class="stat-label">Web平均スコア</div></div>
  <div class="stat"><div class="stat-num green">{gbp_total}</div><div class="stat-label">GBP診断数</div></div>
  <div class="stat"><div class="stat-num green">{gbp_avg}</div><div class="stat-label">GBP平均スコア</div></div>
</div>

<h2>Webサイト診断ログ</h2>
<table>
<tr><th>#</th><th>URL</th><th>スコア</th><th>グレード</th><th>IP</th><th>日時</th></tr>
"""
    for r in web_rows:
        rid, url, score, grade, ip, created_at = r
        grade_cls = (grade or "F")[0]
        html += f'<tr><td>{rid}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{url}</td><td>{score or "-"}</td><td><span class="grade {grade_cls}">{grade or "-"}</span></td><td>{ip or "-"}</td><td>{created_at}</td></tr>'
    html += """</table>

<h2>GBP診断ログ</h2>
<table>
<tr><th>#</th><th>URL</th><th>ビジネス名</th><th>スコア</th><th>グレード</th><th>IP</th><th>日時</th></tr>
"""
    for r in gbp_rows:
        rid, url, bname, score, grade, ip, created_at = r
        grade_cls = (grade or "F")[0]
        html += f'<tr><td>{rid}</td><td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{url}</td><td>{bname or "-"}</td><td>{score or "-"}</td><td><span class="grade {grade_cls}">{grade or "-"}</span></td><td>{ip or "-"}</td><td>{created_at}</td></tr>'
    html += "</table></body></html>"
    return html


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "リクエストが多すぎます。しばらく待ってから再度お試しください。"}), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
