import json
import re
import sqlite3
import os
import time
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()
from urllib.parse import urlparse, urljoin, unquote

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


def validate_gbp_url(url):
    """GoogleマップURLのバリデーション"""
    parsed = urlparse(url)
    valid_hosts = [
        "maps.google.com", "www.google.com", "google.com",
        "maps.google.co.jp", "www.google.co.jp", "google.co.jp",
        "g.page", "goo.gl",
    ]
    host = parsed.netloc.lower()
    if any(host == h or host.endswith("." + h) for h in valid_hosts):
        # google.com系はpathに/mapsが含まれるか、cidパラメータがあるか確認
        if "google" in host:
            if "/maps" in parsed.path or "cid=" in (parsed.query or "") or "place" in parsed.path:
                return True
        else:
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
        app.logger.error(f"analyze error: {e}")  # サーバーログのみ
        return jsonify({"error": "分析中にエラーが発生しました。しばらくしてから再度お試しください"}), 500


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

    # URLの正規化
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # GoogleマップURLバリデーション
    if not validate_gbp_url(url):
        return jsonify({"error": "有効なGoogleマップURLを入力してください（maps.google.com, google.com/maps, g.page等）"}), 400

    try:
        # 1. URLからビジネス名抽出
        business_name = extract_business_name_from_url(url)

        # 2. ページHTML取得（限定的）
        html_snippet = fetch_gmaps_page(url)

        # 3. HTMLからメタ情報等を抽出
        if html_snippet:
            soup = BeautifulSoup(html_snippet, "html.parser")
            # titleタグからビジネス名を補完
            if not business_name and soup.title and soup.title.string:
                title_text = soup.title.string.strip()
                # "ビジネス名 - Google マップ" パターン
                m = re.match(r'^(.+?)\s*[-–]\s*Google', title_text)
                if m:
                    business_name = m.group(1).strip()

        # 4. Geminiで分析
        result = analyze_gbp_with_gemini(url, business_name, html_snippet)
        result["analyzed_url"] = url

        # ビジネス名をレスポンスに反映
        if not result.get("business_name") and business_name:
            result["business_name"] = business_name

        # ログ記録
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        log_gbp_analysis(
            url,
            result.get("business_name", business_name or "不明"),
            result.get("overall_score"),
            result.get("grade"),
            ip
        )

        return jsonify(result)

    except json.JSONDecodeError:
        return jsonify({"error": "AI分析結果の解析に失敗しました。もう一度お試しください"}), 500
    except Exception as e:
        app.logger.error(f"analyze-gbp error: {e}")  # サーバーログのみ
        return jsonify({"error": "分析中にエラーが発生しました。しばらくしてから再度お試しください"}), 500


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
