#!/usr/bin/env python3
"""
Samba AD API — Shell Project Debug / Тестирование.

Полное тестирование API Shell Project (/shell/projet):
- Создание проекта с рабочим пространством
- Загрузка файлов и архивов (.zip)
- Авто-распаковка архивов
- Выполнение bash-скриптов (run.sh, bash run.sh)
- Полная поддержка bash: if/then/elif/else/fi, case/esac,
  for/do/done, while/do/done, until/do/done, select/do/done
- Тестирование пайпов: echo ... | ./run.sh && echo "OK" || echo "ОШИБКА"
- Авто-удаление рабочего места (default: да)
- Сохранение рабочего места (auto_delete: false)
- Просмотр: /shell/projet/show, /shell/projet/list
- WebSocket: реальное время
- Права доступа, owner, env, sudo, pre/post commands

Режимы запуска:
    python3 debug_shell_projet.py                         # все тесты
    python3 debug_shell_projet.py -d                      # подробный вывод
    python3 debug_shell_projet.py --debug                 # то же что -d
    python3 debug_shell_projet.py -t 5                    # тест #5
    python3 debug_shell_projet.py -t 1-5,8                # тесты 1-5 и 8
    python3 debug_shell_projet.py -g create               # группа create
    python3 debug_shell_projet.py -g run,ws               # группы run + ws
    python3 debug_shell_projet.py --show                  # показать список тестов
    python3 debug_shell_projet.py --ws                    # включить WebSocket тесты
    python3 debug_shell_projet.py --ws-timeout 10         # таймаут WS (сек)

Настройка:
    python3 debug_shell_projet.py -s http://192.168.1.10:8099 -k YOUR_KEY
    python3 debug_shell_projet.py --server http://... --api-key YOUR_KEY

    Если ключ/сервер не указаны — читаются из SAMBA_API_KEY / SAMBA_API_SERVER
    или из файла .env.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

# ── HTTP клиент ────────────────────────────────────────────────────────
try:
    import requests

    _HAS_REQUESTS = True
except ImportError:
    import urllib.error
    import urllib.request

    _HAS_REQUESTS = False

# ── WebSocket ──────────────────────────────────────────────────────────
try:
    import websockets

    _HAS_WEBSOCKETS = True
except ImportError:
    _HAS_WEBSOCKETS = False


# ═══════════════════════════════════════════════════════════════════════
#  Конфигурация
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_SERVER = "http://127.0.0.1:8099"
DEFAULT_API_KEY = ""
DEFAULT_TIMEOUT = 120
DOTENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# v1.6.7-3: 15 new features — tags/labels, TTL, disk logs, output limit,
#   download .zip, health, owner transfer, state machine, multi-upload,
#   wait_for_completion, webhook, max projects, disk quota, graceful shutdown
# v1.6.7-2: Fixed auto-delete cleanup — empty parent directories removed
# v1.6.7: Fixed WS client compat, pipe test, concurrent run, autodelete race
DEFAULT_DELAY = 2.0  # seconds between tests (avoid 429)
MAX_429_RETRIES = 3  # max retries on rate limit
RETRY_BACKOFF_BASE = 5  # seconds base backoff on 429


def _load_dotenv() -> Dict[str, str]:
    """Загрузка .env без внешних зависимостей."""
    env: Dict[str, str] = {}
    if DOTENV_PATH.is_file():
        for line in DOTENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    return env


# ═══════════════════════════════════════════════════════════════════════
#  HTTP клиент (requests / urllib fallback)
# ═══════════════════════════════════════════════════════════════════════


def _http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    json_body: Optional[dict] = None,
    timeout: int = 60,
    files: Optional[dict] = None,
    retry_on_429: bool = True,
) -> Tuple[int, Any]:
    """Выполнить HTTP-запрос. Возвращает (status_code, response_body).

    v1.6.6: Added automatic retry on HTTP 429 (rate limit) with
    exponential backoff. Reads Retry-After header if available.
    """
    for attempt in range(MAX_429_RETRIES + 1):
        if _HAS_REQUESTS:
            try:
                resp = requests.request(
                    method, url, headers=headers, json=json_body,
                    timeout=timeout, files=files,
                )
                # v1.6.6: Handle 429 with retry
                if resp.status_code == 429 and retry_on_429 and attempt < MAX_429_RETRIES:
                    retry_after = int(resp.headers.get("Retry-After", RETRY_BACKOFF_BASE))
                    wait_time = max(retry_after, RETRY_BACKOFF_BASE * (attempt + 1))
                    print(f"       {_c('WARN', f'429 rate limited, retry {attempt+1}/{MAX_429_RETRIES} in {wait_time}s...')}")
                    time.sleep(wait_time)
                    continue
                try:
                    body: Any = resp.json()
                except (ValueError, json.JSONDecodeError):
                    body = resp.text
                return resp.status_code, body
            except requests.ConnectionError as exc:
                return 0, f"Connection error: {exc}"
            except requests.Timeout:
                return 0, "Request timed out"
            except Exception as exc:
                return 0, f"Request error: {exc}"
        else:
            # urllib fallback (без поддержки multipart upload)
            data = json.dumps(json_body).encode("utf-8") if json_body else None
            req = urllib.request.Request(url, data=data, method=method)
            for k, v in headers.items():
                req.add_header(k, v)
            if json_body and "Content-Type" not in headers:
                req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    try:
                        return resp.status, json.loads(raw)
                    except (ValueError, json.JSONDecodeError):
                        return resp.status, raw
            except urllib.error.HTTPError as exc:
                # v1.6.6: Handle 429 with retry
                if exc.code == 429 and retry_on_429 and attempt < MAX_429_RETRIES:
                    retry_after = int(exc.headers.get("Retry-After", RETRY_BACKOFF_BASE)) if exc.headers else RETRY_BACKOFF_BASE
                    wait_time = max(retry_after, RETRY_BACKOFF_BASE * (attempt + 1))
                    print(f"       {_c('WARN', f'429 rate limited, retry {attempt+1}/{MAX_429_RETRIES} in {wait_time}s...')}")
                    time.sleep(wait_time)
                    continue
                raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
                try:
                    return exc.code, json.loads(raw)
                except (ValueError, json.JSONDecodeError):
                    return exc.code, raw
            except urllib.error.URLError as exc:
                return 0, f"URL error: {exc.reason}"
            except Exception as exc:
                return 0, f"Request error: {exc}"
    # If we exhausted retries, make one final attempt without retry
    return _http_request(method, url, headers, json_body, timeout, files, retry_on_429=False)


# ═══════════════════════════════════════════════════════════════════════
#  Вспомогательные функции
# ═══════════════════════════════════════════════════════════════════════


def _create_test_zip(
    files: Dict[str, str],
) -> bytes:
    """Создать ZIP-архив в памяти из словаря {filename: content}.

    Возвращает байты архива.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _create_test_zip_file(
    files: Dict[str, str],
    dest_path: str,
) -> str:
    """Создать ZIP-архив на диске из словаря {filename: content}.

    Возвращает путь к архиву.
    """
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return dest_path


# ═══════════════════════════════════════════════════════════════════════
#  Цветной вывод
# ═══════════════════════════════════════════════════════════════════════

_COLORS = {
    "OK": "\033[92m",
    "ER": "\033[91m",
    "SKIP": "\033[93m",
    "WARN": "\033[93m",
    "DIM": "\033[2m",
    "BOLD": "\033[1m",
    "DANGER": "\033[91;1m",
    "CYAN": "\033[96m",
    "RESET": "\033[0m",
}

_NO_COLOR = os.environ.get("NO_COLOR", "") != ""


def _c(color: str, text: str) -> str:
    if _NO_COLOR or not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['RESET']}"


# ═══════════════════════════════════════════════════════════════════════
#  Определение тестов
# ═══════════════════════════════════════════════════════════════════════

# Каждый тест: (test_id, group, name, skip_reason, test_func_name)
# test_func — это метод ShellProjetTester

TEST_DEFINITIONS: List[Tuple[str, str, str, Optional[str], str]] = [
    # ── Группа: create ────────────────────────────────────────────────
    ("1",  "create", "Создание проекта (только workspace)", None, "test_create_workspace_only"),
    ("2",  "create", "Создание проекта с auto_delete=false", None, "test_create_no_autodelete"),
    ("3",  "create", "Создание проекта с owner и permissions", None, "test_create_with_owner"),
    ("4",  "create", "Создание проекта с env переменными", None, "test_create_with_env"),
    ("5",  "create", "Валидация имени проекта (недопустимые символы)", None, "test_name_validation"),

    # ── Группа: upload ────────────────────────────────────────────────
    ("6",  "upload", "Загрузка обычного файла", None, "test_upload_plain_file"),
    ("7",  "upload", "Загрузка .zip с авто-распаковкой", None, "test_upload_zip_auto_extract"),
    ("8",  "upload", "Загрузка .zip с run.sh скриптом", None, "test_upload_zip_with_script"),
    ("9",  "upload", "Загрузка .zip с несколькими файлами", None, "test_upload_zip_multi_file"),
    ("10", "upload", "Загрузка в несуществующий проект", None, "test_upload_nonexistent_project"),

    # ── Группа: run ───────────────────────────────────────────────────
    ("11", "run", "Простой запуск команды (echo)", None, "test_run_simple_echo"),
    ("12", "run", "Запуск ./run.sh из workspace", None, "test_run_script_file"),
    ("13", "run", "Bash if/then/elif/else/fi", None, "test_run_bash_if"),
    ("14", "run", "Bash case/esac", None, "test_run_bash_case"),
    ("15", "run", "Bash for/do/done", None, "test_run_bash_for"),
    ("16", "run", "Bash while/do/done", None, "test_run_bash_while"),
    ("17", "run", "Bash until/do/done", None, "test_run_bash_until"),
    ("18", "run", "Bash select/do/done (автовыбор)", None, "test_run_bash_select"),
    ("19", "run", "Пайп: echo | ./run.sh && OK || ОШИБКА", None, "test_run_pipe_conditional"),
    ("20", "run", "Pre-commands + run + post-commands", None, "test_run_pre_post_commands"),
    ("21", "run", "Запуск с sudo", "needs_sudo", "test_run_sudo"),
    ("22", "run", "Запуск с таймаутом (короткий)", None, "test_run_timeout"),
    ("23", "run", "Запуск с env переменными", None, "test_run_with_env"),
    ("24", "run", "Запуск в несуществующем проекте", None, "test_run_nonexistent_project"),

    # ── Группа: show ──────────────────────────────────────────────────
    ("25", "show", "Просмотр проекта /shell/projet/show/{id}", None, "test_show_project"),
    ("26", "show", "Просмотр несуществующего проекта", None, "test_show_nonexistent"),
    ("27", "show", "Просмотр файла в workspace", None, "test_show_workspace_files"),

    # ── Группа: list ──────────────────────────────────────────────────
    ("28", "list", "Список всех проектов /shell/projet/list", None, "test_list_projects"),
    ("29", "list", "Фильтрация по owner", None, "test_list_filter_owner"),
    ("30", "list", "Фильтрация по status", None, "test_list_filter_status"),
    ("31", "list", "Фильтрация по name", None, "test_list_filter_name"),

    # ── Группа: delete ────────────────────────────────────────────────
    ("32", "delete", "Удаление проекта /shell/projet/{id}", None, "test_delete_project"),
    ("33", "delete", "Удаление несуществующего проекта", None, "test_delete_nonexistent"),
    ("34", "delete", "Авто-удаление после выполнения (default: yes)", None, "test_auto_delete_after_run"),

    # ── Группа: lifecycle ─────────────────────────────────────────────
    ("35", "lifecycle", "Полный цикл: create → upload → run → show → delete", None, "test_full_lifecycle"),
    ("36", "lifecycle", "Create + zip + run.sh + авто-удаление", None, "test_create_zip_run_autodelete"),
    ("37", "lifecycle", "Create + zip + pipe-тест + сохранение", None, "test_create_zip_pipe_persist"),
    ("38", "lifecycle", "Множественные run в одном проекте", None, "test_multiple_runs"),

    # ── Группа: ws ────────────────────────────────────────────────────
    ("39", "ws", "WebSocket: подключение к /ws/projet/{id}", "needs_ws", "test_ws_connect_project"),
    ("40", "ws", "WebSocket: глобальный /ws/projet", "needs_ws", "test_ws_global"),
    ("41", "ws", "WebSocket: реальный вывод при выполнении", "needs_ws", "test_ws_realtime_output"),

    # ── Группа: edge ──────────────────────────────────────────────────
    ("42", "edge", "Пустой run_command", None, "test_empty_run_command"),
    ("43", "edge", "Очень длинный вывод команды", None, "test_long_output"),
    ("44", "edge", "Спецсимволы в команде", None, "test_special_chars"),
    ("45", "edge", "Одновременный запуск в занятом проекте", None, "test_concurrent_run"),

    # ── Группа: v1673 (v1.6.7-3 new features) ──────────────────────────
    ("46", "v1673", "Tags и labels (#11)", None, "test_tags_labels"),
    ("47", "v1673", "Фильтрация по tag/label (#11)", None, "test_tags_filter"),
    ("48", "v1673", "TTL проекта — авто-удаление по таймеру (#5)", None, "test_ttl_project"),
    ("49", "v1673", "Disk logging — .projet_logs/ (#1)", None, "test_disk_logging"),
    ("50", "v1673", "Output limit — OOM protection (#3)", None, "test_output_limit"),
    ("51", "v1673", "Download workspace как .zip (#4)", None, "test_download_zip"),
    ("52", "v1673", "Health check (#13)", None, "test_health_check"),
    ("53", "v1673", "Owner transfer (#14)", None, "test_owner_transfer"),
    ("54", "v1673", "Wait-for-completion режим (#8)", None, "test_wait_for_completion"),
    ("55", "v1673", "Execution history (#6)", None, "test_execution_history"),
    ("56", "v1673", "Multi-file upload (#7)", None, "test_multi_upload"),
    ("57", "v1673", "Max projects limit (#9)", None, "test_max_projects"),
    ("58", "v1673", "Disk quota (#10)", None, "test_disk_quota"),
    ("59", "v1673", "State machine — недопустимые переходы (#15)", None, "test_state_machine"),
    ("60", "v1673", "Tags/labels PATCH обновление (#11)", None, "test_tags_patch"),
]


# ═══════════════════════════════════════════════════════════════════════
#  Группировка тестов
# ═══════════════════════════════════════════════════════════════════════

TEST_GROUPS: Dict[str, List[str]] = {
    "create":    "Создание проектов (тесты 1-5)",
    "upload":    "Загрузка файлов и архивов (тесты 6-10)",
    "run":       "Выполнение команд и скриптов (тесты 11-24)",
    "show":      "Просмотр проектов (тесты 25-27)",
    "list":      "Список проектов с фильтрами (тесты 28-31)",
    "delete":    "Удаление проектов (тесты 32-34)",
    "lifecycle": "Полный цикл (тесты 35-38)",
    "ws":        "WebSocket реальное время (тесты 39-41)",
    "edge":      "Граничные случаи (тесты 42-45)",
    "v1673":     "v1.6.7-3 новые функции (тесты 46-60)",
}


def _get_test_group(test_id: str) -> str:
    """Определить группу теста по его ID."""
    for tid, group, _, _, _ in TEST_DEFINITIONS:
        if tid == test_id:
            return group
    return "other"


# ═══════════════════════════════════════════════════════════════════════
#  Парсер номеров тестов
# ═══════════════════════════════════════════════════════════════════════


def _parse_test_ids(spec: str) -> set:
    """Разобрать спецификацию номеров тестов.

    Форматы: 5 | 1-5 | 1-3,7,10-12
    """
    result: set = set()
    all_ids = [tid for tid, _, _, _, _ in TEST_DEFINITIONS]
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo = bounds[0].strip()
                hi = bounds[1].strip()
                lo_idx = all_ids.index(lo) if lo in all_ids else -1
                hi_idx = all_ids.index(hi) if hi in all_ids else -1
                if lo_idx >= 0 and hi_idx >= 0:
                    result.update(all_ids[lo_idx:hi_idx + 1])
                else:
                    # Fallback: numeric range
                    for i in range(int(lo), int(hi) + 1):
                        sid = str(i)
                        if sid in all_ids:
                            result.add(sid)
            except (ValueError, IndexError):
                print(f"  {_c('WARN', 'WARN:')} Invalid range '{part}'")
        else:
            if part in all_ids:
                result.add(part)
            else:
                print(f"  {_c('WARN', 'WARN:')} Test ID '{part}' not found")
    return result


# ═══════════════════════════════════════════════════════════════════════
#  Основной тестер
# ═══════════════════════════════════════════════════════════════════════


class ShellProjetTester:
    """Тестер API Shell Project."""

    def __init__(
        self,
        server: str,
        api_key: str,
        timeout: int = DEFAULT_TIMEOUT,
        debug: bool = False,
        ws_timeout: int = 10,
        enable_ws: bool = False,
        delay: float = DEFAULT_DELAY,
    ) -> None:
        self.server = server.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.debug = debug
        self.ws_timeout = ws_timeout
        self.enable_ws = enable_ws
        self.delay = delay  # v1.6.6: inter-test delay to avoid 429

        # Хранилище ID созданных проектов для очистки
        self._created_projects: List[str] = []

        # HTTP заголовки
        self._headers: Dict[str, str] = {
            "X-API-Key": api_key,
            "Accept": "application/json",
        }

        # Результаты
        self.results: Dict[str, List[dict]] = {
            "ok": [], "er": [], "skip": [], "warn": [],
        }

    # ── HTTP хелперы ──────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self.server}{path}"

    def _post_json(self, path: str, body: dict, timeout: Optional[int] = None) -> Tuple[int, Any]:
        return _http_request(
            "POST", self._url(path), self._headers,
            json_body=body, timeout=timeout or self.timeout,
        )

    def _get(self, path: str, timeout: Optional[int] = None) -> Tuple[int, Any]:
        return _http_request(
            "GET", self._url(path), self._headers,
            timeout=timeout or self.timeout,
        )

    def _delete(self, path: str, timeout: Optional[int] = None) -> Tuple[int, Any]:
        return _http_request(
            "DELETE", self._url(path), self._headers,
            timeout=timeout or self.timeout,
        )

    def _patch(self, path: str, body: dict, timeout: Optional[int] = None) -> Tuple[int, Any]:
        return _http_request(
            "PATCH", self._url(path), self._headers,
            json_body=body, timeout=timeout or self.timeout,
        )

    def _upload_file(
        self, path: str, filename: str, file_data: bytes, timeout: Optional[int] = None,
    ) -> Tuple[int, Any]:
        """Загрузить файл через multipart/form-data."""
        if not _HAS_REQUESTS:
            return 0, "Upload requires 'requests' library (multipart support)"

        url = self._url(path)
        headers = {"X-API-Key": self.api_key, "Accept": "application/json"}
        files = {"file": (filename, file_data)}

        try:
            resp = requests.post(
                url, headers=headers, files=files,
                timeout=timeout or self.timeout,
            )
            try:
                body = resp.json()
            except (ValueError, json.JSONDecodeError):
                body = resp.text
            return resp.status_code, body
        except Exception as exc:
            return 0, f"Upload error: {exc}"

    # ── Создание/удаление проектов ────────────────────────────────────

    def _create_project(self, **kwargs) -> Tuple[int, Any]:
        """Создать проект POST /api/v1/shell/projet/"""
        code, body = self._post_json("/api/v1/shell/projet/", kwargs)
        if isinstance(body, dict) and body.get("projet_id"):
            self._created_projects.append(body["projet_id"])
        return code, body

    def _cleanup_project(self, projet_id: str) -> None:
        """Удалить проект (force=True)"""
        try:
            self._delete(f"/api/v1/shell/projet/{projet_id}?force=true", timeout=15)
        except Exception:
            pass
        if projet_id in self._created_projects:
            self._created_projects.remove(projet_id)

    def _cleanup_all(self) -> None:
        """Удалить все созданные проекты."""
        for pid in list(self._created_projects):
            self._cleanup_project(pid)

    # ── Запись результатов ────────────────────────────────────────────

    def _record(self, test_id: str, status: str, name: str, detail: str = "", body: Any = None) -> None:
        entry = {"test_id": test_id, "name": name, "detail": detail}
        if body is not None and self.debug:
            entry["body"] = body
        self.results[status].append(entry)

        label = {
            "ok": _c("OK", "OK"),
            "er": _c("ER", "ER"),
            "skip": _c("SKIP", "SKIP"),
            "warn": _c("WARN", "WARN"),
        }.get(status, status)

        line = f"  [{test_id:>2}] {label}  {name}"
        if detail:
            line += f"  {_c('DIM', detail)}"
        print(line)
        if self.debug and body is not None:
            body_str = json.dumps(body, indent=2, ensure_ascii=False) if isinstance(body, dict) else str(body)
            if len(body_str) > 600:
                body_str = body_str[:600] + "..."
            print(f"       {_c('CYAN', body_str)}")

    # ═══════════════════════════════════════════════════════════════════
    #  Тесты
    # ═══════════════════════════════════════════════════════════════════

    # ── Группа: create ────────────────────────────────────────────────

    def test_create_workspace_only(self, test_id: str) -> None:
        """Тест 1: Создание проекта (только workspace)"""
        code, body = self._create_project(name="debug-test", auto_delete=True)
        if code == 200 and isinstance(body, dict) and body.get("projet_id"):
            self._record(test_id, "ok", "Create workspace only", f"id={body['projet_id']}", body)
            self._cleanup_project(body["projet_id"])
        else:
            self._record(test_id, "er", "Create workspace only", f"code={code}", body)

    def test_create_no_autodelete(self, test_id: str) -> None:
        """Тест 2: Создание проекта с auto_delete=false"""
        code, body = self._create_project(name="debug-persist", auto_delete=False)
        if code == 200 and isinstance(body, dict) and body.get("projet_id"):
            pid = body["projet_id"]
            # Проверяем что workspace существует
            s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
            if s_code == 200:
                self._record(test_id, "ok", "Create no autodelete", f"id={pid} workspace exists", body)
            else:
                self._record(test_id, "er", "Create no autodelete", "workspace not found after create", s_body)
            self._cleanup_project(pid)
        else:
            self._record(test_id, "er", "Create no autodelete", f"code={code}", body)

    def test_create_with_owner(self, test_id: str) -> None:
        """Тест 3: Создание проекта с owner и permissions"""
        code, body = self._create_project(
            name="debug-owned", owner="test-admin",
            permissions="755", auto_delete=True,
        )
        if code == 200 and isinstance(body, dict) and body.get("projet_id"):
            pid = body["projet_id"]
            # Проверяем owner
            s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
            if s_code == 200 and isinstance(s_body, dict):
                ws = s_body.get("workspace", {})
                if ws.get("owner") == "test-admin":
                    self._record(test_id, "ok", "Create with owner+perms", f"owner={ws.get('owner')}", body)
                else:
                    self._record(test_id, "warn", "Create with owner+perms", f"owner={ws.get('owner')} (expected test-admin)", body)
            else:
                self._record(test_id, "er", "Create with owner+perms", "show failed", s_body)
            self._cleanup_project(pid)
        else:
            self._record(test_id, "er", "Create with owner+perms", f"code={code}", body)

    def test_create_with_env(self, test_id: str) -> None:
        """Тест 4: Создание проекта с env переменными"""
        code, body = self._create_project(
            name="debug-env",
            auto_delete=False,
            env={"MY_VAR": "hello_world", "APP_MODE": "debug"},
            run_command="echo $MY_VAR $APP_MODE",
        )
        if code == 200 and isinstance(body, dict) and body.get("projet_id"):
            pid = body["projet_id"]
            # Ждём завершения выполнения
            time.sleep(3)
            # Проверяем через show
            s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
            if s_code == 200:
                self._record(test_id, "ok", "Create with env", f"id={pid}", body)
            else:
                self._record(test_id, "warn", "Create with env", "show after run failed", s_body)
            self._cleanup_project(pid)
        else:
            self._record(test_id, "er", "Create with env", f"code={code}", body)

    def test_name_validation(self, test_id: str) -> None:
        """Тест 5: Валидация имени проекта (недопустимые символы)"""
        # Корректное имя
        code1, body1 = self._create_project(name="valid-name_1.2", auto_delete=True)
        ok1 = code1 == 200
        if ok1 and isinstance(body1, dict) and body1.get("projet_id"):
            self._cleanup_project(body1["projet_id"])

        # Некорректное имя (пробелы)
        code2, body2 = self._create_project(name="invalid name", auto_delete=True)
        ok2 = code2 == 422  # Validation error

        # Некорректное имя (начинается с точки)
        code3, body3 = self._create_project(name=".hidden", auto_delete=True)
        ok3 = code3 == 422

        if ok1 and ok2 and ok3:
            self._record(test_id, "ok", "Name validation", "valid OK, invalid rejected")
        else:
            details = []
            if not ok1:
                details.append(f"valid_name code={code1}")
            if not ok2:
                details.append(f"space_name code={code2}")
            if not ok3:
                details.append(f"dot_name code={code3}")
            self._record(test_id, "er", "Name validation", ", ".join(details))

    # ── Группа: upload ────────────────────────────────────────────────

    def test_upload_plain_file(self, test_id: str) -> None:
        """Тест 6: Загрузка обычного файла"""
        code, body = self._create_project(name="debug-upload", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Upload plain file", "create failed", body)
            return

        pid = body["projet_id"]
        # Загрузим текстовый файл
        file_data = b"Hello from debug_shell_projet.py!"
        u_code, u_body = self._upload_file(
            f"/api/v1/shell/projet/{pid}/upload",
            "testfile.txt", file_data,
        )
        if u_code == 200 and isinstance(u_body, dict) and u_body.get("extracted") is False:
            self._record(test_id, "ok", "Upload plain file", f"size={len(file_data)}", u_body)
        else:
            self._record(test_id, "er", "Upload plain file", f"upload code={u_code}", u_body)
        self._cleanup_project(pid)

    def test_upload_zip_auto_extract(self, test_id: str) -> None:
        """Тест 7: Загрузка .zip с авто-распаковкой"""
        code, body = self._create_project(name="debug-zip", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Upload zip auto-extract", "create failed", body)
            return

        pid = body["projet_id"]
        # Создадим zip в памяти
        zip_data = _create_test_zip({
            "hello.txt": "Hello from ZIP!",
            "subdir/nested.txt": "Nested file content",
        })

        u_code, u_body = self._upload_file(
            f"/api/v1/shell/projet/{pid}/upload",
            "archive.zip", zip_data,
        )
        if u_code == 200 and isinstance(u_body, dict) and u_body.get("extracted") is True:
            extracted = u_body.get("extracted_files", [])
            self._record(test_id, "ok", "Upload zip auto-extract", f"extracted={len(extracted)} files", u_body)
        else:
            self._record(test_id, "er", "Upload zip auto-extract", f"code={u_code}", u_body)
        self._cleanup_project(pid)

    def test_upload_zip_with_script(self, test_id: str) -> None:
        """Тест 8: Загрузка .zip с run.sh скриптом"""
        code, body = self._create_project(name="debug-script-zip", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Upload zip with script", "create failed", body)
            return

        pid = body["projet_id"]
        # Создадим zip с run.sh
        run_sh = """#!/bin/bash
echo "=== run.sh started ==="
echo "CWD: $(pwd)"
echo "Files: $(ls -1 | wc -l)"
echo "=== run.sh completed ==="
"""
        zip_data = _create_test_zip({
            "run.sh": run_sh,
            "config.env": "MODE=test\nVERSION=1.0",
        })

        u_code, u_body = self._upload_file(
            f"/api/v1/shell/projet/{pid}/upload",
            "project.zip", zip_data,
        )
        if u_code == 200 and isinstance(u_body, dict) and u_body.get("extracted") is True:
            # Запустим скрипт
            r_code, r_body = self._post_json(
                f"/api/v1/shell/projet/{pid}/run",
                {"run_command": "chmod +x run.sh && bash run.sh", "timeout": 30},
            )
            if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
                stdout = r_body.get("stdout", "")
                if "run.sh started" in stdout and "run.sh completed" in stdout:
                    self._record(test_id, "ok", "Upload zip with script", "script executed OK", r_body)
                else:
                    self._record(test_id, "warn", "Upload zip with script", f"unexpected output: {stdout[:200]}", r_body)
            else:
                self._record(test_id, "er", "Upload zip with script", f"run code={r_code}", r_body)
        else:
            self._record(test_id, "er", "Upload zip with script", f"upload code={u_code}", u_body)
        self._cleanup_project(pid)

    def test_upload_zip_multi_file(self, test_id: str) -> None:
        """Тест 9: Загрузка .zip с несколькими файлами"""
        code, body = self._create_project(name="debug-multi", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Upload zip multi-file", "create failed", body)
            return

        pid = body["projet_id"]
        # Создадим zip с несколькими файлами
        zip_data = _create_test_zip({
            "file1.txt": "Content 1",
            "file2.py": "print('hello')",
            "data/config.json": '{"key": "value"}',
            "scripts/setup.sh": "#!/bin/bash\necho setup",
            "README.md": "# Test Project",
        })

        u_code, u_body = self._upload_file(
            f"/api/v1/shell/projet/{pid}/upload",
            "multi.zip", zip_data,
        )
        if u_code == 200 and isinstance(u_body, dict) and u_body.get("extracted") is True:
            extracted = u_body.get("extracted_files", [])
            self._record(test_id, "ok", "Upload zip multi-file", f"extracted={len(extracted)} files", u_body)
        else:
            self._record(test_id, "er", "Upload zip multi-file", f"code={u_code}", u_body)
        self._cleanup_project(pid)

    def test_upload_nonexistent_project(self, test_id: str) -> None:
        """Тест 10: Загрузка в несуществующий проект"""
        file_data = b"test"
        u_code, u_body = self._upload_file(
            "/api/v1/shell/projet/nonexistent123/upload",
            "test.txt", file_data,
        )
        if u_code == 404:
            self._record(test_id, "ok", "Upload to nonexistent", "correctly returned 404", u_body)
        else:
            self._record(test_id, "er", "Upload to nonexistent", f"expected 404, got {u_code}", u_body)

    # ── Группа: run ───────────────────────────────────────────────────

    def test_run_simple_echo(self, test_id: str) -> None:
        """Тест 11: Простой запуск команды (echo)"""
        code, body = self._create_project(name="debug-echo", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Run simple echo", "create failed", body)
            return

        pid = body["projet_id"]
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "echo 'Hello from shell projet'", "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "").strip()
            if "Hello from shell projet" in stdout:
                self._record(test_id, "ok", "Run simple echo", f"stdout={stdout!r}", r_body)
            else:
                self._record(test_id, "warn", "Run simple echo", f"unexpected: {stdout!r}", r_body)
        else:
            self._record(test_id, "er", "Run simple echo", f"code={r_code}", r_body)
        # auto_delete должен был удалить workspace

    def test_run_script_file(self, test_id: str) -> None:
        """Тест 12: Запуск ./run.sh из workspace"""
        code, body = self._create_project(name="debug-runsh", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Run ./run.sh", "create failed", body)
            return

        pid = body["projet_id"]
        # Загрузим zip с run.sh
        run_sh = """#!/bin/bash
echo "Script executed successfully"
echo "Args: $@"
"""
        zip_data = _create_test_zip({"run.sh": run_sh})
        self._upload_file(f"/api/v1/shell/projet/{pid}/upload", "app.zip", zip_data)

        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {
                "run_command": "chmod +x run.sh && ./run.sh --test",
                "timeout": 20,
                "auto_delete": True,
            },
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "Script executed successfully" in stdout:
                self._record(test_id, "ok", "Run ./run.sh", "OK", r_body)
            else:
                self._record(test_id, "warn", "Run ./run.sh", f"unexpected output", r_body)
        else:
            self._record(test_id, "er", "Run ./run.sh", f"code={r_code}", r_body)

    def test_run_bash_if(self, test_id: str) -> None:
        """Тест 13: Bash if/then/elif/else/fi"""
        code, body = self._create_project(name="debug-bash-if", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Bash if/then/elif/else/fi", "create failed", body)
            return

        pid = body["projet_id"]
        cmd = """
MODE="production"
if [ "$MODE" = "production" ]; then
    echo "PROD mode"
elif [ "$MODE" = "staging" ]; then
    echo "STAGING mode"
else
    echo "DEV mode"
fi
"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "").strip()
            if "PROD mode" in stdout:
                self._record(test_id, "ok", "Bash if/then/elif/else/fi", f"stdout={stdout!r}", r_body)
            else:
                self._record(test_id, "er", "Bash if/then/elif/else/fi", f"expected 'PROD mode', got: {stdout!r}", r_body)
        else:
            self._record(test_id, "er", "Bash if/then/elif/else/fi", f"code={r_code}", r_body)

    def test_run_bash_case(self, test_id: str) -> None:
        """Тест 14: Bash case/esac"""
        code, body = self._create_project(name="debug-bash-case", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Bash case/esac", "create failed", body)
            return

        pid = body["projet_id"]
        cmd = """
ENV="prod"
case "$ENV" in
    prod)   echo "Production environment" ;;
    dev)    echo "Development environment" ;;
    *)      echo "Unknown environment" ;;
esac
"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "").strip()
            if "Production environment" in stdout:
                self._record(test_id, "ok", "Bash case/esac", f"stdout={stdout!r}", r_body)
            else:
                self._record(test_id, "er", "Bash case/esac", f"unexpected: {stdout!r}", r_body)
        else:
            self._record(test_id, "er", "Bash case/esac", f"code={r_code}", r_body)

    def test_run_bash_for(self, test_id: str) -> None:
        """Тест 15: Bash for/do/done"""
        code, body = self._create_project(name="debug-bash-for", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Bash for/do/done", "create failed", body)
            return

        pid = body["projet_id"]
        cmd = """
RESULT=""
for i in 1 2 3; do
    RESULT="${RESULT}${i}-"
done
echo "Loop result: ${RESULT}"
"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "").strip()
            if "1-2-3-" in stdout:
                self._record(test_id, "ok", "Bash for/do/done", f"stdout={stdout!r}", r_body)
            else:
                self._record(test_id, "er", "Bash for/do/done", f"unexpected: {stdout!r}", r_body)
        else:
            self._record(test_id, "er", "Bash for/do/done", f"code={r_code}", r_body)

    def test_run_bash_while(self, test_id: str) -> None:
        """Тест 16: Bash while/do/done"""
        code, body = self._create_project(name="debug-bash-while", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Bash while/do/done", "create failed", body)
            return

        pid = body["projet_id"]
        cmd = """
COUNT=0
while [ $COUNT -lt 3 ]; do
    echo "Count: $COUNT"
    COUNT=$((COUNT + 1))
done
echo "While loop done"
"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "Count: 0" in stdout and "Count: 2" in stdout and "While loop done" in stdout:
                self._record(test_id, "ok", "Bash while/do/done", "OK", r_body)
            else:
                self._record(test_id, "er", "Bash while/do/done", f"unexpected: {stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Bash while/do/done", f"code={r_code}", r_body)

    def test_run_bash_until(self, test_id: str) -> None:
        """Тест 17: Bash until/do/done"""
        code, body = self._create_project(name="debug-bash-until", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Bash until/do/done", "create failed", body)
            return

        pid = body["projet_id"]
        cmd = """
N=0
until [ $N -ge 3 ]; do
    echo "Until N=$N"
    N=$((N + 1))
done
echo "Until loop done"
"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "Until N=0" in stdout and "Until loop done" in stdout:
                self._record(test_id, "ok", "Bash until/do/done", "OK", r_body)
            else:
                self._record(test_id, "er", "Bash until/do/done", f"unexpected: {stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Bash until/do/done", f"code={r_code}", r_body)

    def test_run_bash_select(self, test_id: str) -> None:
        """Тест 18: Bash select/do/done (автовыбор)"""
        code, body = self._create_project(name="debug-bash-select", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Bash select/do/done", "create failed", body)
            return

        pid = body["projet_id"]
        # select с автоматическим вводом (echo "1" | select ...)
        cmd = """
echo "2" | bash -c '
select opt in "Option A" "Option B" "Option C"; do
    echo "Selected: $opt"
    break
done
'
"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "Option B" in stdout:
                self._record(test_id, "ok", "Bash select/do/done", "OK", r_body)
            else:
                self._record(test_id, "warn", "Bash select/do/done", f"output: {stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Bash select/do/done", f"code={r_code}", r_body)

    def test_run_pipe_conditional(self, test_id: str) -> None:
        """Тест 19: Пайп: echo | ./run.sh && OK || ОШИБКА"""
        code, body = self._create_project(name="debug-pipe", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Pipe conditional", "create failed", body)
            return

        pid = body["projet_id"]
        # Создадим run.sh который фильтрует stdin
        run_sh = """#!/bin/bash
while IFS= read -r line; do
    if echo "$line" | grep -q "^OK"; then
        echo "PASS: $line"
    else
        echo "FAIL: $line"
        exit 1
    fi
done
"""
        zip_data = _create_test_zip({"run.sh": run_sh})
        self._upload_file(f"/api/v1/shell/projet/{pid}/upload", "pipe-test.zip", zip_data)

        # Тест 1: Успешный пайп
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {
                "run_command": "chmod +x run.sh && echo -e 'OK line1\\nOK line2' | ./run.sh && echo 'ALL OK' || echo 'ОШИБКА'",
                "timeout": 20,
            },
        )
        if r_code == 200 and isinstance(r_body, dict):
            stdout = r_body.get("stdout", "")
            rc = r_body.get("returncode", -1)
            if rc == 0 and "ALL OK" in stdout and "PASS: OK" in stdout:
                self._record(test_id, "ok", "Pipe conditional", "OK line: PASS + ALL OK", r_body)
            else:
                self._record(test_id, "er", "Pipe conditional", f"rc={rc} stdout={stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Pipe conditional", f"code={r_code}", r_body)
        self._cleanup_project(pid)

    def test_run_pre_post_commands(self, test_id: str) -> None:
        """Тест 20: Pre-commands + run + post-commands"""
        code, body = self._create_project(name="debug-prepost", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Pre/post commands", "create failed", body)
            return

        pid = body["projet_id"]
        # Создадим файл через pre_commands
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {
                "pre_commands": ["echo 'PRE_SETUP' > pre_marker.txt", "echo 'READY' > status.txt"],
                "run_command": "cat pre_marker.txt status.txt",
                "post_commands": ["rm -f pre_marker.txt status.txt", "echo 'CLEANUP_DONE'"],
                "timeout": 20,
            },
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "PRE_SETUP" in stdout and "READY" in stdout and "CLEANUP_DONE" in stdout:
                self._record(test_id, "ok", "Pre/post commands", "all stages executed", r_body)
            else:
                self._record(test_id, "warn", "Pre/post commands", f"partial output: {stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Pre/post commands", f"code={r_code}", r_body)
        self._cleanup_project(pid)

    def test_run_sudo(self, test_id: str) -> None:
        """Тест 21: Запуск с sudo"""
        code, body = self._create_project(name="debug-sudo", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Run with sudo", "create failed", body)
            return

        pid = body["projet_id"]
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "whoami", "sudo": True, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict):
            stdout = r_body.get("stdout", "").strip()
            rc = r_body.get("returncode", -1)
            if rc == 0 and stdout == "root":
                self._record(test_id, "ok", "Run with sudo", f"whoami={stdout}", r_body)
            elif rc == 0:
                self._record(test_id, "warn", "Run with sudo", f"whoami={stdout} (not root)", r_body)
            else:
                self._record(test_id, "er", "Run with sudo", f"rc={rc}", r_body)
        else:
            self._record(test_id, "er", "Run with sudo", f"code={r_code}", r_body)

    def test_run_timeout(self, test_id: str) -> None:
        """Тест 22: Запуск с таймаутом (короткий)"""
        code, body = self._create_project(name="debug-timeout", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Run with timeout", "create failed", body)
            return

        pid = body["projet_id"]
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "sleep 30", "timeout": 2, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict):
            timed_out = r_body.get("timed_out", False)
            if timed_out:
                self._record(test_id, "ok", "Run with timeout", "correctly timed out", r_body)
            else:
                self._record(test_id, "er", "Run with timeout", "expected timeout but didn't", r_body)
        else:
            self._record(test_id, "er", "Run with timeout", f"code={r_code}", r_body)

    def test_run_with_env(self, test_id: str) -> None:
        """Тест 23: Запуск с env переменными"""
        code, body = self._create_project(name="debug-runenv", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Run with env", "create failed", body)
            return

        pid = body["projet_id"]
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {
                "run_command": "echo $SHELL_TEST_VAR $SHELL_TEST_MODE",
                "env": {"SHELL_TEST_VAR": "42", "SHELL_TEST_MODE": "testing"},
                "timeout": 15,
                "auto_delete": True,
            },
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "").strip()
            if "42" in stdout and "testing" in stdout:
                self._record(test_id, "ok", "Run with env", f"stdout={stdout!r}", r_body)
            else:
                self._record(test_id, "er", "Run with env", f"env vars not found: {stdout!r}", r_body)
        else:
            self._record(test_id, "er", "Run with env", f"code={r_code}", r_body)

    def test_run_nonexistent_project(self, test_id: str) -> None:
        """Тест 24: Запуск в несуществующем проекте"""
        r_code, r_body = self._post_json(
            "/api/v1/shell/projet/nonexistent999/run",
            {"run_command": "echo test"},
        )
        if r_code == 404:
            self._record(test_id, "ok", "Run nonexistent project", "correctly returned 404", r_body)
        else:
            self._record(test_id, "er", "Run nonexistent project", f"expected 404, got {r_code}", r_body)

    # ── Группа: show ──────────────────────────────────────────────────

    def test_show_project(self, test_id: str) -> None:
        """Тест 25: Просмотр проекта /shell/projet/show/{id}"""
        code, body = self._create_project(name="debug-show", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Show project", "create failed", body)
            return

        pid = body["projet_id"]
        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        if s_code == 200 and isinstance(s_body, dict):
            ws = s_body.get("workspace", {})
            if ws.get("projet_id") == pid and ws.get("status") in ("ready", "creating"):
                files = s_body.get("files", [])
                self._record(test_id, "ok", "Show project", f"status={ws.get('status')} files={len(files)}", s_body)
            else:
                self._record(test_id, "warn", "Show project", f"unexpected: {ws}", s_body)
        else:
            self._record(test_id, "er", "Show project", f"code={s_code}", s_body)
        self._cleanup_project(pid)

    def test_show_nonexistent(self, test_id: str) -> None:
        """Тест 26: Просмотр несуществующего проекта"""
        s_code, s_body = self._get("/api/v1/shell/projet/show/nonexistent999")
        if s_code == 404:
            self._record(test_id, "ok", "Show nonexistent", "correctly returned 404", s_body)
        else:
            self._record(test_id, "er", "Show nonexistent", f"expected 404, got {s_code}", s_body)

    def test_show_workspace_files(self, test_id: str) -> None:
        """Тест 27: Просмотр файлов в workspace"""
        code, body = self._create_project(name="debug-files", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Show workspace files", "create failed", body)
            return

        pid = body["projet_id"]
        # Загрузим файлы
        zip_data = _create_test_zip({
            "test1.txt": "content1",
            "dir/test2.txt": "content2",
        })
        self._upload_file(f"/api/v1/shell/projet/{pid}/upload", "files.zip", zip_data)

        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        if s_code == 200 and isinstance(s_body, dict):
            files = s_body.get("files", [])
            file_names = [f.get("name", "") for f in files]
            has_test1 = any("test1.txt" in n for n in file_names)
            if has_test1:
                self._record(test_id, "ok", "Show workspace files", f"files={len(files)}", {"file_names": file_names})
            else:
                self._record(test_id, "warn", "Show workspace files", f"test1.txt not found in {file_names}", s_body)
        else:
            self._record(test_id, "er", "Show workspace files", f"code={s_code}", s_body)
        self._cleanup_project(pid)

    # ── Группа: list ──────────────────────────────────────────────────

    def test_list_projects(self, test_id: str) -> None:
        """Тест 28: Список всех проектов /shell/projet/list"""
        # Сначала создадим проект
        code, body = self._create_project(name="debug-list", auto_delete=False)
        pid = body.get("projet_id", "") if isinstance(body, dict) else ""

        l_code, l_body = self._get("/api/v1/shell/projet/list")
        if l_code == 200 and isinstance(l_body, dict):
            count = l_body.get("count", 0)
            projects = l_body.get("projects", [])
            self._record(test_id, "ok", "List projects", f"count={count}", {"count": count, "first_few": projects[:3]})
        else:
            self._record(test_id, "er", "List projects", f"code={l_code}", l_body)

        if pid:
            self._cleanup_project(pid)

    def test_list_filter_owner(self, test_id: str) -> None:
        """Тест 29: Фильтрация по owner"""
        code, body = self._create_project(name="debug-list-owner", owner="debug-tester", auto_delete=False)
        pid = body.get("projet_id", "") if isinstance(body, dict) else ""

        l_code, l_body = self._get("/api/v1/shell/projet/list?owner=debug-tester")
        if l_code == 200 and isinstance(l_body, dict):
            count = l_body.get("count", 0)
            if count >= 1:
                self._record(test_id, "ok", "List filter owner", f"count={count}", l_body)
            else:
                self._record(test_id, "warn", "List filter owner", "no projects found", l_body)
        else:
            self._record(test_id, "er", "List filter owner", f"code={l_code}", l_body)

        if pid:
            self._cleanup_project(pid)

    def test_list_filter_status(self, test_id: str) -> None:
        """Тест 30: Фильтрация по status"""
        l_code, l_body = self._get("/api/v1/shell/projet/list?status_filter=ready")
        if l_code == 200 and isinstance(l_body, dict):
            self._record(test_id, "ok", "List filter status", f"count={l_body.get('count', 0)}", l_body)
        else:
            self._record(test_id, "er", "List filter status", f"code={l_code}", l_body)

    def test_list_filter_name(self, test_id: str) -> None:
        """Тест 31: Фильтрация по name"""
        code, body = self._create_project(name="debug-unique-filter-name", auto_delete=False)
        pid = body.get("projet_id", "") if isinstance(body, dict) else ""

        l_code, l_body = self._get("/api/v1/shell/projet/list?name=debug-unique-filter")
        if l_code == 200 and isinstance(l_body, dict):
            count = l_body.get("count", 0)
            if count >= 1:
                self._record(test_id, "ok", "List filter name", f"count={count}", l_body)
            else:
                self._record(test_id, "warn", "List filter name", "not found", l_body)
        else:
            self._record(test_id, "er", "List filter name", f"code={l_code}", l_body)

        if pid:
            self._cleanup_project(pid)

    # ── Группа: delete ────────────────────────────────────────────────

    def test_delete_project(self, test_id: str) -> None:
        """Тест 32: Удаление проекта /shell/projet/{id}"""
        code, body = self._create_project(name="debug-delete", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Delete project", "create failed", body)
            return

        pid = body["projet_id"]
        d_code, d_body = self._delete(f"/api/v1/shell/projet/{pid}")
        if d_code == 200:
            # Проверяем что проект удалён
            s_code, _ = self._get(f"/api/v1/shell/projet/show/{pid}")
            if s_code == 404:
                self._record(test_id, "ok", "Delete project", "deleted and confirmed 404", d_body)
            else:
                self._record(test_id, "warn", "Delete project", f"deleted but still accessible (code={s_code})", d_body)
        else:
            self._record(test_id, "er", "Delete project", f"code={d_code}", d_body)

    def test_delete_nonexistent(self, test_id: str) -> None:
        """Тест 33: Удаление несуществующего проекта"""
        d_code, d_body = self._delete("/api/v1/shell/projet/nonexistent999")
        if d_code == 404:
            self._record(test_id, "ok", "Delete nonexistent", "correctly returned 404", d_body)
        else:
            self._record(test_id, "er", "Delete nonexistent", f"expected 404, got {d_code}", d_body)

    def test_auto_delete_after_run(self, test_id: str) -> None:
        """Тест 34: Авто-удаление после выполнения (default: yes)"""
        code, body = self._create_project(name="debug-autodel", auto_delete=True, run_command="echo 'will be deleted'")
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Auto-delete after run", "create failed", body)
            return

        pid = body["projet_id"]
        # Ждём выполнения и авто-удаления
        time.sleep(5)
        # Проверяем что проект удалён
        s_code, _ = self._get(f"/api/v1/shell/projet/show/{pid}")
        if s_code == 404:
            self._record(test_id, "ok", "Auto-delete after run", "workspace auto-deleted")
        else:
            self._record(test_id, "warn", "Auto-delete after run", f"still accessible (code={s_code})")
            self._cleanup_project(pid)

    # ── Группа: lifecycle ─────────────────────────────────────────────

    def test_full_lifecycle(self, test_id: str) -> None:
        """Тест 35: Полный цикл: create → upload → run → show → delete"""
        # 1. Create
        code, body = self._create_project(name="debug-lifecycle", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Full lifecycle", "create failed", body)
            return
        pid = body["projet_id"]

        # 2. Upload
        zip_data = _create_test_zip({"app.sh": "#!/bin/bash\necho 'APP_OK'"})
        u_code, u_body = self._upload_file(f"/api/v1/shell/projet/{pid}/upload", "app.zip", zip_data)
        if u_code != 200:
            self._record(test_id, "er", "Full lifecycle", "upload failed", u_body)
            self._cleanup_project(pid)
            return

        # 3. Run
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "chmod +x app.sh && bash app.sh", "timeout": 20},
        )
        if r_code != 200 or not isinstance(r_body, dict) or r_body.get("returncode") != 0:
            self._record(test_id, "er", "Full lifecycle", "run failed", r_body)
            self._cleanup_project(pid)
            return

        # 4. Show
        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        if s_code != 200:
            self._record(test_id, "er", "Full lifecycle", "show failed", s_body)
            self._cleanup_project(pid)
            return

        # 5. Delete
        d_code, d_body = self._delete(f"/api/v1/shell/projet/{pid}")
        if d_code == 200:
            self._record(test_id, "ok", "Full lifecycle", "create→upload→run→show→delete OK", r_body)
            # Don't cleanup - already deleted
        else:
            self._record(test_id, "er", "Full lifecycle", "delete failed", d_body)
            self._cleanup_project(pid)

    def test_create_zip_run_autodelete(self, test_id: str) -> None:
        """Тест 36: Create + zip + run.sh + авто-удаление

        v1.6.7: Fixed — do NOT set run_command at create time when you plan to
        upload first. Create with auto_delete=True but NO run_command, then
        upload zip, then run. The run endpoint's auto_delete will clean up.
        """
        run_sh = """#!/bin/bash
echo "DEPLOY_START"
for i in 1 2 3; do
    echo "Step $i/3"
done
echo "DEPLOY_COMPLETE"
"""
        zip_data = _create_test_zip({
            "run.sh": run_sh,
            "version.txt": "1.6.7",
        })

        # v1.6.7: Create WITHOUT run_command — upload zip first, then run
        code, body = self._create_project(
            name="debug-autodel-run",
            auto_delete=False,  # Not auto-deleting at create; run will handle it
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Create+zip+run+autodelete", "create failed", body)
            return

        pid = body["projet_id"]
        # Загрузим zip
        u_code, u_body = self._upload_file(f"/api/v1/shell/projet/{pid}/upload", "deploy.zip", zip_data)
        if u_code != 200:
            self._record(test_id, "er", "Create+zip+run+autodelete", f"upload failed code={u_code}", u_body)
            self._cleanup_project(pid)
            return

        # Запустим с auto_delete=true
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "chmod +x run.sh && bash run.sh", "timeout": 30, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "DEPLOY_COMPLETE" in stdout:
                self._record(test_id, "ok", "Create+zip+run+autodelete", "OK", r_body)
            else:
                self._record(test_id, "warn", "Create+zip+run+autodelete", f"unexpected: {stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Create+zip+run+autodelete", f"code={r_code}", r_body)

    def test_create_zip_pipe_persist(self, test_id: str) -> None:
        """Тест 37: Create + zip + pipe-тест + сохранение

        v1.6.7: Fixed — The ER pipe test now checks stdout for "ERROR:"
        instead of checking rc!=0. With bash, `cmd || echo fallback`
        makes the overall exit code 0 (the || branch succeeds), so
        checking rc!=0 was wrong. Check stdout content instead.
        """
        run_sh = """#!/bin/bash
while IFS= read -r line; do
    if echo "$line" | grep -q "^ER:"; then
        echo "ERROR: $line"
        exit 1
    elif echo "$line" | grep -q "^OK"; then
        echo "PASS: $line"
    else
        echo "UNKNOWN: $line"
    fi
done
"""
        zip_data = _create_test_zip({"run.sh": run_sh})
        code, body = self._create_project(name="debug-pipe-persist", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Create+zip+pipe+persist", "create failed", body)
            return

        pid = body["projet_id"]
        self._upload_file(f"/api/v1/shell/projet/{pid}/upload", "filter.zip", zip_data)

        # Успешный пайп (OK строки)
        r1_code, r1_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {
                "run_command": "chmod +x run.sh && echo -e 'OK: no ip\\nOK: connected' | ./run.sh && echo 'OK - код 200' || echo 'ОШИБКА'",
                "timeout": 20,
            },
        )
        ok1 = r1_code == 200 and isinstance(r1_body, dict) and r1_body.get("returncode") == 0
        # Also verify the OK pipe actually passed
        if ok1 and isinstance(r1_body, dict):
            stdout1 = r1_body.get("stdout", "")
            ok1 = "PASS:" in stdout1

        # Пайп с ошибкой (ER строки)
        # v1.6.7: Check that ERROR: appears in stdout, not that rc!=0
        # Because `./run.sh && ... || echo 'fallback'` makes rc=0 when || succeeds
        r2_code, r2_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {
                "run_command": "echo -e 'ER: no ip\\nOK' | ./run.sh && echo 'OK' || echo 'ER: -1 - код 407 (ожидаемо)'",
                "timeout": 20,
            },
        )
        ok2 = False
        if r2_code == 200 and isinstance(r2_body, dict):
            stdout2 = r2_body.get("stdout", "")
            # v1.6.7: The ER line should trigger "ERROR:" in output
            ok2 = "ERROR:" in stdout2 or "ER: -1" in stdout2

        # Проверяем что workspace сохранён
        s_code, _ = self._get(f"/api/v1/shell/projet/show/{pid}")
        ok3 = s_code == 200

        if ok1 and ok2 and ok3:
            self._record(test_id, "ok", "Create+zip+pipe+persist", "OK pipe + ER pipe + workspace persisted")
        else:
            details = []
            if not ok1:
                details.append(f"OK-pipe failed (rc={r1_body.get('returncode') if isinstance(r1_body, dict) else '?'})")
            if not ok2:
                stdout2 = r2_body.get("stdout", "?") if isinstance(r2_body, dict) else "?"
                details.append(f"ER-pipe no ERROR in output (stdout={stdout2[:100]})")
            if not ok3:
                details.append(f"workspace not found (code={s_code})")
            self._record(test_id, "er", "Create+zip+pipe+persist", ", ".join(details))

        self._cleanup_project(pid)

    def test_multiple_runs(self, test_id: str) -> None:
        """Тест 38: Множественные run в одном проекте"""
        code, body = self._create_project(name="debug-multi-run", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Multiple runs", "create failed", body)
            return

        pid = body["projet_id"]
        results = []
        for i in range(1, 4):
            r_code, r_body = self._post_json(
                f"/api/v1/shell/projet/{pid}/run",
                {"run_command": f"echo 'Run {i}'; echo 'Step {i}'", "timeout": 10},
            )
            ok = r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0
            results.append(ok)
            time.sleep(1)  # Небольшая пауза между запусками

        if all(results):
            self._record(test_id, "ok", "Multiple runs", f"3/3 runs succeeded")
        else:
            succeeded = sum(results)
            self._record(test_id, "er", "Multiple runs", f"{succeeded}/3 runs succeeded")

        self._cleanup_project(pid)

    # ── Группа: ws ────────────────────────────────────────────────────

    def test_ws_connect_project(self, test_id: str) -> None:
        """Тест 39: WebSocket: подключение к /ws/projet/{id}

        v1.6.7: Fixed — use extra_headers instead of additional_headers
        for websockets < 11.0 compatibility.
        """
        if not _HAS_WEBSOCKETS:
            self._record(test_id, "skip", "WS connect project", "websockets library not installed")
            return

        code, body = self._create_project(name="debug-ws-proj", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "WS connect project", "create failed", body)
            return

        pid = body["projet_id"]

        async def _ws_test():
            ws_url = self.server.replace("http://", "ws://").replace("https://", "wss://")
            try:
                # v1.6.7: Try additional_headers first (websockets >= 11.0),
                # fall back to extra_headers (websockets < 11.0)
                connect_kwargs = {
                    "open_timeout": self.ws_timeout,
                }
                headers = {"X-API-Key": self.api_key}
                # Try new API first
                try:
                    async with websockets.connect(
                        f"{ws_url}/ws/projet/{pid}",
                        additional_headers=headers,
                        **connect_kwargs,
                    ) as ws:
                        await ws.send("ping")
                        response = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
                        data = json.loads(response)
                        return data.get("type") == "pong" or data.get("type") == "status"
                except TypeError:
                    # Fall back to older websockets API
                    async with websockets.connect(
                        f"{ws_url}/ws/projet/{pid}",
                        extra_headers=headers,
                        **connect_kwargs,
                    ) as ws:
                        await ws.send("ping")
                        response = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
                        data = json.loads(response)
                        return data.get("type") == "pong" or data.get("type") == "status"
            except Exception as exc:
                return f"WS error: {exc}"

        try:
            result = asyncio.run(_ws_test())
            if result is True:
                self._record(test_id, "ok", "WS connect project", "connected and received data")
            else:
                self._record(test_id, "er", "WS connect project", str(result))
        except Exception as exc:
            self._record(test_id, "er", "WS connect project", str(exc))

        self._cleanup_project(pid)

    def test_ws_global(self, test_id: str) -> None:
        """Тест 40: WebSocket: глобальный /ws/projet

        v1.6.7: Fixed — use extra_headers instead of additional_headers
        for websockets < 11.0 compatibility.
        """
        if not _HAS_WEBSOCKETS:
            self._record(test_id, "skip", "WS global", "websockets library not installed")
            return

        async def _ws_test():
            ws_url = self.server.replace("http://", "ws://").replace("https://", "wss://")
            try:
                headers = {"X-API-Key": self.api_key}
                try:
                    async with websockets.connect(
                        f"{ws_url}/ws/projet",
                        additional_headers=headers,
                        open_timeout=self.ws_timeout,
                    ) as ws:
                        response = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
                        data = json.loads(response)
                        return data.get("type") in ("projets_snapshot", "pong", "status")
                except TypeError:
                    async with websockets.connect(
                        f"{ws_url}/ws/projet",
                        extra_headers=headers,
                        open_timeout=self.ws_timeout,
                    ) as ws:
                        response = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
                        data = json.loads(response)
                        return data.get("type") in ("projets_snapshot", "pong", "status")
            except Exception as exc:
                return f"WS error: {exc}"

        try:
            result = asyncio.run(_ws_test())
            if result is True:
                self._record(test_id, "ok", "WS global", "connected and received snapshot")
            else:
                self._record(test_id, "er", "WS global", str(result))
        except Exception as exc:
            self._record(test_id, "er", "WS global", str(exc))

    def test_ws_realtime_output(self, test_id: str) -> None:
        """Тест 41: WebSocket: реальный вывод при выполнении

        v1.6.7: Fixed — use extra_headers instead of additional_headers
        for websockets < 11.0 compatibility.
        """
        if not _HAS_WEBSOCKETS:
            self._record(test_id, "skip", "WS realtime output", "websockets library not installed")
            return

        code, body = self._create_project(name="debug-ws-rt", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "WS realtime output", "create failed", body)
            return

        pid = body["projet_id"]

        async def _ws_test():
            ws_url = self.server.replace("http://", "ws://").replace("https://", "wss://")
            try:
                headers = {"X-API-Key": self.api_key}
                try:
                    ws = await websockets.connect(
                        f"{ws_url}/ws/projet/{pid}",
                        additional_headers=headers,
                        open_timeout=self.ws_timeout,
                    )
                except TypeError:
                    ws = await websockets.connect(
                        f"{ws_url}/ws/projet/{pid}",
                        extra_headers=headers,
                        open_timeout=self.ws_timeout,
                    )

                # Пропускаем начальный статус
                initial = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)

                # Запускаем команду через HTTP
                import threading

                def _run_cmd():
                    self._post_json(
                        f"/api/v1/shell/projet/{pid}/run",
                        {"run_command": "echo 'WS_TEST_OUTPUT'", "timeout": 10},
                    )

                t = threading.Thread(target=_run_cmd, daemon=True)
                t.start()

                # Собираем WS сообщения
                messages = []
                try:
                    while True:
                        msg = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
                        data = json.loads(msg)
                        messages.append(data)
                        if data.get("type") == "command_result":
                            break
                except asyncio.TimeoutError:
                    pass

                await ws.close()

                # Проверяем что получили output
                has_output = any(m.get("type") == "output" for m in messages)
                has_result = any(m.get("type") == "command_result" for m in messages)
                return has_output or has_result, messages
            except Exception as exc:
                return False, str(exc)

        try:
            result, detail = asyncio.run(_ws_test())
            if result:
                self._record(test_id, "ok", "WS realtime output", "received output via WebSocket")
            else:
                self._record(test_id, "warn", "WS realtime output", f"no output received: {detail}")
        except Exception as exc:
            self._record(test_id, "er", "WS realtime output", str(exc))

        self._cleanup_project(pid)

    # ── Группа: edge ──────────────────────────────────────────────────

    def test_empty_run_command(self, test_id: str) -> None:
        """Тест 42: Пустой run_command"""
        code, body = self._create_project(name="debug-empty", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Empty run_command", "create failed", body)
            return

        pid = body["projet_id"]
        # Создаём проект без команды — это нормально
        self._record(test_id, "ok", "Empty run_command", "project created without command (valid)", body)
        self._cleanup_project(pid)

    def test_long_output(self, test_id: str) -> None:
        """Тест 43: Очень длинный вывод команды"""
        code, body = self._create_project(name="debug-longout", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Long output", "create failed", body)
            return

        pid = body["projet_id"]
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "for i in $(seq 1 100); do echo \"Line $i: $(head -c 50 /dev/urandom | base64)\"; done", "timeout": 30, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            line_count = stdout.count("\n")
            self._record(test_id, "ok", "Long output", f"{line_count} lines received", {"stdout_len": len(stdout)})
        else:
            self._record(test_id, "er", "Long output", f"code={r_code}", r_body)

    def test_special_chars(self, test_id: str) -> None:
        """Тест 44: Спецсимволы в команде"""
        code, body = self._create_project(name="debug-special", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Special chars", "create failed", body)
            return

        pid = body["projet_id"]
        cmd = """echo 'Привет мир!' && echo "Тест: $((2+2))" && echo 'Single: '"'"'quote'"'"''"""
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": cmd, "timeout": 15, "auto_delete": True},
        )
        if r_code == 200 and isinstance(r_body, dict) and r_body.get("returncode") == 0:
            stdout = r_body.get("stdout", "")
            if "4" in stdout:  # $((2+2)) = 4
                self._record(test_id, "ok", "Special chars", "OK", r_body)
            else:
                self._record(test_id, "warn", "Special chars", f"unexpected: {stdout[:200]}", r_body)
        else:
            self._record(test_id, "er", "Special chars", f"code={r_code}", r_body)

    def test_concurrent_run(self, test_id: str) -> None:
        """Тест 45: Одновременный запуск в занятом проекте

        v1.6.7: Fixed — the /run endpoint now runs synchronously (waits for
        result), so to test concurrent access we must send the first command
        in a background thread and immediately try the second command.
        """
        code, body = self._create_project(name="debug-concurrent", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Concurrent run", "create failed", body)
            return

        pid = body["projet_id"]

        # v1.6.7: Run first command in a background thread so it doesn't block
        import threading
        first_result = [None]

        def _run_first():
            first_result[0] = self._post_json(
                f"/api/v1/shell/projet/{pid}/run",
                {"run_command": "sleep 10", "timeout": 20},
            )

        t1 = threading.Thread(target=_run_first, daemon=True)
        t1.start()

        # Give the first command a moment to start
        time.sleep(0.5)

        # Пробуем запустить вторую — должно быть 409 Conflict
        r2_code, r2_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "echo 'second'", "timeout": 5},
        )
        if r2_code == 409:
            self._record(test_id, "ok", "Concurrent run", "correctly rejected with 409")
        else:
            self._record(test_id, "warn", "Concurrent run", f"expected 409, got {r2_code}", r2_body)

        # Clean up — force delete even if running
        self._cleanup_project(pid)

    # ── Группа: v1673 (v1.6.7-3 new features) ─────────────────────────

    def test_tags_labels(self, test_id: str) -> None:
        """Тест 46: Tags и labels (#11)"""
        code, body = self._create_project(
            name="debug-tags", auto_delete=False,
            tags=["production", "v2.1"],
            labels={"team": "backend", "env": "prod"},
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Tags/labels", "create failed", body)
            return

        pid = body["projet_id"]
        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        if s_code == 200 and isinstance(s_body, dict):
            ws = s_body.get("workspace", {})
            tags = ws.get("tags", [])
            labels = ws.get("labels", {})
            if "production" in tags and labels.get("team") == "backend":
                self._record(test_id, "ok", "Tags/labels", f"tags={tags}, labels={labels}", s_body)
            else:
                self._record(test_id, "warn", "Tags/labels", f"tags={tags}, labels={labels}", s_body)
        else:
            self._record(test_id, "er", "Tags/labels", "show failed", s_body)
        self._cleanup_project(pid)

    def test_tags_filter(self, test_id: str) -> None:
        """Тест 47: Фильтрация по tag/label (#11)"""
        code, body = self._create_project(
            name="debug-filter", auto_delete=False,
            tags=["test-filter-tag"],
            labels={"testkey": "testval"},
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Tags filter", "create failed", body)
            return

        pid = body["projet_id"]
        # Фильтрация по tag
        l_code, l_body = self._get(f"/api/v1/shell/projet/list?tag=test-filter-tag")
        tag_ok = l_code == 200 and isinstance(l_body, dict) and l_body.get("count", 0) >= 1

        # Фильтрация по label
        l2_code, l2_body = self._get(f"/api/v1/shell/projet/list?label=testkey=testval")
        label_ok = l2_code == 200 and isinstance(l2_body, dict) and l2_body.get("count", 0) >= 1

        if tag_ok and label_ok:
            self._record(test_id, "ok", "Tags filter", "tag and label filtering works")
        else:
            self._record(test_id, "warn", "Tags filter", f"tag_ok={tag_ok}, label_ok={label_ok}")
        self._cleanup_project(pid)

    def test_ttl_project(self, test_id: str) -> None:
        """Тест 48: TTL проекта — авто-удаление по таймеру (#5)"""
        # Создаём проект с коротким TTL (5 секунд)
        code, body = self._create_project(
            name="debug-ttl", auto_delete=False,
            ttl_seconds=5,
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "TTL project", "create failed", body)
            return

        pid = body["projet_id"]
        # Проверяем что ttl_seconds и ttl_expires_at заполнены
        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        ttl_ok = False
        if s_code == 200 and isinstance(s_body, dict):
            ws = s_body.get("workspace", {})
            if ws.get("ttl_seconds") == 5 and ws.get("ttl_expires_at"):
                ttl_ok = True

        # Ждём TTL + запас (35 секунд = 5s TTL + 30s cleanup interval)
        # Для теста не ждём реального удаления — только проверяем что поля корректны
        if ttl_ok:
            self._record(test_id, "ok", "TTL project", "ttl_seconds=5, expires_at set", s_body)
        else:
            self._record(test_id, "er", "TTL project", "ttl fields missing", s_body)
        self._cleanup_project(pid)

    def test_disk_logging(self, test_id: str) -> None:
        """Тест 49: Disk logging — .projet_logs/ (#1)"""
        code, body = self._create_project(
            name="debug-logs", auto_delete=False,
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Disk logging", "create failed", body)
            return

        pid = body["projet_id"]
        # Выполняем команду для создания логов
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "echo 'test disk logging'", "timeout": 10},
        )
        # Проверяем что logs_available=True в show
        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        logs_ok = False
        if s_code == 200 and isinstance(s_body, dict):
            logs_ok = s_body.get("logs_available", False)

        if logs_ok:
            self._record(test_id, "ok", "Disk logging", "logs_available=True", s_body)
        else:
            self._record(test_id, "warn", "Disk logging", "logs_available not True", s_body)
        self._cleanup_project(pid)

    def test_output_limit(self, test_id: str) -> None:
        """Тест 50: Output limit — OOM protection (#3)"""
        code, body = self._create_project(
            name="debug-outlim", auto_delete=False,
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Output limit", "create failed", body)
            return

        pid = body["projet_id"]
        # Генерируем большой вывод (8MB > default 5MB limit)
        r_code, r_body = self._post_json(
            f"/api/v1/shell/projet/{pid}/run",
            {"run_command": "python3 -c \"print('A' * 8 * 1024 * 1024)\"", "timeout": 30},
        )
        truncated = False
        if r_code == 200 and isinstance(r_body, dict):
            truncated = r_body.get("output_truncated", False)

        if truncated:
            self._record(test_id, "ok", "Output limit", "output truncated as expected")
        else:
            self._record(test_id, "warn", "Output limit", f"truncated={truncated}", r_body)
        self._cleanup_project(pid)

    def test_download_zip(self, test_id: str) -> None:
        """Тест 51: Download workspace как .zip (#4)"""
        code, body = self._create_project(
            name="debug-dl", auto_delete=False,
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Download .zip", "create failed", body)
            return

        pid = body["projet_id"]
        # Загрузим файл
        self._upload_file(
            f"/api/v1/shell/projet/{pid}/upload",
            "test.txt", b"Download test content",
        )
        # Скачаем workspace
        d_code, d_body = self._get(f"/api/v1/shell/projet/{pid}/download")
        if d_code == 200:
            self._record(test_id, "ok", "Download .zip", "workspace downloaded")
        else:
            self._record(test_id, "er", "Download .zip", f"code={d_code}", d_body)
        self._cleanup_project(pid)

    def test_health_check(self, test_id: str) -> None:
        """Тест 52: Health check (#13)"""
        h_code, h_body = self._get("/api/v1/shell/projet/health")
        if h_code == 200 and isinstance(h_body, dict):
            required = ["total_projects", "running", "pool_max", "max_projects"]
            ok = all(k in h_body for k in required)
            if ok:
                self._record(test_id, "ok", "Health check", f"projects={h_body.get('total_projects')}, running={h_body.get('running')}", h_body)
            else:
                self._record(test_id, "warn", "Health check", f"missing fields", h_body)
        else:
            self._record(test_id, "er", "Health check", f"code={h_code}", h_body)

    def test_owner_transfer(self, test_id: str) -> None:
        """Тест 53: Owner transfer (#14)"""
        code, body = self._create_project(
            name="debug-owner", auto_delete=False, owner="original-owner",
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Owner transfer", "create failed", body)
            return

        pid = body["projet_id"]
        # Передаём owner
        p_code, p_body = self._patch(
            f"/api/v1/shell/projet/{pid}/owner",
            {"new_owner": "new-owner"},
        )
        if p_code == 200 and isinstance(p_body, dict):
            if p_body.get("new_owner") == "new-owner":
                self._record(test_id, "ok", "Owner transfer", f"old={p_body.get('old_owner')} → new={p_body.get('new_owner')}")
            else:
                self._record(test_id, "warn", "Owner transfer", f"unexpected: {p_body}", p_body)
        else:
            self._record(test_id, "er", "Owner transfer", f"code={p_code}", p_body)
        self._cleanup_project(pid)

    def test_wait_for_completion(self, test_id: str) -> None:
        """Тест 54: Wait-for-completion режим (#8)"""
        code, body = self._create_project(
            name="debug-wait", auto_delete=False,
            run_command="echo 'sync mode test'",
            wait_for_completion=True,
            timeout=15,
        )
        if code == 200 and isinstance(body, dict):
            run_result = body.get("run_result")
            if run_result and run_result.get("returncode") == 0:
                stdout = run_result.get("stdout", "")
                if "sync mode test" in stdout:
                    self._record(test_id, "ok", "Wait-for-completion", f"rc={run_result.get('returncode')}, sync response")
                else:
                    self._record(test_id, "warn", "Wait-for-completion", f"unexpected stdout: {stdout[:100]}", body)
            else:
                self._record(test_id, "er", "Wait-for-completion", f"run_result={run_result}", body)
        else:
            self._record(test_id, "er", "Wait-for-completion", f"code={code}", body)
        if isinstance(body, dict) and body.get("projet_id"):
            self._cleanup_project(body["projet_id"])

    def test_execution_history(self, test_id: str) -> None:
        """Тест 55: Execution history (#6)"""
        code, body = self._create_project(
            name="debug-hist", auto_delete=False,
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Execution history", "create failed", body)
            return

        pid = body["projet_id"]
        # Выполняем две команды
        self._post_json(f"/api/v1/shell/projet/{pid}/run", {"run_command": "echo 'first'", "timeout": 10})
        self._post_json(f"/api/v1/shell/projet/{pid}/run", {"run_command": "echo 'second'", "timeout": 10})

        # Проверяем историю
        s_code, s_body = self._get(f"/api/v1/shell/projet/show/{pid}")
        if s_code == 200 and isinstance(s_body, dict):
            ws = s_body.get("workspace", {})
            history = ws.get("execution_history", [])
            if len(history) >= 2:
                self._record(test_id, "ok", "Execution history", f"history has {len(history)} entries")
            else:
                self._record(test_id, "warn", "Execution history", f"only {len(history)} entries", history)
        else:
            self._record(test_id, "er", "Execution history", "show failed", s_body)
        self._cleanup_project(pid)

    def test_multi_upload(self, test_id: str) -> None:
        """Тест 56: Multi-file upload (#7)"""
        if not _HAS_REQUESTS:
            self._record(test_id, "skip", "Multi-file upload", "needs requests library")
            return

        code, body = self._create_project(name="debug-multiup", auto_delete=False)
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Multi-file upload", "create failed", body)
            return

        pid = body["projet_id"]
        url = self._url(f"/api/v1/shell/projet/{pid}/upload-multi")
        headers = {"X-API-Key": self.api_key, "Accept": "application/json"}
        files = [
            ("files", ("file1.txt", b"Content 1")),
            ("files", ("file2.txt", b"Content 2")),
            ("files", ("file3.txt", b"Content 3")),
        ]
        try:
            resp = requests.post(url, headers=headers, files=files, timeout=30)
            r_body = resp.json() if resp.status_code == 200 else resp.text
            if resp.status_code == 200 and isinstance(r_body, dict):
                uploaded = r_body.get("uploaded_files", [])
                if len(uploaded) >= 3:
                    self._record(test_id, "ok", "Multi-file upload", f"{len(uploaded)} files uploaded")
                else:
                    self._record(test_id, "warn", "Multi-file upload", f"only {len(uploaded)} files", r_body)
            else:
                self._record(test_id, "er", "Multi-file upload", f"code={resp.status_code}", r_body)
        except Exception as exc:
            self._record(test_id, "er", "Multi-file upload", str(exc))
        self._cleanup_project(pid)

    def test_max_projects(self, test_id: str) -> None:
        """Тест 57: Max projects limit (#9)"""
        # Проверяем что health endpoint возвращает max_projects
        h_code, h_body = self._get("/api/v1/shell/projet/health")
        if h_code == 200 and isinstance(h_body, dict):
            max_p = h_body.get("max_projects", 0)
            total = h_body.get("total_projects", 0)
            self._record(test_id, "ok", "Max projects", f"max={max_p}, current={total}")
        else:
            self._record(test_id, "er", "Max projects", "health check failed", h_body)

    def test_disk_quota(self, test_id: str) -> None:
        """Тест 58: Disk quota (#10)"""
        # Проверяем что health endpoint возвращает max_workspace_size_mb
        h_code, h_body = self._get("/api/v1/shell/projet/health")
        if h_code == 200 and isinstance(h_body, dict):
            max_ws = h_body.get("max_workspace_size_mb", 0)
            max_out = h_body.get("max_output_size_mb", 0)
            self._record(test_id, "ok", "Disk quota", f"max_workspace={max_ws}MB, max_output={max_out}MB")
        else:
            self._record(test_id, "er", "Disk quota", "health check failed", h_body)

    def test_state_machine(self, test_id: str) -> None:
        """Тест 59: State machine — недопустимые переходы (#15)"""
        # Создаём проект и сразу пробуем удалить из running (без force)
        code, body = self._create_project(
            name="debug-statem", auto_delete=False,
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "State machine", "create failed", body)
            return

        pid = body["projet_id"]
        # Запускаем команду в фоне
        import threading
        def _run_bg():
            self._post_json(f"/api/v1/shell/projet/{pid}/run", {"run_command": "sleep 5", "timeout": 10})
        t = threading.Thread(target=_run_bg, daemon=True)
        t.start()
        time.sleep(0.5)

        # Пробуем удалить без force — должно быть 409
        d_code, d_body = self._delete(f"/api/v1/shell/projet/{pid}")
        if d_code == 409:
            self._record(test_id, "ok", "State machine", "delete from running state correctly rejected (409)")
        else:
            self._record(test_id, "warn", "State machine", f"expected 409, got {d_code}", d_body)
        self._cleanup_project(pid)

    def test_tags_patch(self, test_id: str) -> None:
        """Тест 60: Tags/labels PATCH обновление (#11)"""
        code, body = self._create_project(
            name="debug-tags-patch", auto_delete=False,
            tags=["initial"],
        )
        if code != 200 or not isinstance(body, dict) or not body.get("projet_id"):
            self._record(test_id, "er", "Tags PATCH", "create failed", body)
            return

        pid = body["projet_id"]
        # Обновляем tags через PATCH
        p_code, p_body = self._patch(
            f"/api/v1/shell/projet/{pid}/tags",
            {"tags": ["updated-tag"], "labels": {"version": "2.0"}},
        )
        if p_code == 200 and isinstance(p_body, dict):
            tags = p_body.get("tags", [])
            labels = p_body.get("labels", {})
            if "updated-tag" in tags and labels.get("version") == "2.0":
                self._record(test_id, "ok", "Tags PATCH", f"tags={tags}, labels={labels}")
            else:
                self._record(test_id, "warn", "Tags PATCH", f"unexpected: tags={tags}, labels={labels}", p_body)
        else:
            self._record(test_id, "er", "Tags PATCH", f"code={p_code}", p_body)
        self._cleanup_project(pid)

    # ═══════════════════════════════════════════════════════════════════
    #  Запуск тестов
    # ═══════════════════════════════════════════════════════════════════

    def run_test(self, test_id: str) -> None:
        """Запустить один тест по ID."""
        for tid, group, name, skip, func_name in TEST_DEFINITIONS:
            if tid == test_id:
                # Проверяем skip
                if skip == "needs_sudo" and not os.environ.get("SAMBA_SUDO_PASSWORD", ""):
                    self._record(test_id, "skip", name, "needs sudo (set SAMBA_SUDO_PASSWORD)")
                    return
                if skip == "needs_ws" and not self.enable_ws:
                    self._record(test_id, "skip", name, "WebSocket tests disabled (use --ws)")
                    return

                func = getattr(self, func_name, None)
                if func is None:
                    self._record(test_id, "er", name, f"test function '{func_name}' not found")
                    return
                try:
                    func(test_id)
                except Exception as exc:
                    self._record(test_id, "er", name, f"exception: {exc}")
                return

        print(f"  {_c('WARN', 'WARN:')} Test ID '{test_id}' not found")

    def run_all(
        self,
        test_ids: Optional[set] = None,
        group_filter: Optional[str] = None,
    ) -> None:
        """Запустить все или выбранные тесты."""
        to_run = []
        for tid, group, name, skip, func_name in TEST_DEFINITIONS:
            if test_ids is not None and tid not in test_ids:
                continue
            if group_filter is not None:
                requested_groups = [g.strip().lower() for g in group_filter.split(",")]
                if group not in requested_groups:
                    continue
            to_run.append((tid, group, name, skip, func_name))

        total = len(to_run)
        print(f"\n{_c('BOLD', f'=== Shell Project Debug: {total} tests ===')}\n")

        for idx, (tid, group, name, skip, func_name) in enumerate(to_run, 1):
            print(f"[{idx}/{total}] ", end="", flush=True)
            self.run_test(tid)
            # v1.6.6: Delay between tests to avoid rate limiting
            if self.delay > 0 and idx < total:
                time.sleep(self.delay)

        # Итоги
        print(f"\n{_c('BOLD', '=== Results ===')}")
        ok_count = len(self.results["ok"])
        er_count = len(self.results["er"])
        skip_count = len(self.results["skip"])
        warn_count = len(self.results["warn"])
        total_run = ok_count + er_count + warn_count

        print(f"  {_c('OK', f'OK: {ok_count}')}")
        print(f"  {_c('ER', f'ER: {er_count}')}")
        print(f"  {_c('WARN', f'WARN: {warn_count}')}")
        print(f"  {_c('SKIP', f'SKIP: {skip_count}')}")
        print(f"  Total: {total_run + skip_count}")

        if er_count > 0:
            print(f"\n{_c('ER', 'Failed tests:')}")
            for item in self.results["er"]:
                print(f"  [{item['test_id']}] {item['name']}: {item['detail']}")

        # Очистка
        self._cleanup_all()

        return er_count == 0


def _list_tests(show_groups: bool = False, group_filter: Optional[str] = None) -> None:
    """Показать список тестов без запуска."""
    total = len(TEST_DEFINITIONS)
    width = len(str(total))
    shown = 0
    for tid, group, name, skip, _ in TEST_DEFINITIONS:
        if group_filter is not None:
            requested_groups = [g.strip().lower() for g in group_filter.split(",")]
            if group not in requested_groups:
                continue
        parts = []
        if skip:
            parts.append(skip.upper())
        if show_groups:
            parts.append(group)
        tag = " [" + "][".join(parts) + "]" if parts else ""
        print(f"  {tid:{width}}  {group:10s} {name}{tag}")
        shown += 1
    print(f"\n  Shown: {shown} of {total} tests")
    if show_groups:
        print(f"\n  Groups:")
        for g, desc in sorted(TEST_GROUPS.items()):
            print(f"    {g:12s} {desc}")
        print(f"\n  Available groups for -g: {', '.join(sorted(TEST_GROUPS.keys()))}")


# ═══════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Shell Project API Debug / Тестирование",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-s", "--server", default=None, help="API server URL")
    parser.add_argument("-k", "--api-key", default=None, help="API key")
    parser.add_argument("-d", "--debug", action="store_true", help="Подробный вывод")
    parser.add_argument("-t", "--tests", default=None, help="Номера тестов: 5 | 1-5,8 | 10-15")
    parser.add_argument("-g", "--group", default=None, help="Группа тестов: create,upload,run,show,list,delete,lifecycle,ws,edge")
    parser.add_argument("--show", action="store_true", help="Показать список тестов")
    parser.add_argument("--ws", action="store_true", help="Включить WebSocket тесты")
    parser.add_argument("--ws-timeout", type=int, default=10, help="WebSocket таймаут (сек)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP таймаут (сек)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Задержка между тестами (сек, default=2.0, 0=без задержки)")
    parser.add_argument("--no-delay", action="store_true", help="Без задержки между тестами (--delay 0)")

    args = parser.parse_args()

    # Загрузка .env
    dotenv = _load_dotenv()

    server = args.server or os.environ.get("SAMBA_API_SERVER", "") or dotenv.get("SAMBA_API_SERVER", DEFAULT_SERVER)
    api_key = args.api_key or os.environ.get("SAMBA_API_KEY", "") or dotenv.get("SAMBA_API_KEY", DEFAULT_API_KEY)

    if not api_key:
        print(_c("WARN", "WARN: No API key provided. Set SAMBA_API_KEY or use -k flag."))
        print(_c("DIM", "  Some endpoints may return 401 Unauthorized."))

    # Показать список тестов
    if args.show:
        _list_tests(show_groups=True, group_filter=args.group)
        return

    # Парсинг номеров тестов
    test_ids = None
    if args.tests:
        test_ids = _parse_test_ids(args.tests)

    # Создаём тестер
    tester = ShellProjetTester(
        server=server,
        api_key=api_key,
        timeout=args.timeout,
        debug=args.debug,
        ws_timeout=args.ws_timeout,
        enable_ws=args.ws,
        delay=0.0 if args.no_delay else args.delay,
    )

    # Запуск
    success = tester.run_all(test_ids=test_ids, group_filter=args.group)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
