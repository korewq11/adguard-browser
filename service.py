"""Single-user browser service. CAPTCHA is operated only by the human owner."""
import asyncio
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import time
import traceback
from urllib.parse import parse_qs, urlsplit

from aiohttp import web

AUTH = "https://auth.adguardaccount.com"
AUTH_HOSTS = {"auth.adguardaccount.com", "auth.adguard.com"}
ACCOUNT_HOSTS = {"adguardaccount.com", "account.adguardaccount.com", "account.adguard.com", "my.adguard.com"}
WIDTH, HEIGHT = 960, 720
TTL = 720
TERMINAL = {"ready", "error", "expired", "stopped"}


def diagnostic_reason(exc):
    # Emit only known constant signatures, never Playwright call logs/form values.
    text = str(exc)
    network = re.search(r"net::ERR_[A-Z0-9_]+", text)
    if network:
        return network.group(0)
    lowered = text.lower()
    signatures = [
        ("no usable sandbox", "NO_USABLE_SANDBOX"),
        ("failed to move to new namespace", "NAMESPACE_DENIED"),
        ("missing dependencies", "MISSING_LIBRARIES"),
        ("error while loading shared libraries", "MISSING_LIBRARIES"),
        ("page crashed", "PAGE_CRASHED"),
        ("target page, context or browser has been closed", "TARGET_CLOSED"),
        ("interrupted by another navigation", "NAVIGATION_INTERRUPTED"),
        ("strict mode violation", "STRICT_LOCATOR"),
        ("element is not editable", "ELEMENT_NOT_EDITABLE"),
        ("execution context was destroyed", "CONTEXT_DESTROYED"),
        ("frame was detached", "FRAME_DETACHED"),
        ("timeout", "TIMEOUT"),
    ]
    return next((code for fragment, code in signatures if fragment in lowered), "UNCLASSIFIED")


def diagnostic_location(exc):
    frames = traceback.extract_tb(exc.__traceback__)
    local = [f"{frame.name}:{frame.lineno}" for frame in frames if Path(frame.filename).name == "service.py"]
    return ">".join(local[-3:]) or "unknown"


def credential_digest(email, password):
    return hashlib.sha256((email + "\0" + password).encode()).hexdigest()


def login_accepted(data):
    redirect = str(data.get("redirect_url") or "").lower()
    return (data.get("success") is True and not data.get("error_code")
            and not data.get("errorCode") and not data.get("mfa_method")
            and not any(word in redirect for word in ("confirmation", "confirm_account", "two_factor", "2fa")))


def decode_body(request):
    try:
        if "json" in request.headers.get("content-type", ""):
            return json.loads(request.post_data or "{}")
        return {key: values[0] for key, values in parse_qs(request.post_data or "").items()}
    except (ValueError, TypeError):
        return {}


@dataclass
class Session:
    ident: str
    email: str
    password: str = field(repr=False)
    view_token: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    created: float = field(default_factory=time.monotonic)
    started_at: float = field(default_factory=time.time)
    otp_since: float = 0
    phase: str = "opening"
    message: str = "Запускаю браузер…"
    stage: str = "register"
    operation: str = "starting"
    verified: bool = False
    confirmed: bool = False
    password_accepted: bool = False
    initial_authenticated: bool = False
    captcha_ack: bool = False
    captcha_required: bool = False
    code: str | None = None
    submitted: str = ""
    task: object = None
    driver: object = None
    browser: object = None
    context: object = None
    page: object = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    response_tasks: set = field(default_factory=set)

    def __post_init__(self):
        self.digest = credential_digest(self.email, self.password)

    def public(self, base=None):
        result = {"id": self.ident, "phase": self.phase, "message": self.message,
                  "verified": self.verified, "stage": self.stage,
                  "started_at": self.started_at, "otp_since": self.otp_since,
                  "expires_in": max(0, int(TTL - (time.monotonic() - self.created)))}
        if base:
            result["view_url"] = f"{base}/#session={self.ident}&token={self.view_token}"
        return result

    def response(self, response, stage):
        task = asyncio.create_task(self.inspect_response(response, stage))
        self.response_tasks.add(task)
        task.add_done_callback(self.response_tasks.discard)

    async def inspect_response(self, response, stage):
        try:
            if stage != self.stage:
                return
            parsed = urlsplit(response.url)
            if parsed.hostname not in AUTH_HOSTS or response.request.method != "POST":
                return
            path = parsed.path
            watched = {"/api/1.0/web/user_lookup", "/api/1.0/web/registration",
                       "/login_api/1.0/login", "/login_api/1.0/authorized"}
            if path not in watched:
                return
            posted = decode_body(response.request)
            try:
                data = await response.json()
            except Exception:
                data = {}
            if self.phase in TERMINAL or stage != self.stage:
                return
            if path.endswith("user_lookup") and self.stage == "verify" and response.status == 200:
                if posted.get("email", "").lower() == self.email.lower():
                    self.confirmed = data.get("confirmed") is True and data.get("can_register") is False
            if response.status == 429:
                self.phase, self.message = "error", "AdGuard ограничил запросы. Автоматических повторов нет."
                return
            captcha_error = str(data.get("error_code") or data.get("errorCode") or "").lower()
            if data.get("captcha") is True or "captcha" in captcha_error or data.get("field") == "captcha":
                self.captcha_required = True
                self.captcha_ack = False
                self.phase, self.message = "captcha", "Пройди CAPTCHA в этом окне и нажми «Продолжить»."
                return
            if response.status >= 400:
                self.phase, self.message = "manual", "AdGuard отклонил действие. Проверь сообщение в окне браузера."
                return
            if path.endswith("/login"):
                same_email = posted.get("username", "").lower() == self.email.lower()
                if same_email and login_accepted(data):
                    if self.stage == "verify" and hmac.compare_digest(posted.get("password", ""), self.password):
                        self.password_accepted = True
                    elif self.stage == "register":
                        self.initial_authenticated = True
            if path.endswith("/authorized") and self.stage == "register" and login_accepted(data):
                self.initial_authenticated = True
        except Exception:
            # No response bodies, form values or cookies in logs.
            logging.warning("Could not inspect an AdGuard response")

    async def route(self, route):
        request = route.request
        if request.is_navigation_request() and request.frame.parent_frame is None:
            url = urlsplit(request.url)
            if url.scheme != "https" or url.hostname not in AUTH_HOSTS | ACCOUNT_HOSTS:
                await route.abort()
                self.phase, self.message = "manual", "Разрешён только вход по email на официальных страницах AdGuard."
                return
        if request.resource_type == "media":
            await route.abort()
        else:
            # Do not interfere with CAPTCHA JavaScript, images or iframes.
            await route.continue_()

    async def new_page(self, stage):
        self.operation = "new-context"
        if self.context is not None:
            await self.context.close()
        self.stage = stage
        self.context = await self.browser.new_context(viewport={"width": WIDTH, "height": HEIGHT})
        self.operation = "new-page"
        self.page = await self.context.new_page()
        self.page.on("response", lambda response: self.response(response, stage))
        await self.context.route("**/*", self.route)
        self.submitted = ""
        self.captcha_ack = False
        self.captcha_required = False
        self.operation = "open-login-form"
        await self.page.goto(AUTH + "/login.html", wait_until="domcontentloaded", timeout=45000)

    async def visible(self, selector):
        locator = self.page.locator(selector)
        for index in range(min(await locator.count(), 12)):
            item = locator.nth(index)
            if await item.is_visible() and await item.is_enabled():
                return item
        return None

    async def captcha_visible(self):
        frames = self.page.locator('iframe[src*="captcha"], iframe[src*="challenges.cloudflare.com"]')
        for index in range(await frames.count()):
            item = frames.nth(index)
            box = await item.bounding_box() if await item.is_visible() else None
            if box and box["width"] >= 200 and box["height"] >= 50:
                return True
        return False

    async def drive(self):
        if self.phase in TERMINAL or self.phase == "manual":
            return
        if self.stage == "register" and self.initial_authenticated:
            # Drop ALL cookies from OTP/registration before password verification.
            self.phase, self.message = "verifying", "Проверяю пароль в новой браузерной сессии…"
            await self.new_page("verify")
            return
        if self.stage == "verify" and self.confirmed and self.password_accepted:
            self.verified = True
            self.phase, self.message = "ready", "Вход с паролем подтверждён."
            return
        self.operation = "inspect-form"
        email_input = await self.visible('input[type="email"]')
        password_input = await self.visible('input[type="password"]')
        if email_input and await email_input.input_value() != self.email:
            self.operation = "fill-email"
            await email_input.fill(self.email, timeout=3000)
        if password_input and await password_input.input_value() != self.password:
            self.operation = "fill-password"
            await password_input.fill(self.password, timeout=3000)
        self.operation = "accept-terms"
        terms = self.page.locator('input#eulaConfirmed, input[name="eulaConfirmed"]')
        if await terms.count() and not await terms.is_checked():
            await terms.check(force=True, timeout=3000)
        # Newsletter boxes are deliberately left unchecked.
        self.operation = "inspect-captcha"
        captcha = self.captcha_required or await self.captcha_visible()
        if captcha and not self.captcha_ack:
            self.phase, self.message = "captcha", "Пройди CAPTCHA и нажми «Продолжить»."
            return
        self.operation = "inspect-otp"
        code_input = await self.visible('input[autocomplete="one-time-code"], input[inputmode="numeric"], input[maxlength="6"], input[maxlength="1"]')
        if code_input:
            switch = self.page.get_by_role("button", name=re.compile(
                r"^((Use|Enter|Log ?in|Sign ?in).*password|(Войти|Вход|Использовать|Ввести).*парол.*)$", re.I)).first
            if not password_input and await switch.count() and await switch.is_visible():
                await switch.click(timeout=3000)
                return
            if self.stage == "verify" and not self.password_accepted:
                self.phase, self.message = "manual", "Переключи форму на вход с паролем и нажми «Продолжить»; вход по коду не подтверждает пароль."
                return
            if self.code is None:
                if self.phase != "otp":
                    self.otp_since = time.time()
                self.phase, self.message = "otp", "Ожидаю код из почты; бот введёт его автоматически."
                return
            code, self.code = self.code, None
            maxlength = await code_input.get_attribute("maxlength")
            if maxlength == "1":
                fields = self.page.locator('input[maxlength="1"]')
                if await fields.count() != 6:
                    self.phase, self.message = "manual", "Неизвестный формат поля кода."
                    return
                for index, digit in enumerate(code):
                    await fields.nth(index).fill(digit, timeout=3000)
            else:
                await code_input.fill(code, timeout=3000)
            self.phase = "working"
            # Some forms submit as soon as the last digit is entered.
            await asyncio.sleep(0.5)
        button = self.page.get_by_role("button", name=re.compile(
            r"^(Continue|Log in|Sign up|Confirm|Продолжить|Войти|Создать аккаунт|Зарегистрироваться|Подтвердить)$", re.I)).first
        if await button.count() and await button.is_visible() and await button.is_enabled():
            values = await self.page.locator("input").evaluate_all(
                "els => els.map(e => [e.type, e.value, e.checked])")
            signature = hashlib.sha256(json.dumps([self.stage, self.page.url, values]).encode()).hexdigest()
            if signature == self.submitted:
                return  # Never loop a failed POST or repeatedly click a registration button.
            self.submitted = signature
            self.captcha_ack = False
            self.captcha_required = False
            self.operation = "submit-form"
            await button.click(timeout=3000)
            if self.phase not in {"captcha", "otp", "manual"}:
                self.phase = "working" if self.stage == "register" else "verifying"
                self.message = "Выполняю регистрацию…" if self.stage == "register" else "Проверяю вход…"

    async def run(self):
        try:
            from playwright.async_api import async_playwright
            self.driver = await async_playwright().start()
            self.operation = "launch-chromium"
            self.browser = await self.driver.chromium.launch(
                headless=True, chromium_sandbox=os.environ.get("BROWSER_NO_SANDBOX") != "1",
                args=["--disable-dev-shm-usage", "--renderer-process-limit=1", "--js-flags=--max-old-space-size=96"],
                timeout=45000)
            await self.new_page("register")
            self.phase = "working"
            while self.phase not in TERMINAL:
                if time.monotonic() - self.created >= TTL:
                    self.phase, self.message = "expired", "Время сессии истекло; данные аккаунта остаются у бота."
                    break
                async with self.lock:
                    await self.drive()
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.phase, self.message = "error", "Ошибка браузера. Проверь Render Logs; автоматического успеха нет."
            if self.browser is None:
                logging.error("Chromium launch failure: %s", str(exc)[:1500])
            else:
                reason = diagnostic_reason(exc)
                self.message = f"Ошибка браузера: {self.operation}, {reason}. Подробности в Render Logs."
                logging.error("Browser operation failure: stage=%s operation=%s type=%s reason=%s location=%s",
                              self.stage, self.operation, type(exc).__name__, reason, diagnostic_location(exc))
        finally:
            await self.cleanup()

    async def cleanup(self):
        for pending in list(self.response_tasks):
            pending.cancel()
        if self.response_tasks:
            await asyncio.gather(*self.response_tasks, return_exceptions=True)
        if self.browser:
            try:
                await asyncio.wait_for(self.browser.close(), 10)
            except Exception:
                pass
        if self.driver:
            try:
                await asyncio.wait_for(self.driver.stop(), 10)
            except Exception:
                pass
        self.password = ""

    async def stop(self, phase="stopped"):
        self.phase = phase
        self.message = "Сессия остановлена." if phase == "stopped" else "Время сессии истекло."
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)


class Manager:
    def __init__(self, key, base):
        if len(key) < 32:
            raise ValueError("BROWSER_SERVICE_KEY must contain at least 32 characters")
        parsed = urlsplit(base)
        if not base or parsed.scheme not in {"https", "http"} or parsed.username or parsed.password or parsed.path.strip("/") or parsed.query or parsed.fragment:
            raise ValueError("Set PUBLIC_BASE_URL or RENDER_EXTERNAL_URL to the service origin")
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("HTTPS is required outside localhost")
        self.key, self.base = key, base.rstrip("/")
        self.sessions = {}
        self.lock = asyncio.Lock()

    def api_auth(self, request):
        supplied = request.headers.get("Authorization", "")
        return hmac.compare_digest(supplied.encode(), ("Bearer " + self.key).encode())

    def session(self, request, api_only=False):
        session = self.sessions.get(request.match_info["ident"])
        supplied = request.headers.get("Authorization", "")
        valid = self.api_auth(request) or (not api_only and session and hmac.compare_digest(
            supplied.encode(), ("Bearer " + session.view_token).encode()))
        if not valid:
            raise web.HTTPUnauthorized()
        if session is None:
            raise web.HTTPNotFound()
        if time.monotonic() - session.created >= TTL:
            raise web.HTTPGone(text="Session expired")
        return session


MANAGER_KEY = web.AppKey("manager", Manager)


@web.middleware
async def security_headers(request, handler):
    origin = request.headers.get("Origin")
    if request.method != "GET" and origin and origin.rstrip("/") != request.app[MANAGER_KEY].base:
        raise web.HTTPForbidden()
    try:
        response = await handler(request)
    except web.HTTPException as exc:
        response = exc
    except Exception as exc:
        logging.warning("Browser HTTP operation failed (%s)", type(exc).__name__)
        response = web.HTTPBadGateway(text="Browser operation failed")
    response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
                             "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                             "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"})
    if isinstance(response, web.HTTPException):
        raise response
    return response


async def root(request):
    return web.FileResponse(Path(__file__).with_name("index.html"))


async def object_body(request):
    try:
        body = await request.json()
    except (ValueError, TypeError):
        raise web.HTTPBadRequest()
    if not isinstance(body, dict):
        raise web.HTTPBadRequest()
    return body


async def ui_js(request):
    return web.FileResponse(Path(__file__).with_name("ui.js"))


async def ui_css(request):
    return web.FileResponse(Path(__file__).with_name("ui.css"))


async def health(request):
    return web.json_response({"status": "ok"})


async def create_session(request):
    manager = request.app[MANAGER_KEY]
    if not manager.api_auth(request):
        raise web.HTTPUnauthorized()
    try:
        data = await object_body(request)
        ident, email, password = data["id"], data["email"], data["password"]
        if not (isinstance(ident, str) and re.fullmatch(r"[a-f0-9]{32}", ident)
                and isinstance(email, str) and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
                and len(email) <= 254 and isinstance(password, str) and 8 <= len(password) <= 64
                and data.get("terms_accepted") is True):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise web.HTTPBadRequest(text="Invalid registration request or missing consent")
    async with manager.lock:
        old = manager.sessions.get(ident)
        if old and time.monotonic() - old.created < TTL:
            if not hmac.compare_digest(old.digest, credential_digest(email, password)):
                raise web.HTTPConflict()
            return web.json_response(old.public(manager.base))
        if any(s.phase not in TERMINAL for s in manager.sessions.values()):
            raise web.HTTPConflict(text="A browser session is already active")
        session = Session(ident, email, password)
        manager.sessions[ident] = session
        session.task = asyncio.create_task(session.run())
        return web.json_response(session.public(manager.base), status=201)


async def state(request):
    session = request.app[MANAGER_KEY].session(request)
    return web.json_response(session.public())


async def screen(request):
    session = request.app[MANAGER_KEY].session(request)
    if session.phase in TERMINAL or session.page is None:
        raise web.HTTPConflict(text="Browser not available")
    async with session.lock:
        try:
            image = await session.page.screenshot(type="jpeg", quality=65, timeout=5000)
        except Exception:
            raise web.HTTPConflict(text="Browser frame not available")
    return web.Response(body=image, content_type="image/jpeg")


async def code(request):
    session = request.app[MANAGER_KEY].session(request, api_only=True)
    data = await object_body(request)
    value = data.get("code")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{6}", value):
        raise web.HTTPBadRequest()
    if session.phase != "otp" or session.code is not None:
        return web.json_response({"accepted": False})
    session.code = value
    return web.json_response({"accepted": True})


def point(value, maximum):
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value < maximum:
        raise web.HTTPBadRequest()
    return float(value)


async def action(request):
    session = request.app[MANAGER_KEY].session(request)
    data = await object_body(request)
    kind = data.get("kind")
    if kind == "stop":
        await session.stop()
        return web.json_response(session.public())
    if session.phase in TERMINAL or session.page is None:
        raise web.HTTPConflict()
    async with session.lock:
        if kind == "resume":
            session.captcha_ack = True
            session.captcha_required = False
            session.submitted = ""
            session.phase, session.message = "working", "Продолжаю…"
        elif kind in {"click", "drag"}:
            x, y = point(data.get("x"), WIDTH), point(data.get("y"), HEIGHT)
            if kind == "click":
                await session.page.mouse.click(x, y)
            else:
                x2, y2 = point(data.get("x2"), WIDTH), point(data.get("y2"), HEIGHT)
                await session.page.mouse.move(x, y)
                await session.page.mouse.down()
                try:
                    await session.page.mouse.move(x2, y2, steps=10)
                finally:
                    await session.page.mouse.up()
        elif kind == "key" and data.get("key") in {"Enter", "Tab", "Backspace", "Escape", "ArrowLeft", "ArrowRight", "Control+a"}:
            await session.page.keyboard.press(data["key"])
        elif kind == "text" and isinstance(data.get("text"), str) and len(data["text"]) <= 256:
            await session.page.keyboard.insert_text(data["text"])
        elif kind == "scroll" and data.get("dy") in {-500, 500}:
            await session.page.mouse.wheel(0, data["dy"])
        else:
            raise web.HTTPBadRequest()
    return web.json_response(session.public())


async def lifecycle(app):
    async def expire():
        while True:
            await asyncio.sleep(20)
            manager = app[MANAGER_KEY]
            for ident, session in list(manager.sessions.items()):
                if time.monotonic() - session.created >= TTL:
                    await session.stop("expired")
                    manager.sessions.pop(ident, None)
    task = asyncio.create_task(expire())
    yield
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await asyncio.gather(*(s.stop() for s in app[MANAGER_KEY].sessions.values()), return_exceptions=True)


def create_app(key=None, base=None):
    app = web.Application(middlewares=[security_headers], client_max_size=4096)
    app[MANAGER_KEY] = Manager(key or os.environ.get("BROWSER_SERVICE_KEY", ""),
                             base or os.environ.get("PUBLIC_BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL", ""))
    app.router.add_get("/", root)
    app.router.add_get("/ui.js", ui_js)
    app.router.add_get("/ui.css", ui_css)
    app.router.add_get("/health", health)
    app.router.add_post("/v1/sessions", create_session)
    app.router.add_get("/v1/sessions/{ident}", state)
    app.router.add_get("/v1/sessions/{ident}/screen", screen)
    app.router.add_post("/v1/sessions/{ident}/code", code)
    app.router.add_post("/v1/sessions/{ident}/action", action)
    app.cleanup_ctx.append(lifecycle)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    web.run_app(create_app(), host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), access_log=None)
