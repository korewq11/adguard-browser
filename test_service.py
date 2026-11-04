import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer
import service

KEY = "test-service-key-" + "x" * 32
IDENT = "a" * 32
PAYLOAD = {"id": IDENT, "email": "mine@example.test", "password": "dummy-password",
           "terms_accepted": True}


class LogicTests(unittest.IsolatedAsyncioTestCase):
    def response(self, path, posted, data, status=200):
        request = SimpleNamespace(method="POST", headers={"content-type": "application/json"},
                                  post_data=json.dumps(posted))
        return SimpleNamespace(url=service.AUTH + path, request=request, status=status, json=AsyncMock(return_value=data))

    async def test_otp_login_cannot_verify_password(self):
        session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"], stage="verify")
        await session.inspect_response(self.response("/login_api/1.0/login", {
            "username": session.email, "code": "012345"}, {"success": True}), "verify")
        self.assertFalse(session.password_accepted)

    async def test_wrong_email_or_password_cannot_verify(self):
        for posted in [{"username": "other@example.test", "password": PAYLOAD["password"]},
                       {"username": PAYLOAD["email"], "password": "wrong-password"}]:
            session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"], stage="verify")
            await session.inspect_response(self.response("/login_api/1.0/login", posted, {"success": True}), "verify")
            self.assertFalse(session.password_accepted)

    async def test_old_context_response_cannot_verify_new_context(self):
        session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"], stage="verify")
        await session.inspect_response(self.response("/login_api/1.0/login", {
            "username": session.email, "password": session.password}, {"success": True}), "register")
        self.assertFalse(session.password_accepted)

    async def test_confirmed_and_correct_password_are_both_required(self):
        session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"], stage="verify")
        await session.inspect_response(self.response("/api/1.0/web/user_lookup", {"email": session.email},
            {"confirmed": True, "can_register": False, "captcha": True}), "verify")
        self.assertTrue(session.confirmed)
        self.assertEqual(session.phase, "captcha")
        session.phase = "working"
        await session.inspect_response(self.response("/login_api/1.0/login", {
            "username": session.email, "password": session.password}, {"success": True}), "verify")
        await session.drive()
        self.assertTrue(session.verified)
        self.assertEqual(session.phase, "ready")

    async def test_verification_does_not_fall_back_to_otp(self):
        session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"], stage="verify", phase="working")
        absent = SimpleNamespace(count=AsyncMock(return_value=0))
        session.page = SimpleNamespace(locator=lambda *a, **kw: absent,
            get_by_role=lambda *a, **kw: SimpleNamespace(first=absent))
        session.visible = AsyncMock(side_effect=[None, None, object()])
        session.captcha_visible = AsyncMock(return_value=False)
        await session.drive()
        self.assertEqual(session.phase, "manual")
        self.assertFalse(session.verified)
        self.assertIn("паролем", session.message)

    async def test_429_stops_instead_of_retrying(self):
        session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"])
        await session.inspect_response(self.response("/api/1.0/web/registration", {}, {}, 429), "register")
        self.assertEqual(session.phase, "error")
        await session.drive()  # No page object: must return without clicking anything.

    async def test_mfa_is_not_a_successful_login(self):
        self.assertFalse(service.login_accepted({"success": True, "mfa_method": "email"}))
        self.assertFalse(service.login_accepted({"success": True, "redirect_url": "/confirm_account.html"}))
        self.assertTrue(service.login_accepted({"success": True, "redirect_url": "/process_login.html"}))

    async def test_public_state_and_repr_do_not_expose_credentials(self):
        session = service.Session(IDENT, PAYLOAD["email"], PAYLOAD["password"])
        public = json.dumps(session.public())
        self.assertNotIn(session.password, public)
        self.assertNotIn(session.view_token, public)
        self.assertNotIn(session.password, repr(session))
        self.assertNotIn(session.view_token, repr(session))

    async def test_bad_coordinates_and_weak_key_rejected(self):
        for value in [-1, 960, True, "1", float("nan")]:
            with self.assertRaises(service.web.HTTPBadRequest):
                service.point(value, 960)
        with self.assertRaises(ValueError):
            service.Manager("short", "https://example.test")
        with self.assertRaises(ValueError):
            service.Manager(KEY, "http://example.test")


class HttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = service.create_app(KEY, "https://browser.example.test")
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        async def idle(session):
            await asyncio.Event().wait()
        self.run_patch = patch.object(service.Session, "run", idle)
        self.run_patch.start()
        self.headers = {"Authorization": "Bearer " + KEY}

    async def asyncTearDown(self):
        await self.client.close()
        self.run_patch.stop()

    async def create(self, payload=None):
        response = await self.client.post("/v1/sessions", json=payload or PAYLOAD, headers=self.headers)
        self.assertEqual(response.status, 201)
        return await response.json()

    async def test_health_is_public_but_create_requires_api_key(self):
        self.assertEqual((await self.client.get("/health")).status, 200)
        response = await self.client.post("/v1/sessions", json=PAYLOAD)
        self.assertEqual(response.status, 401)
        self.assertFalse(self.app[service.MANAGER_KEY].sessions)

    async def test_idempotent_create_and_conflicting_credentials(self):
        original = await self.create()
        response = await self.client.post("/v1/sessions", json=PAYLOAD, headers=self.headers)
        self.assertEqual(response.status, 200)
        self.assertEqual((await response.json())["view_url"], original["view_url"])
        changed = dict(PAYLOAD, password="another-password")
        self.assertEqual((await self.client.post("/v1/sessions", json=changed, headers=self.headers)).status, 409)
        self.assertEqual(len(self.app[service.MANAGER_KEY].sessions), 1)

    async def test_only_one_browser_at_a_time(self):
        await self.create()
        response = await self.client.post("/v1/sessions", json=dict(PAYLOAD, id="b" * 32), headers=self.headers)
        self.assertEqual(response.status, 409)

    async def test_view_token_controls_only_its_session_not_code_api(self):
        await self.create()
        session = self.app[service.MANAGER_KEY].sessions[IDENT]
        viewer = {"Authorization": "Bearer " + session.view_token}
        path = "/v1/sessions/" + IDENT
        self.assertEqual((await self.client.get(path)).status, 401)
        response = await self.client.get(path, headers=viewer)
        self.assertEqual(response.status, 200)
        self.assertNotIn("view_url", await response.json())
        self.assertEqual((await self.client.post(path + "/code", json={"code": "012345"}, headers=viewer)).status, 401)
        self.assertEqual((await self.client.get("/v1/sessions/" + "b" * 32, headers=viewer)).status, 401)

    async def test_consent_and_body_validation(self):
        for payload in [[], {"id": IDENT}, dict(PAYLOAD, terms_accepted=False), dict(PAYLOAD, id="../escape")]:
            response = await self.client.post("/v1/sessions", json=payload, headers=self.headers)
            self.assertEqual(response.status, 400)
        self.assertFalse(self.app[service.MANAGER_KEY].sessions)

    async def test_cross_origin_actions_are_blocked(self):
        response = await self.client.post("/v1/sessions", json=PAYLOAD,
            headers={**self.headers, "Origin": "https://evil.example"})
        self.assertEqual(response.status, 403)

    async def test_expiry_and_security_headers(self):
        await self.create()
        session = self.app[service.MANAGER_KEY].sessions[IDENT]
        session.created -= service.TTL + 1
        response = await self.client.get("/v1/sessions/" + IDENT, headers=self.headers)
        self.assertEqual(response.status, 410)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    async def test_codes_only_when_requested_and_six_digits(self):
        await self.create()
        session = self.app[service.MANAGER_KEY].sessions[IDENT]
        path = "/v1/sessions/" + IDENT + "/code"
        response = await self.client.post(path, json={"code": "012345"}, headers=self.headers)
        self.assertFalse((await response.json())["accepted"])
        session.phase = "otp"
        response = await self.client.post(path, json={"code": "012345"}, headers=self.headers)
        self.assertTrue((await response.json())["accepted"])
        self.assertEqual(session.code, "012345")
        self.assertEqual((await self.client.post(path, json={"code": "abc"}, headers=self.headers)).status, 400)

    async def test_browser_action_error_does_not_expose_typed_text(self):
        await self.create()
        session = self.app[service.MANAGER_KEY].sessions[IDENT]
        session.page = SimpleNamespace(mouse=SimpleNamespace(click=AsyncMock(side_effect=RuntimeError("typed-private-text"))))
        session.phase = "working"
        with self.assertLogs(level="WARNING") as captured:
            response = await self.client.post("/v1/sessions/" + IDENT + "/action",
                json={"kind": "click", "x": 1, "y": 1}, headers=self.headers)
        self.assertEqual(response.status, 502)
        self.assertNotIn("typed-private-text", await response.text())
        self.assertNotIn("typed-private-text", "".join(captured.output))

    async def test_manual_click_and_resume_do_not_claim_captcha_solved(self):
        await self.create()
        session = self.app[service.MANAGER_KEY].sessions[IDENT]
        session.page = SimpleNamespace(mouse=SimpleNamespace(click=AsyncMock()))
        session.phase = "captcha"
        path = "/v1/sessions/" + IDENT + "/action"
        response = await self.client.post(path, json={"kind": "click", "x": 20, "y": 30}, headers=self.headers)
        self.assertEqual(response.status, 200)
        session.page.mouse.click.assert_awaited_once_with(20.0, 30.0)
        self.assertFalse(session.verified)
        response = await self.client.post(path, json={"kind": "resume"}, headers=self.headers)
        self.assertEqual(response.status, 200)
        self.assertTrue(session.captcha_ack)
        self.assertFalse(session.verified)
        self.assertEqual((await self.client.post(path, json={"kind": "navigate", "url": "https://evil.example"}, headers=self.headers)).status, 400)


if __name__ == "__main__":
    unittest.main()
