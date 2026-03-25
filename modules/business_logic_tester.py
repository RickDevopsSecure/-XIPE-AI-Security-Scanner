"""
XIPE — Business Logic Tester v1.0
High-value for fintech, ecommerce (Mercado Pago, Enviaflores, JAC):

1. Price/amount manipulation     → negative price, zero cost, overflow
2. Quantity manipulation         → negative qty, fractional qty, zero
3. Coupon/discount abuse         → stacking, reuse, expired codes
4. Rate limiting on payments     → no throttle on checkout/charge endpoints
5. Mass assignment on orders     → inject price/discount fields in body
6. Currency manipulation         → unit mismatch, currency switching mid-flow
7. Workflow step skipping        → jump from cart to confirmation without payment
8. Privilege escalation on orders → access/modify other users' orders
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException, Timeout

from agent.finding import Finding, ScoringDetail, Severity, OWASPCategory
from utils.logger import get_logger

log = get_logger("business_logic_tester")

# ── Common e-commerce / payment endpoint patterns ────────────────────────────
CART_PATHS = [
    "/api/cart", "/api/v1/cart", "/api/basket", "/api/order",
    "/api/v1/order", "/api/orders", "/api/v1/orders",
    "/api/checkout", "/api/v1/checkout",
    "/cart", "/order", "/checkout",
]

PAYMENT_PATHS = [
    "/api/payment", "/api/v1/payment", "/api/payments",
    "/api/charge", "/api/v1/charge",
    "/api/checkout/complete", "/api/order/confirm",
    "/api/v1/orders/create", "/api/purchase",
]

COUPON_PATHS = [
    "/api/coupon", "/api/v1/coupon", "/api/coupons",
    "/api/discount", "/api/promo", "/api/voucher",
    "/api/v1/apply-coupon", "/api/cart/coupon",
]

PROFILE_PATHS = [
    "/api/me", "/api/profile", "/api/v1/me", "/api/account",
    "/api/user", "/api/v1/user",
]


class BusinessLogicTester:
    def __init__(self, base_url: str, config: Dict[str, Any]):
        self.base_url = base_url.rstrip("/")
        self.config   = config
        self.timeout  = config.get("testing", {}).get("request_timeout", 8)
        self.session  = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "XIPE-SecurityScanner/4.0",
            "Content-Type": "application/json",
        })
        token = (
            config.get("scope", {}).get("credentials", {}).get("api_key")
            or config.get("scope", {}).get("credentials", {}).get("bearer_token")
            or ""
        )
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

        self._findings: List[Finding] = []

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self) -> List[Finding]:
        log.info("Starting business logic tests against %s", self.base_url)

        cart_url     = self._find_active_path(CART_PATHS)
        payment_url  = self._find_active_path(PAYMENT_PATHS)
        coupon_url   = self._find_active_path(COUPON_PATHS)
        profile_url  = self._find_active_path(PROFILE_PATHS)

        if cart_url:
            self._test_negative_price(cart_url)
            self._test_negative_quantity(cart_url)
            self._test_mass_assignment_price(cart_url)
            self._test_currency_manipulation(cart_url)

        if payment_url:
            self._test_payment_rate_limiting(payment_url)
            self._test_zero_amount_payment(payment_url)
            self._test_amount_overflow(payment_url)

        if coupon_url:
            self._test_coupon_stacking(coupon_url)
            self._test_expired_coupon_reuse(coupon_url)

        if profile_url:
            self._test_mass_assignment_profile(profile_url)

        # Always test: workflow step skip
        self._test_workflow_skip()

        # Always test: IDOR on orders
        self._test_order_idor()

        log.info("Business logic tests complete — %d findings", len(self._findings))
        return self._findings

    # ── Endpoint discovery ───────────────────────────────────────────────────

    def _find_active_path(self, paths: List[str]) -> Optional[str]:
        for path in paths:
            url = self.base_url + path
            try:
                r = self.session.request("GET", url, timeout=3, allow_redirects=False)
                if r.status_code not in (404, 502, 503):
                    return url
                # Try POST
                r2 = self.session.post(url, json={}, timeout=3, allow_redirects=False)
                if r2.status_code not in (404, 502, 503):
                    return url
            except Exception:
                continue
        return None

    # ── 1. Negative price ────────────────────────────────────────────────────

    def _test_negative_price(self, cart_url: str):
        payloads = [
            {"product_id": "1", "quantity": 1, "price": -99.99},
            {"item_id": "1", "qty": 1, "unit_price": -100},
            {"sku": "PRODUCT-001", "amount": -1, "quantity": 1},
        ]
        for payload in payloads:
            try:
                r = self.session.post(cart_url, json=payload, timeout=self.timeout)
                if r.status_code in (200, 201):
                    body = r.json() if r.headers.get("content-type","").startswith("application/json") else {}
                    total = (body.get("total") or body.get("grand_total") or
                             body.get("amount") or body.get("price") or 0)
                    try:
                        if float(total) < 0:
                            self._add(
                                title="Negative Price Accepted — Business Logic Bypass",
                                severity=Severity.CRITICAL,
                                category=OWASPCategory.BROKEN_ACCESS,
                                endpoint=cart_url,
                                description=(
                                    "The application accepted a negative price value in the cart/order "
                                    "payload and reflected a negative total. In a complete e-commerce flow, "
                                    "this could result in a credit being issued to the attacker's account "
                                    "or a purchase being made at a negative cost."
                                ),
                                evidence=f"POST {cart_url} with price={payload.get('price') or payload.get('unit_price') or payload.get('amount')} → total={total}",
                                recommendation=(
                                    "1. Validate all price/amount fields server-side: reject negative values.\n"
                                    "2. Never trust client-supplied price — always calculate server-side from product catalog.\n"
                                    "3. Use unsigned integer types for monetary amounts (cents, not floats)."
                                ),
                                cwe="CWE-840",
                                priority_score=9.5,
                            )
                            return
                    except Exception:
                        pass
            except Exception:
                continue

    # ── 2. Negative quantity ─────────────────────────────────────────────────

    def _test_negative_quantity(self, cart_url: str):
        payloads = [
            {"product_id": "1", "quantity": -1, "price": 100},
            {"item_id": "1", "qty": -5},
            {"sku": "PRODUCT-001", "quantity": -999},
        ]
        for payload in payloads:
            try:
                r = self.session.post(cart_url, json=payload, timeout=self.timeout)
                if r.status_code in (200, 201):
                    body_text = r.text
                    if any(c in body_text for c in ["-", "−"]) and "total" in body_text.lower():
                        self._add(
                            title="Negative Quantity Accepted — Inventory / Refund Manipulation",
                            severity=Severity.HIGH,
                            category=OWASPCategory.BROKEN_ACCESS,
                            endpoint=cart_url,
                            description=(
                                "The application accepted a negative quantity in the cart. This can be "
                                "abused to reverse inventory charges, generate fraudulent refunds, or "
                                "produce a negative cart total."
                            ),
                            evidence=f"POST {cart_url} qty=-1 → HTTP 200",
                            recommendation=(
                                "1. Validate quantity as a positive integer (qty >= 1).\n"
                                "2. Enforce minimum order quantity server-side.\n"
                                "3. Separate add/remove cart operations rather than accepting negative qty."
                            ),
                            cwe="CWE-840",
                            priority_score=8.0,
                        )
                        return
            except Exception:
                continue

    # ── 3. Mass assignment — inject price ────────────────────────────────────

    def _test_mass_assignment_price(self, cart_url: str):
        """Try injecting price/discount fields the server shouldn't accept from client."""
        payloads = [
            {"product_id": "1", "quantity": 1, "price": 0.01, "final_price": 0.01, "discount": 99},
            {"item_id": "1", "quantity": 1, "unit_price": 0, "total": 0},
            {"sku": "PRODUCT-001", "quantity": 1, "override_price": 1, "coupon_discount": 100},
        ]
        for payload in payloads:
            try:
                r = self.session.post(cart_url, json=payload, timeout=self.timeout)
                if r.status_code in (200, 201):
                    try:
                        body = r.json()
                        total = float(body.get("total") or body.get("amount") or body.get("price") or 999)
                        if 0 <= total < 5:
                            self._add(
                                title="Mass Assignment — Client-Controlled Price Override",
                                severity=Severity.CRITICAL,
                                category=OWASPCategory.API_MASS_ASSIGN,
                                endpoint=cart_url,
                                description=(
                                    "The API accepts price/discount fields from the client request body "
                                    "and uses them in the order total calculation. An attacker can send "
                                    "arbitrarily low prices and bypass the server-side pricing logic."
                                ),
                                evidence=f"POST with price=0.01 → total={total}",
                                recommendation=(
                                    "1. NEVER use client-supplied price fields for calculations.\n"
                                    "2. Look up price from server-side product catalog using product_id.\n"
                                    "3. Use allowlist DTO validation — reject any field not in the allowlist.\n"
                                    "4. Log and alert on any order with total < expected minimum."
                                ),
                                cwe="CWE-915",
                                priority_score=9.5,
                            )
                            return
                    except Exception:
                        pass
            except Exception:
                continue

    # ── 4. Currency manipulation ──────────────────────────────────────────────

    def _test_currency_manipulation(self, cart_url: str):
        """Switch currency to low-value denomination mid-request."""
        payloads = [
            {"product_id": "1", "quantity": 1, "currency": "VND"},   # Vietnamese dong
            {"product_id": "1", "quantity": 1, "currency": "IDR"},   # Indonesian rupiah
            {"product_id": "1", "quantity": 1, "currency": "XAF"},   # CFA franc
        ]
        for payload in payloads:
            try:
                r = self.session.post(cart_url, json=payload, timeout=self.timeout)
                if r.status_code in (200, 201):
                    body = r.text
                    if payload["currency"].lower() in body.lower():
                        self._add(
                            title="Currency Manipulation — Attacker-Controlled Currency Switch",
                            severity=Severity.HIGH,
                            category=OWASPCategory.BROKEN_ACCESS,
                            endpoint=cart_url,
                            description=(
                                f"The API accepted an attacker-supplied currency code ({payload['currency']}) "
                                "in the cart payload and reflected it. If the backend charges in the "
                                "requested currency without proper conversion, an attacker could pay "
                                "100 VND (≈ $0.004) for a $100 product."
                            ),
                            evidence=f"POST with currency={payload['currency']} → reflected in response",
                            recommendation=(
                                "1. Currency must be determined server-side based on user region/account settings.\n"
                                "2. Never accept currency as a client parameter.\n"
                                "3. Validate all currency conversions with a trusted exchange rate service."
                            ),
                            cwe="CWE-840",
                            priority_score=8.5,
                        )
                        return
            except Exception:
                continue

    # ── 5. Payment rate limiting ─────────────────────────────────────────────

    def _test_payment_rate_limiting(self, payment_url: str):
        """Send 10 rapid payment requests — check for 429 or other throttling."""
        statuses = []
        for _ in range(10):
            try:
                r = self.session.post(
                    payment_url,
                    json={"amount": 1, "currency": "MXN", "card_token": "probe_token"},
                    timeout=4,
                )
                statuses.append(r.status_code)
            except Exception:
                break
            time.sleep(0.1)

        throttled = any(s == 429 for s in statuses)
        if not throttled and len(statuses) >= 8:
            self._add(
                title="No Rate Limiting on Payment Endpoint",
                severity=Severity.HIGH,
                category=OWASPCategory.API_UNRESTRICTED,
                endpoint=payment_url,
                description=(
                    "The payment endpoint does not enforce rate limiting. 10 rapid payment "
                    f"requests returned status codes {set(statuses)} with no throttling. "
                    "This enables card testing attacks (carding) where attackers validate "
                    "stolen credit card numbers by making micro-charges."
                ),
                evidence=f"10 requests in <2s → statuses: {statuses}",
                recommendation=(
                    "1. Implement strict rate limiting: max 3-5 payment attempts per minute per user/IP.\n"
                    "2. Add velocity checks: flag accounts with >3 failed payments in 10 minutes.\n"
                    "3. Require CAPTCHA after 3 failed payment attempts.\n"
                    "4. Integrate with fraud detection (e.g., Stripe Radar, Mercado Pago fraud signals)."
                ),
                cwe="CWE-770",
                priority_score=8.0,
            )

    # ── 6. Zero amount payment ────────────────────────────────────────────────

    def _test_zero_amount_payment(self, payment_url: str):
        for amount in [0, 0.0, "0", "0.00"]:
            try:
                r = self.session.post(
                    payment_url,
                    json={"amount": amount, "currency": "MXN", "order_id": "test-001"},
                    timeout=self.timeout,
                )
                if r.status_code in (200, 201):
                    body_text = r.text.lower()
                    if any(k in body_text for k in ("success", "approved", "confirmed", "transaction_id", "reference")):
                        self._add(
                            title="Zero-Amount Payment Accepted",
                            severity=Severity.CRITICAL,
                            category=OWASPCategory.BROKEN_ACCESS,
                            endpoint=payment_url,
                            description=(
                                f"The payment endpoint accepted a charge of amount=0 and returned "
                                f"a success response. An attacker can complete purchases for free "
                                f"by manipulating the amount to zero."
                            ),
                            evidence=f"POST amount={amount} → HTTP {r.status_code} success",
                            recommendation=(
                                "1. Validate amount > 0 before processing any payment.\n"
                                "2. Cross-check payment amount against order total server-side.\n"
                                "3. Never process a payment without verifying the charge amount matches the order."
                            ),
                            cwe="CWE-840",
                            priority_score=9.5,
                        )
                        return
            except Exception:
                continue

    # ── 7. Amount overflow ────────────────────────────────────────────────────

    def _test_amount_overflow(self, payment_url: str):
        for amount in [2**31, 2**53, 9999999999999, -2**31]:
            try:
                r = self.session.post(
                    payment_url,
                    json={"amount": amount, "currency": "MXN"},
                    timeout=self.timeout,
                )
                if r.status_code in (200, 201):
                    try:
                        body = r.json()
                        resp_amount = body.get("amount") or body.get("total") or body.get("charged")
                        if resp_amount is not None and float(resp_amount) != float(amount):
                            self._add(
                                title="Integer Overflow in Payment Amount",
                                severity=Severity.HIGH,
                                category=OWASPCategory.BROKEN_ACCESS,
                                endpoint=payment_url,
                                description=(
                                    f"A very large amount ({amount}) was sent to the payment endpoint. "
                                    f"The response reflected a different amount ({resp_amount}), indicating "
                                    f"integer overflow or truncation. This could be exploited to make "
                                    f"large-value purchases appear as negligible amounts."
                                ),
                                evidence=f"Sent {amount} → response amount={resp_amount}",
                                recommendation=(
                                    "1. Use 64-bit integers or decimal types for monetary amounts.\n"
                                    "2. Validate amount within reasonable business bounds (e.g., max $10,000).\n"
                                    "3. Use cents (integer) rather than floating-point for all money."
                                ),
                                cwe="CWE-190",
                                priority_score=8.0,
                            )
                            return
                    except Exception:
                        pass
            except Exception:
                continue

    # ── 8. Coupon stacking ────────────────────────────────────────────────────

    def _test_coupon_stacking(self, coupon_url: str):
        """Apply same coupon twice in rapid succession."""
        for code in ["SAVE10", "DISCOUNT20", "PROMO50", "TEST100"]:
            results = []
            for _ in range(2):
                try:
                    r = self.session.post(
                        coupon_url,
                        json={"code": code, "cart_id": "test-cart-001"},
                        timeout=5,
                    )
                    results.append(r.status_code)
                except Exception:
                    break
                time.sleep(0.2)

            if len(results) == 2 and results[0] == 200 and results[1] == 200:
                self._add(
                    title="Coupon Code Double-Application (Stacking)",
                    severity=Severity.HIGH,
                    category=OWASPCategory.BROKEN_ACCESS,
                    endpoint=coupon_url,
                    description=(
                        f"The coupon code '{code}' was accepted twice in rapid succession "
                        f"(both requests returned HTTP 200). This suggests no server-side "
                        f"check prevents applying the same coupon multiple times, allowing "
                        f"attackers to compound discounts beyond what's intended."
                    ),
                    evidence=f"POST coupon={code} × 2 → [{results[0]}, {results[1]}]",
                    recommendation=(
                        "1. Track coupon application at the session/order level and reject duplicates.\n"
                        "2. Implement atomic check-and-apply (database transaction) to prevent race conditions.\n"
                        "3. Mark coupons as 'used' immediately upon first application."
                    ),
                    cwe="CWE-840",
                    priority_score=7.5,
                )
                return

    # ── 9. Expired coupon reuse ───────────────────────────────────────────────

    def _test_expired_coupon_reuse(self, coupon_url: str):
        for code in ["EXPIRED2020", "OLD_PROMO", "NEWYEAR2021", "BLACKFRIDAY2022"]:
            try:
                r = self.session.post(
                    coupon_url,
                    json={"code": code, "cart_id": "test-cart-001"},
                    timeout=5,
                )
                if r.status_code == 200:
                    body = r.text.lower()
                    if any(k in body for k in ("discount", "applied", "saved", "valid")):
                        self._add(
                            title="Expired Promotional Code Accepted",
                            severity=Severity.MEDIUM,
                            category=OWASPCategory.BROKEN_ACCESS,
                            endpoint=coupon_url,
                            description=(
                                f"The clearly expired coupon code '{code}' was accepted. "
                                "Lack of expiry validation allows attackers to reuse promotional "
                                "codes indefinitely after their intended end date."
                            ),
                            evidence=f"POST code={code} → HTTP 200 with discount applied",
                            recommendation=(
                                "1. Store coupon expiry dates and validate on every application.\n"
                                "2. Automatically disable expired coupons in the database.\n"
                                "3. Log and alert when expired codes are attempted."
                            ),
                            cwe="CWE-613",
                            priority_score=5.5,
                        )
                        return
            except Exception:
                continue

    # ── 10. Mass assignment on profile ───────────────────────────────────────

    def _test_mass_assignment_profile(self, profile_url: str):
        """Try to inject privileged fields via profile update."""
        payloads = [
            {"name": "Test", "balance": 9999, "credits": 9999},
            {"name": "Test", "wallet_balance": 10000, "store_credit": 5000},
            {"name": "Test", "loyalty_points": 999999},
        ]
        for payload in payloads:
            try:
                r = self.session.patch(profile_url, json=payload, timeout=self.timeout)
                if r.status_code in (200, 201, 204):
                    try:
                        body = r.json()
                        injected_fields = [k for k in payload if k != "name"]
                        if any(body.get(k, 0) != 0 for k in injected_fields):
                            self._add(
                                title="Mass Assignment — User Balance / Credit Manipulation",
                                severity=Severity.CRITICAL,
                                category=OWASPCategory.API_MASS_ASSIGN,
                                endpoint=profile_url,
                                description=(
                                    "The profile update endpoint accepted financial fields "
                                    f"({', '.join(injected_fields)}) and reflected modified values. "
                                    "An attacker can credit their own account with arbitrary balance or points."
                                ),
                                evidence=f"PATCH {profile_url} with {injected_fields} → values reflected",
                                recommendation=(
                                    "1. Use strict DTO/serializer allowlist — only accept `name`, `email`, etc.\n"
                                    "2. Financial fields (balance, credits, points) must only be modified "
                                    "by internal service calls, never by user-facing API.\n"
                                    "3. Apply mass assignment protection at the framework level."
                                ),
                                cwe="CWE-915",
                                priority_score=9.5,
                            )
                            return
                    except Exception:
                        pass
            except Exception:
                continue

    # ── 11. Workflow step skip ────────────────────────────────────────────────

    def _test_workflow_skip(self):
        """Try to hit order confirmation without going through payment."""
        skip_targets = [
            ("/api/order/confirm",     {"order_id": "TEST-001", "status": "paid"}),
            ("/api/checkout/complete", {"cart_id": "test-cart", "payment_status": "completed"}),
            ("/api/v1/orders/confirm", {"order_id": "ORD-001", "payment": "skip"}),
        ]
        for path, payload in skip_targets:
            url = self.base_url + path
            try:
                r = self.session.post(url, json=payload, timeout=5)
                if r.status_code in (200, 201):
                    body = r.text.lower()
                    if any(k in body for k in ("confirmed", "success", "order_id", "confirmation")):
                        self._add(
                            title="Order Confirmation Without Payment — Workflow Skip",
                            severity=Severity.CRITICAL,
                            category=OWASPCategory.BROKEN_ACCESS,
                            endpoint=url,
                            description=(
                                "The order confirmation endpoint accepted a request with a forged "
                                "'paid' status without going through the payment gateway. "
                                "This allows attackers to place orders without paying."
                            ),
                            evidence=f"POST {path} with payment_status=completed → HTTP 200 confirmed",
                            recommendation=(
                                "1. NEVER trust payment status from the client request.\n"
                                "2. Verify payment status by querying the payment gateway server-side.\n"
                                "3. Use a state machine: cart → payment_initiated → payment_verified → confirmed.\n"
                                "4. Each state transition must be validated server-side."
                            ),
                            cwe="CWE-840",
                            priority_score=9.5,
                        )
                        return
            except Exception:
                continue

    # ── 12. Order IDOR ────────────────────────────────────────────────────────

    def _test_order_idor(self):
        order_paths = [
            "/api/orders/1", "/api/v1/orders/1", "/api/order/1",
            "/api/orders/ORD-001", "/api/v1/orders/100",
        ]
        for path in order_paths:
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
                if r.status_code == 200 and len(r.text) > 50:
                    body_text = r.text.lower()
                    if any(k in body_text for k in ("order_id", "customer", "amount", "total", "email")):
                        self._add(
                            title="Order IDOR — Access to Other Users' Orders",
                            severity=Severity.HIGH,
                            category=OWASPCategory.API_BOLA,
                            endpoint=url,
                            description=(
                                f"Authenticated request to {path} returned order data that may belong "
                                f"to a different user. No ownership verification was performed. "
                                f"Attackers can enumerate all orders by iterating IDs."
                            ),
                            evidence=f"GET {url} → HTTP 200 with order data",
                            recommendation=(
                                "1. Verify the requesting user owns the order: `order.user_id == auth.user_id`.\n"
                                "2. Use UUIDs instead of sequential integers for order IDs.\n"
                                "3. Return 403 or 404 for orders not belonging to the current user."
                            ),
                            cwe="CWE-639",
                            priority_score=7.5,
                        )
                        return
            except Exception:
                continue

    # ── Finding builder ──────────────────────────────────────────────────────

    def _add(self, title: str, severity: Severity, category: OWASPCategory,
             endpoint: str, description: str, evidence: str,
             recommendation: str, cwe: str, priority_score: float) -> None:
        if any(f.title == title for f in self._findings):
            return

        sev_map = {
            Severity.CRITICAL: 9.5, Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,   Severity.LOW: 3.0,
        }
        base = sev_map.get(severity, 5.0)

        scoring = ScoringDetail(
            severity_score=base,
            exploitability_score=base,
            exposure_score=8.0,
            business_risk_score=9.5,   # Business logic = max business risk
            asset_criticality_score=9.0,
            confidence_score=8.0,
            priority_score=priority_score,
            score_explanation=f"Business logic — {title[:60]}",
        )

        f = Finding(
            id=f"BIZ-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            severity=severity,
            category=category,
            module="business_logic_tester",
            endpoint=endpoint,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            cwe=cwe,
            scoring=scoring,
            tags=["business-logic", "ecommerce", "fintech", cwe.lower()],
        )
        self._findings.append(f)
        log.warning("Business logic finding: %s", title)


# ── Orchestrator entry ────────────────────────────────────────────────────────

def run(base_url: str, config: Dict[str, Any]) -> List[Finding]:
    return BusinessLogicTester(base_url, config).run()
