package collector

import (
	"crypto/tls"
	"io"
	"net/http"
	"siphon-go/core"
	"strings"
	"sync"
	"time"
)

package main

var CommonJSPaths = []string{
	// ── Root-level basics ──────────────────────────────────────────────────────
	"/app.js", "/main.js", "/index.js", "/bundle.js", "/init.js",
	"/config.js", "/settings.js", "/env.js", "/constants.js",
	"/api.js", "/utils.js", "/helpers.js", "/common.js", "/global.js",
	"/auth.js", "/router.js", "/routes.js", "/store.js", "/services.js",
	"/vendors.js", "/chunk.js", "/core.js", "/base.js",

	// ── /js/ ──────────────────────────────────────────────────────────────────
	"/js/app.js", "/js/main.js", "/js/index.js", "/js/config.js",
	"/js/api.js", "/js/utils.js", "/js/helpers.js", "/js/auth.js",
	"/js/bundle.js", "/js/vendors.js",
	"/js/core.js", "/js/base.js", "/js/common.js", "/js/global.js",
	"/js/routes.js", "/js/router.js", "/js/store.js", "/js/services.js",
	"/js/init.js", "/js/settings.js", "/js/constants.js",
	"/js/chunk.js", "/js/polyfills.js", "/js/runtime.js",
	"/js/bootstrap.js", "/js/jquery.js", "/js/jquery.min.js",
	"/js/vue.js", "/js/react.js", "/js/angular.js",
	"/js/lodash.js", "/js/axios.js", "/js/moment.js",
	"/js/payment.js", "/js/checkout.js", "/js/cart.js",
	"/js/login.js", "/js/register.js", "/js/profile.js",
	"/js/dashboard.js", "/js/analytics.js", "/js/tracking.js",
	"/js/mobile.js", "/js/desktop.js", "/js/responsive.js",
	"/js/slider.js", "/js/carousel.js", "/js/modal.js",
	"/js/form.js", "/js/validation.js", "/js/upload.js",
	"/js/i18n.js", "/js/locale.js", "/js/translate.js",
	"/js/crypto.js", "/js/encrypt.js",
	"/js/notification.js", "/js/push.js",
	"/js/socket.js", "/js/websocket.js",

	// ── /static/js/ ────────────────────────────────────────────────────────────
	"/static/js/app.js", "/static/js/main.js", "/static/js/index.js", "/static/js/bundle.js",
	"/static/js/config.js", "/static/js/vendors.js", "/static/js/core.js",
	"/static/js/utils.js", "/static/js/helpers.js", "/static/js/auth.js",
	"/static/js/chunk.js", "/static/js/runtime.js", "/static/js/polyfills.js",
	"/static/js/payment.js", "/static/js/checkout.js", "/static/js/cart.js",
	"/static/js/login.js", "/static/js/dashboard.js",
	"/static/js/router.js", "/static/js/store.js", "/static/js/api.js",
	"/static/js/common.js", "/static/js/global.js", "/static/js/base.js",
	"/static/js/bootstrap.js", "/static/js/jquery.min.js",
	"/static/js/vue.js", "/static/js/react.js",
	"/static/js/mobile.js", "/static/js/responsive.js",
	"/static/js/tracking.js", "/static/js/analytics.js",
	"/static/js/i18n.js", "/static/js/locale.js",
	"/static/js/2.chunk.js", "/static/js/3.chunk.js",
	"/static/js/main.chunk.js", "/static/js/vendor.chunk.js",

	// ── /assets/ ───────────────────────────────────────────────────────────────
	"/assets/js/app.js", "/assets/js/main.js", "/assets/js/config.js",
	"/assets/js/api.js", "/assets/js/utils.js", "/assets/application.js",
	"/assets/index.js", "/assets/vendor.js",
	"/assets/js/core.js", "/assets/js/base.js", "/assets/js/common.js",
	"/assets/js/bundle.js", "/assets/js/vendors.js", "/assets/js/chunk.js",
	"/assets/js/auth.js", "/assets/js/router.js", "/assets/js/store.js",
	"/assets/js/helpers.js", "/assets/js/services.js", "/assets/js/payment.js",
	"/assets/js/checkout.js", "/assets/js/cart.js", "/assets/js/login.js",
	"/assets/js/dashboard.js", "/assets/js/tracking.js",
	"/assets/js/bootstrap.js", "/assets/js/jquery.min.js",
	"/assets/js/runtime.js", "/assets/js/polyfills.js",
	"/assets/js/mobile.js", "/assets/js/i18n.js",
	"/assets/js/manifest.js", "/assets/js/framework.js",
	"/assets/js/notification.js", "/assets/js/socket.js",

	// ── /dist/ ─────────────────────────────────────────────────────────────────
	"/dist/app.js", "/dist/main.js", "/dist/bundle.js", "/dist/index.js",
	"/dist/config.js", "/dist/vendors.js", "/dist/core.js",
	"/dist/utils.js", "/dist/helpers.js", "/dist/auth.js",
	"/dist/chunk.js", "/dist/runtime.js", "/dist/polyfills.js",
	"/dist/payment.js", "/dist/checkout.js", "/dist/cart.js",
	"/dist/login.js", "/dist/dashboard.js", "/dist/router.js",
	"/dist/store.js", "/dist/api.js", "/dist/common.js",
	"/dist/js/app.js", "/dist/js/main.js", "/dist/js/bundle.js",
	"/dist/js/config.js", "/dist/js/vendors.js", "/dist/js/core.js",
	"/dist/js/utils.js", "/dist/js/auth.js", "/dist/js/payment.js",
	"/dist/js/chunk.js", "/dist/js/runtime.js",
	"/dist/js/2.chunk.js", "/dist/js/3.chunk.js",

	// ── /build/ ────────────────────────────────────────────────────────────────
	"/build/app.js", "/build/main.js", "/build/bundle.js", "/build/static/js/main.js",
	"/build/static/js/main.chunk.js", "/build/static/js/2.chunk.js",
	"/build/static/js/runtime-main.js", "/build/static/js/vendors~main.chunk.js",
	"/build/js/app.js", "/build/js/main.js", "/build/js/bundle.js",
	"/build/js/config.js", "/build/js/vendors.js", "/build/js/core.js",
	"/build/js/utils.js", "/build/js/auth.js", "/build/js/chunk.js",
	"/build/index.js", "/build/config.js", "/build/vendors.js",

	// ── /public/ ───────────────────────────────────────────────────────────────
	"/public/js/app.js", "/public/js/main.js",
	"/public/js/config.js", "/public/js/vendors.js", "/public/js/core.js",
	"/public/js/utils.js", "/public/js/helpers.js", "/public/js/auth.js",
	"/public/js/bundle.js", "/public/js/chunk.js", "/public/js/runtime.js",
	"/public/js/payment.js", "/public/js/checkout.js",
	"/public/js/login.js", "/public/js/dashboard.js",
	"/public/js/router.js", "/public/js/store.js", "/public/js/api.js",
	"/public/js/tracking.js", "/public/js/analytics.js",
	"/public/app.js", "/public/main.js", "/public/bundle.js",
	"/public/config.js", "/public/index.js",

	// ── /src/ ──────────────────────────────────────────────────────────────────
	"/src/app.js", "/src/main.js", "/src/index.js",
	"/src/config.js", "/src/api.js", "/src/utils.js",
	"/src/helpers.js", "/src/auth.js", "/src/router.js",
	"/src/store.js", "/src/services.js", "/src/common.js",
	"/src/payment.js", "/src/checkout.js", "/src/login.js",
	"/src/dashboard.js", "/src/tracking.js",
	"/src/js/app.js", "/src/js/main.js", "/src/js/config.js",
	"/src/js/api.js", "/src/js/utils.js", "/src/js/auth.js",

	// ── /scripts/ ──────────────────────────────────────────────────────────────
	"/scripts/app.js", "/scripts/main.js", "/scripts/bundle.js",
	"/scripts/config.js", "/scripts/api.js", "/scripts/utils.js",
	"/scripts/auth.js", "/scripts/router.js", "/scripts/payment.js",
	"/scripts/checkout.js", "/scripts/login.js", "/scripts/dashboard.js",
	"/scripts/tracking.js", "/scripts/analytics.js",
	"/scripts/jquery.min.js", "/scripts/bootstrap.js",
	"/scripts/vendors.js", "/scripts/core.js", "/scripts/base.js",
	"/scripts/init.js", "/scripts/common.js",

	// ── /app/ ──────────────────────────────────────────────────────────────────
	"/app/app.js", "/app/main.js", "/app/index.js",
	"/app/config.js", "/app/api.js", "/app/utils.js",
	"/app/auth.js", "/app/router.js", "/app/store.js",
	"/app/payment.js", "/app/checkout.js", "/app/login.js",
	"/app/dashboard.js", "/app/bundle.js", "/app/vendors.js",
	"/app/js/app.js", "/app/js/main.js", "/app/js/config.js",
	"/app/js/api.js", "/app/js/auth.js", "/app/js/payment.js",

	// ── /admin/ ────────────────────────────────────────────────────────────────
	"/admin/app.js", "/admin/main.js", "/admin/index.js",
	"/admin/config.js", "/admin/api.js", "/admin/utils.js",
	"/admin/auth.js", "/admin/dashboard.js", "/admin/bundle.js",
	"/admin/js/app.js", "/admin/js/main.js", "/admin/js/config.js",
	"/admin/js/api.js", "/admin/js/auth.js", "/admin/js/dashboard.js",
	"/admin/static/js/main.js", "/admin/static/js/bundle.js",
	"/admin/assets/js/app.js", "/admin/assets/js/main.js",
	"/panel/app.js", "/panel/main.js", "/panel/js/app.js",
	"/panel/js/main.js", "/panel/js/config.js",

	// ── /api/ versioned ────────────────────────────────────────────────────────
	"/v1/app.js", "/v2/app.js", "/api/config.js", "/api/v1/config.js",
	"/api/v2/config.js", "/api/v1/app.js", "/api/v2/app.js",
	"/api/js/config.js", "/api/js/main.js",
	"/v1/js/app.js", "/v2/js/app.js", "/v3/app.js", "/v3/js/app.js",

	// ── /config/ ───────────────────────────────────────────────────────────────
	"/config/config.js", "/config/index.js", "/env.production.js",
	"/config/app.js", "/config/api.js", "/config/auth.js",
	"/config/payment.js", "/config/settings.js", "/config/constants.js",
	"/config/routes.js", "/config/router.js", "/config/store.js",
	"/configuration/config.js", "/configuration/app.js",

	// ── Next.js ────────────────────────────────────────────────────────────────
	"/_next/static/chunks/main.js",
	"/_next/static/chunks/app-pages.js",
	"/_next/static/chunks/pages/_app.js",
	"/_next/static/chunks/webpack.js",
	"/_next/static/chunks/framework.js",
	"/_next/static/chunks/polyfills.js",
	"/_next/static/chunks/commons.js",
	"/_next/static/chunks/pages/index.js",
	"/_next/static/chunks/pages/_error.js",
	"/_next/static/chunks/pages/auth/login.js",
	"/_next/static/chunks/pages/auth/register.js",
	"/_next/static/chunks/pages/dashboard.js",
	"/_next/static/chunks/pages/payment.js",
	"/_next/static/chunks/pages/checkout.js",
	"/_next/static/chunks/pages/profile.js",
	"/_next/static/chunks/pages/transfer.js",
	"/_next/static/chunks/pages/wallet.js",
	"/_next/static/chunks/pages/orders.js",
	"/_next/static/chunks/pages/catalog.js",
	"/_next/static/chunks/pages/product.js",
	"/_next/static/chunks/pages/cart.js",
	"/_next/static/chunks/pages/search.js",
	"/_next/static/chunks/pages/settings.js",
	"/_next/static/chunks/pages/notifications.js",
	"/_next/static/chunks/react.js",
	"/_next/static/chunks/react-dom.js",
	"/_next/static/runtime/main.js",
	"/_next/static/runtime/webpack.js",
	"/_next/static/runtime/polyfills.js",
	"/_next/data/build-id/index.json",

	// ── Nuxt.js ────────────────────────────────────────────────────────────────
	"/_nuxt/app.js", "/_nuxt/entry.js",
	"/_nuxt/config.js", "/_nuxt/runtime.js",
	"/_nuxt/vendors.app.js", "/_nuxt/commons.app.js",
	"/_nuxt/pages/index.js", "/_nuxt/pages/login.js",
	"/_nuxt/pages/register.js", "/_nuxt/pages/dashboard.js",
	"/_nuxt/pages/payment.js", "/_nuxt/pages/checkout.js",
	"/_nuxt/pages/profile.js", "/_nuxt/pages/transfer.js",
	"/_nuxt/pages/wallet.js", "/_nuxt/pages/orders.js",
	"/_nuxt/pages/catalog.js", "/_nuxt/pages/product.js",
	"/_nuxt/pages/cart.js", "/_nuxt/pages/search.js",
	"/_nuxt/layouts/default.js", "/_nuxt/layouts/error.js",
	"/_nuxt/middleware/auth.js", "/_nuxt/middleware/redirect.js",
	"/_nuxt/store/index.js", "/_nuxt/store/auth.js",
	"/_nuxt/store/cart.js", "/_nuxt/store/payment.js",

	// ── WordPress ──────────────────────────────────────────────────────────────
	"/wp-content/themes/app.js", "/wp-includes/js/api.js",
	"/wp-content/themes/main.js", "/wp-content/themes/bundle.js",
	"/wp-content/plugins/woocommerce/app.js",
	"/wp-content/plugins/woocommerce/checkout.js",
	"/wp-content/themes/child/app.js",
	"/wp-includes/js/jquery/jquery.min.js",
	"/wp-includes/js/wp-api.js",

	// ── Create React App / chunk patterns ─────────────────────────────────────
	"/build/static/js/main.chunk.js", "/build/static/js/2.chunk.js",
	"/build/static/js/3.chunk.js", "/build/static/js/4.chunk.js",
	"/build/static/js/runtime-main.chunk.js",
	"/build/static/js/vendors~main.chunk.js",
	"/static/js/main.chunk.js", "/static/js/2.chunk.js",
	"/static/js/3.chunk.js", "/static/js/4.chunk.js",
	"/static/js/runtime-main.chunk.js",
	"/static/js/vendors~main.chunk.js",

	// ── Kapitalbank specific patterns ──────────────────────────────────────────
	"/mobile/js/app.js", "/mobile/js/main.js", "/mobile/js/config.js",
	"/mobile/js/api.js", "/mobile/js/auth.js", "/mobile/js/payment.js",
	"/mobile/app.js", "/mobile/main.js", "/mobile/bundle.js",
	"/mobile/assets/js/app.js", "/mobile/assets/js/main.js",
	"/mobile/static/js/main.js", "/mobile/static/js/bundle.js",
	"/internet-banking/app.js", "/internet-banking/main.js",
	"/internet-banking/js/app.js", "/internet-banking/js/main.js",
	"/internet-banking/js/config.js", "/internet-banking/js/api.js",
	"/internet-banking/js/auth.js", "/internet-banking/js/payment.js",
	"/internet-banking/static/js/main.js",
	"/internet-banking/assets/js/app.js",
	"/ib/app.js", "/ib/main.js", "/ib/js/app.js",
	"/ib/js/main.js", "/ib/js/config.js", "/ib/js/auth.js",
	"/ib/static/js/main.js", "/ib/assets/js/app.js",
	"/online/app.js", "/online/main.js", "/online/js/app.js",
	"/online/js/main.js", "/online/js/config.js", "/online/js/api.js",
	"/online/js/auth.js", "/online/js/payment.js",
	"/online/static/js/main.js",
	"/online-banking/app.js", "/online-banking/main.js",
	"/online-banking/js/app.js", "/online-banking/js/config.js",
	"/bank/app.js", "/bank/main.js", "/bank/js/app.js",
	"/bank/js/config.js", "/bank/js/api.js",
	"/banking/app.js", "/banking/main.js", "/banking/js/app.js",
	"/banking/js/config.js", "/banking/js/payment.js",
	"/digital/app.js", "/digital/main.js", "/digital/js/app.js",
	"/digital/js/config.js", "/digital-banking/js/app.js",
	"/payment/app.js", "/payment/main.js", "/payment/js/app.js",
	"/payment/js/config.js", "/payment/js/api.js",
	"/payment/js/checkout.js", "/payment/js/auth.js",
	"/payment/static/js/main.js", "/payment/assets/js/app.js",
	"/payments/app.js", "/payments/main.js", "/payments/js/app.js",
	"/payments/js/config.js", "/payments/js/checkout.js",
	"/transfer/app.js", "/transfer/main.js", "/transfer/js/app.js",
	"/transfer/js/config.js", "/transfer/js/api.js",
	"/transfers/js/app.js", "/transfers/js/config.js",
	"/kapital/app.js", "/kapital/js/app.js", "/kapital/js/config.js",
	"/kapitalbank/app.js", "/kapitalbank/js/app.js",
	"/kb/app.js", "/kb/main.js", "/kb/js/app.js",
	"/kb/js/config.js", "/kb/js/api.js",
	"/kbank/app.js", "/kbank/js/app.js",
	"/e-bank/app.js", "/e-bank/js/app.js", "/e-bank/js/config.js",
	"/ebank/app.js", "/ebank/js/app.js", "/ebank/js/config.js",
	"/personal/app.js", "/personal/js/app.js",
	"/personal/js/config.js", "/personal/js/auth.js",
	"/corporate/app.js", "/corporate/js/app.js",
	"/corporate/js/config.js", "/corporate/js/api.js",
	"/business/app.js", "/business/main.js", "/business/js/app.js",
	"/business/js/config.js", "/business/js/api.js",
	"/sms/app.js", "/sms/js/config.js",
	"/otp/app.js", "/otp/js/config.js",
	"/2fa/app.js", "/2fa/js/config.js",
	"/security/app.js", "/security/js/config.js",
	"/wallet/app.js", "/wallet/main.js", "/wallet/js/app.js",
	"/wallet/js/config.js", "/wallet/js/api.js",
	"/card/app.js", "/card/js/app.js", "/card/js/config.js",
	"/cards/app.js", "/cards/js/app.js", "/cards/js/config.js",
	"/loan/app.js", "/loan/js/app.js", "/loan/js/config.js",
	"/loans/app.js", "/loans/js/app.js", "/loans/js/config.js",
	"/deposit/app.js", "/deposit/js/app.js", "/deposit/js/config.js",
	"/deposits/js/app.js", "/deposits/js/config.js",
	"/account/app.js", "/account/js/app.js", "/account/js/config.js",
	"/accounts/app.js", "/accounts/js/app.js",
	"/history/app.js", "/history/js/app.js",
	"/statement/app.js", "/statement/js/app.js",
	"/exchange/app.js", "/exchange/js/app.js", "/exchange/js/config.js",
	"/currency/app.js", "/currency/js/config.js",
	"/atm/app.js", "/atm/js/config.js",
	"/branch/app.js", "/branch/js/config.js",
	"/kyc/app.js", "/kyc/js/config.js", "/kyc/js/app.js",
	"/verification/app.js", "/verification/js/app.js",
	"/onboarding/app.js", "/onboarding/js/app.js",
	"/pos/app.js", "/pos/js/app.js", "/pos/js/config.js",
	"/invoice/app.js", "/invoice/js/app.js",

	// ── Umico specific patterns ────────────────────────────────────────────────
	"/umico/app.js", "/umico/main.js", "/umico/js/app.js",
	"/umico/js/config.js", "/umico/js/api.js",
	"/marketplace/app.js", "/marketplace/main.js",
	"/marketplace/js/app.js", "/marketplace/js/config.js",
	"/marketplace/js/api.js", "/marketplace/js/checkout.js",
	"/market/app.js", "/market/main.js", "/market/js/app.js",
	"/market/js/config.js", "/market/js/api.js",
	"/shop/app.js", "/shop/main.js", "/shop/js/app.js",
	"/shop/js/config.js", "/shop/js/api.js", "/shop/js/cart.js",
	"/shop/js/checkout.js", "/shop/js/payment.js",
	"/store/app.js", "/store/main.js", "/store/js/app.js",
	"/store/js/config.js", "/store/js/api.js",
	"/catalog/app.js", "/catalog/main.js", "/catalog/js/app.js",
	"/catalog/js/config.js", "/catalog/js/api.js",
	"/category/app.js", "/category/js/app.js",
	"/product/app.js", "/product/main.js", "/product/js/app.js",
	"/product/js/config.js", "/product/js/api.js",
	"/products/app.js", "/products/js/app.js",
	"/cart/app.js", "/cart/main.js", "/cart/js/app.js",
	"/cart/js/config.js", "/cart/js/api.js",
	"/checkout/app.js", "/checkout/main.js", "/checkout/js/app.js",
	"/checkout/js/config.js", "/checkout/js/api.js",
	"/checkout/js/payment.js", "/checkout/js/shipping.js",
	"/order/app.js", "/order/main.js", "/order/js/app.js",
	"/order/js/config.js", "/order/js/api.js",
	"/orders/app.js", "/orders/js/app.js", "/orders/js/config.js",
	"/delivery/app.js", "/delivery/js/app.js", "/delivery/js/config.js",
	"/shipping/app.js", "/shipping/js/app.js",
	"/tracking/app.js", "/tracking/js/app.js", "/tracking/js/config.js",
	"/review/app.js", "/review/js/app.js",
	"/reviews/app.js", "/reviews/js/app.js",
	"/seller/app.js", "/seller/js/app.js", "/seller/js/config.js",
	"/vendor/app.js", "/vendor/js/app.js", "/vendor/js/config.js",
	"/buyer/app.js", "/buyer/js/app.js",
	"/wishlist/app.js", "/wishlist/js/app.js",
	"/favorites/app.js", "/favorites/js/app.js",
	"/comparison/app.js", "/comparison/js/app.js",
	"/search/app.js", "/search/main.js", "/search/js/app.js",
	"/search/js/config.js", "/search/js/api.js",
	"/filter/app.js", "/filter/js/app.js",
	"/sort/app.js", "/sort/js/app.js",
	"/recommendation/app.js", "/recommendation/js/app.js",
	"/promo/app.js", "/promo/js/app.js", "/promo/js/config.js",
	"/banner/app.js", "/banner/js/app.js",
	"/coupon/app.js", "/coupon/js/app.js",
	"/discount/app.js", "/discount/js/app.js",
	"/loyalty/app.js", "/loyalty/js/app.js", "/loyalty/js/config.js",
	"/points/app.js", "/points/js/app.js",
	"/bonus/app.js", "/bonus/js/app.js", "/bonus/js/config.js",
	"/cashback/app.js", "/cashback/js/app.js",
	"/offer/app.js", "/offer/js/app.js",
	"/deals/app.js", "/deals/js/app.js",
	"/campaign/app.js", "/campaign/js/app.js",

	// ── Finance / fintech general ──────────────────────────────────────────────
	"/fintech/app.js", "/fintech/js/app.js", "/fintech/js/config.js",
	"/finance/app.js", "/finance/js/app.js", "/finance/js/config.js",
	"/insurance/app.js", "/insurance/js/app.js",
	"/credit/app.js", "/credit/js/app.js", "/credit/js/config.js",
	"/scoring/app.js", "/scoring/js/app.js",
	"/analytics/app.js", "/analytics/js/app.js", "/analytics/js/config.js",
	"/report/app.js", "/report/js/app.js",
	"/reports/app.js", "/reports/js/app.js",
	"/budget/app.js", "/budget/js/app.js",
	"/expense/app.js", "/expense/js/app.js",

	// ── Auth / user ────────────────────────────────────────────────────────────
	"/login/app.js", "/login/main.js", "/login/js/app.js",
	"/login/js/config.js", "/login/js/auth.js",
	"/logout/app.js", "/logout/js/app.js",
	"/register/app.js", "/register/main.js", "/register/js/app.js",
	"/register/js/config.js",
	"/signup/app.js", "/signup/js/app.js",
	"/auth/app.js", "/auth/main.js", "/auth/js/app.js",
	"/auth/js/config.js", "/auth/js/api.js",
	"/user/app.js", "/user/main.js", "/user/js/app.js",
	"/user/js/config.js", "/user/js/api.js",
	"/users/app.js", "/users/js/app.js",
	"/profile/app.js", "/profile/main.js", "/profile/js/app.js",
	"/profile/js/config.js", "/profile/js/api.js",
	"/account/app.js", "/account/js/app.js",
	"/dashboard/app.js", "/dashboard/main.js", "/dashboard/js/app.js",
	"/dashboard/js/config.js", "/dashboard/js/api.js",
	"/home/app.js", "/home/main.js", "/home/js/app.js",
	"/home/js/config.js",
	"/settings/app.js", "/settings/js/app.js", "/settings/js/config.js",
	"/notifications/app.js", "/notifications/js/app.js",
	"/support/app.js", "/support/js/app.js",
	"/help/app.js", "/help/js/app.js",
	"/contact/app.js", "/contact/js/app.js",
	"/faq/app.js", "/faq/js/app.js",
	"/about/app.js", "/about/js/app.js",

	// ── Angular / Vue / React named chunks ────────────────────────────────────
	"/main-es2015.js", "/main-es5.js", "/polyfills-es2015.js", "/polyfills-es5.js",
	"/runtime-es2015.js", "/runtime-es5.js", "/vendor-es2015.js", "/vendor-es5.js",
	"/scripts-es2015.js", "/common-es2015.js", "/lazy-module.js",
	"/chunk-vendors.js", "/chunk-common.js", "/chunk-app.js",
	"/chunk-common.js", "/chunk-vendors.js",
	"/js/chunk-vendors.js", "/js/chunk-common.js", "/js/chunk-app.js",
	"/static/js/chunk-vendors.js", "/static/js/chunk-common.js",
	"/assets/js/chunk-vendors.js", "/assets/js/chunk-common.js",
	"/ng/main.js", "/ng/runtime.js", "/ng/polyfills.js",
	"/ng/vendor.js", "/ng/scripts.js", "/ng/styles.js",
	"/vue/app.js", "/vue/config.js",
	"/react/app.js", "/react/config.js",

	// ── CDN / versioned paths ─────────────────────────────────────────────────
	"/cdn/js/app.js", "/cdn/js/main.js", "/cdn/js/bundle.js",
	"/cdn/js/vendor.js", "/cdn/assets/js/app.js",
	"/s/js/app.js", "/s/js/main.js", "/s/js/bundle.js",
	"/media/js/app.js", "/media/js/main.js",
	"/files/js/app.js", "/files/js/main.js",
	"/resources/js/app.js", "/resources/js/main.js",
	"/resources/js/config.js", "/resources/js/api.js",
	"/resource/js/app.js", "/resource/js/config.js",
	"/content/js/app.js", "/content/js/main.js",
	"/uploads/js/app.js", "/uploads/js/config.js",

	// ── Version-specific (/v1 - /v4) ──────────────────────────────────────────
	"/v1/static/js/main.js", "/v1/static/js/bundle.js",
	"/v1/assets/js/app.js", "/v1/js/config.js",
	"/v2/static/js/main.js", "/v2/static/js/bundle.js",
	"/v2/assets/js/app.js", "/v2/js/config.js",
	"/v3/static/js/main.js", "/v3/assets/js/app.js",
	"/v4/app.js", "/v4/js/app.js",
	"/api/v1/js/config.js", "/api/v2/js/config.js",
	"/api/v1/static/js/main.js", "/api/v2/static/js/main.js",

	// ── Env-specific builds ────────────────────────────────────────────────────
	"/env.development.js", "/env.staging.js", "/env.production.js",
	"/env.local.js", "/env.test.js",
	"/config.production.js", "/config.staging.js", "/config.development.js",
	"/config.local.js", "/config.test.js",
	"/settings.production.js", "/settings.staging.js",
	"/constants.production.js", "/constants.staging.js",

	// ── Libraries / third-party ───────────────────────────────────────────────
	"/lib/app.js", "/lib/main.js", "/lib/bundle.js",
	"/lib/jquery.min.js", "/lib/bootstrap.min.js",
	"/lib/vue.min.js", "/lib/react.min.js", "/lib/angular.min.js",
	"/lib/lodash.min.js", "/lib/axios.min.js", "/lib/moment.min.js",
	"/lib/js/app.js", "/lib/js/main.js", "/lib/js/config.js",
	"/libs/app.js", "/libs/main.js", "/libs/jquery.min.js",
	"/plugins/app.js", "/plugins/main.js", "/plugins/js/app.js",
	"/plugins/payment.js", "/plugins/checkout.js",
	"/vendor/js/app.js", "/vendor/js/main.js",
	"/vendor/js/jquery.min.js", "/vendor/js/bootstrap.min.js",
	"/vendors/js/app.js", "/vendors/js/main.js",
	"/third-party/js/app.js", "/third-party/js/config.js",
	"/external/js/app.js", "/external/js/config.js",

	// ── Mobile / PWA ──────────────────────────────────────────────────────────
	"/pwa/app.js", "/pwa/main.js", "/pwa/js/app.js",
	"/pwa/js/config.js", "/pwa/service-worker.js",
	"/sw.js", "/service-worker.js", "/workbox.js",
	"/manifest.js", "/app-manifest.js",
	"/ios/app.js", "/ios/js/app.js",
	"/android/app.js", "/android/js/app.js",
	"/react-native/app.js",

	// ── Microservices / BFF ───────────────────────────────────────────────────
	"/bff/app.js", "/bff/js/app.js", "/bff/js/config.js",
	"/gateway/app.js", "/gateway/js/app.js",
	"/proxy/app.js", "/proxy/js/app.js",
	"/middleware/app.js", "/middleware/js/app.js",
	"/integration/app.js", "/integration/js/app.js",
	"/webhook/app.js", "/webhook/js/app.js",

	// ── Monitoring / analytics ────────────────────────────────────────────────
	"/gtm.js", "/gtag.js", "/analytics.js", "/pixel.js",
	"/metrics/app.js", "/metrics/js/config.js",
	"/telemetry/app.js", "/telemetry/js/config.js",
	"/monitoring/app.js", "/monitoring/js/config.js",
	"/sentry/app.js", "/sentry/js/config.js",
	"/logger/app.js", "/logger/js/config.js",
	"/log/app.js", "/log/js/config.js",

	// ── Miscellaneous patterns seen in AZ fintech / e-commerce ───────────────
	"/frontend/app.js", "/frontend/main.js", "/frontend/js/app.js",
	"/frontend/js/config.js", "/frontend/static/js/main.js",
	"/backend/app.js", "/backend/js/app.js",
	"/web/app.js", "/web/main.js", "/web/js/app.js",
	"/web/js/config.js", "/web/static/js/main.js",
	"/portal/app.js", "/portal/main.js", "/portal/js/app.js",
	"/portal/js/config.js",
	"/crm/app.js", "/crm/js/app.js", "/crm/js/config.js",
	"/erp/app.js", "/erp/js/app.js",
	"/cms/app.js", "/cms/js/app.js",
	"/landing/app.js", "/landing/js/app.js",
	"/lp/app.js", "/lp/js/app.js",
	"/promo/js/app.js",
	"/event/app.js", "/event/js/app.js",
	"/events/app.js", "/events/js/app.js",
	"/news/app.js", "/news/js/app.js",
	"/blog/app.js", "/blog/js/app.js",
	"/career/app.js", "/career/js/app.js",
	"/jobs/app.js", "/jobs/js/app.js",
	"/press/app.js", "/press/js/app.js",
	"/legal/app.js", "/legal/js/app.js",
	"/terms/app.js", "/terms/js/app.js",
	"/privacy/app.js", "/privacy/js/app.js",
	"/sitemap/app.js",
	"/404/app.js", "/error/app.js", "/500/app.js",

	// ── Hash / contenthash chunk patterns (generic) ────────────────────────────
	"/static/js/main.abcdef12.js",
	"/static/js/bundle.abcdef12.js",
	"/static/js/vendors~main.abcdef12.chunk.js",
	"/assets/js/app.abcdef12.js",
	"/dist/js/bundle.abcdef12.js",
	"/_next/static/abcdef12/pages/index.js",

	// ── Common framework manifests / maps ──────────────────────────────────────
	"/asset-manifest.json", "/precache-manifest.js",
	"/workbox-precaching.js", "/workbox-routing.js",
	"/workbox-strategies.js",

	// ── Internationalisation / locale shims (common in AZ region) ─────────────
	"/i18n/az.js", "/i18n/ru.js", "/i18n/en.js",
	"/locales/az.js", "/locales/ru.js", "/locales/en.js",
	"/lang/az.js", "/lang/ru.js", "/lang/en.js",
	"/translations/app.js", "/translations/az.js",
	"/locale/app.js", "/locale/az.js",
}

func BruteJSPaths(liveHosts []string, pathFilter string) []string {
	var found []string
	var mu sync.Mutex

	if pathFilter != "" {
		if strings.HasPrefix(pathFilter, "http") {
			// Extract path from full URL
			if strings.Count(pathFilter, "/") >= 3 {
				parts := strings.SplitN(pathFilter, "/", 4)
				if len(parts) > 3 {
					pathFilter = "/" + parts[3]
				} else {
					pathFilter = ""
				}
			} else {
				pathFilter = ""
			}
		}

		if pathFilter != "" && !strings.HasPrefix(pathFilter, "/") {
			pathFilter = "/" + pathFilter
		}
		pathFilter = strings.TrimRight(pathFilter, "/")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: core.GlobalConfig.Insecure},
		MaxIdleConns:    200,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	sem := make(chan struct{}, core.GlobalConfig.Threads*2)
	var wg sync.WaitGroup

	core.Logf("  %s→%s  Brute-force %d common JS paths...\n", core.MAGENTA, core.RESET, len(CommonJSPaths))

	for _, host := range liveHosts {
		host = strings.TrimRight(host, "/")
		for _, path := range CommonJSPaths {
			fullPath := pathFilter + path
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Use GET instead of HEAD so we can read body for HTML if needed
				req, err := http.NewRequest("GET", urlStr, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")
				resp, err := client.Do(req)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						ct := resp.Header.Get("Content-Type")
						if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") || strings.HasSuffix(urlStr, ".js") {
							mu.Lock()
							found = append(found, urlStr)
							mu.Unlock()
						} else if strings.Contains(ct, "text/html") {
							bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
							if err == nil && len(bodyBytes) > 0 {
								htmlStr := string(bodyBytes)
								srcs := parseScriptTags(urlStr, htmlStr)
								if len(srcs) > 0 {
									mu.Lock()
									found = append(found, srcs...)
									mu.Unlock()
								}
							}
						}
					}
				}
			}(host + fullPath)
		}
	}

	wg.Wait()
	return found
}
