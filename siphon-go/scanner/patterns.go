package scanner

var FalsePositiveRe = `(?i)(application/(json|xml|javascript|x-www-form-urlencoded)|text/(html|plain|xml|javascript)|image/(png|jpeg|gif|svg\+xml)|charset|utf-8|content-type|border-[a-z]+|background-[a-z]+|font-[a-z]+|box-shadow|text-align|margin-[a-z]+|padding-[a-z]+|display:\s*(none|block|inline)|position:\s*(absolute|relative)|index\.js|main\.js|vendor\.js|app\.js|bundle\.js|/api/v\d+/|/oauth/token|/auth/login|/users/|/products/|/api/public|jquery|bootstrap|angular|react|vue|moment|lodash|localhost|127\.0\.0\.1)`

var SecretPatterns = map[string]string{
	"Google API Key":     `AIza[0-9A-Za-z\-_]{35}`,
	"AWS Access Key":     `AKIA[0-9A-Z]{16}`,
	"AWS Secret Key":     `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`,
	"Slack Token":        `xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}`,
	"Stripe Standard API":`sk_live_[0-9a-zA-Z]{24}`,
	"Stripe Restricted":  `rk_live_[0-9a-zA-Z]{24}`,
	"GitHub Token":       `ghp_[0-9a-zA-Z]{36}`,
	"Twilio API Key":     `SK[0-9a-fA-F]{32}`,
	"SendGrid API Key":   `SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}`,
	"Firebase URL":       `.*firebaseio\.com`,
	"RSA Private Key":    `-----BEGIN RSA PRIVATE KEY-----`,

	// NEW BANKING PATTERNS
	"Credit Card (PAN)":        `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b`,
	"IBAN (European format)":   `\b[A-Z]{2}[0-9]{2}(?:[ ]?[0-9a-zA-Z]{4}){4,7}[ ]?[0-9a-zA-Z]{1,2}\b`,
	"Internal IP (10.x.x.x)":   `\b10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}\b`,
	"Internal IP (192.168.x.x)":`\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b`,
	"Internal IP (172.16-31)":  `\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}\b`,
	"SWIFT / BIC Code":         `\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`,
	"Extended JWT Token":       `\b(?:ey[a-zA-Z0-9_-]{2,}\.ey[a-zA-Z0-9_-]{2,}\.[a-zA-Z0-9_-]{2,})\b`,
	"Azure DB Connection":      `(?i)Server=tcp:[^;]+;Database=[^;]+;User ID=[^;]+;Password=[^;]+;`,
	"AWS ElastiCache Redis":    `(?i)[a-z0-9.-]+\.cache\.amazonaws\.com:[0-9]{4}`,
	"Oracle DB JDBC String":    `(?i)jdbc:oracle:thin:[^:]+/[^@]+@[^:]+:[0-9]+:[a-z0-9]+`,
}

var PatternEntropy = map[string]float64{
	"Google API Key": 3.0,
	"AWS Access Key": 3.0,
	"Slack Token":    3.0,
	"Extended JWT Token": 4.0,
	"AWS Secret Key": 3.5,
}

var DefaultEntropy = 0.0

var BankingKeywordList = []string{
	"username", "password", "passwd", "pwd", "auth", "authentication", "api_key",
	"apikey", "secret", "token", "access_token", "refresh_token", "jwt",
	"iban", "swift", "swift_code", "bic", "bic_code", "sort_code", "routing_number",
	"account_number", "account_no", "acct_no", "biller_code", "payee", "pan",
	"cvv", "cvc", "card_number", "credit_card", "debit_card", "expiry_date",
	"pin", "pin_code", "atm_pin", "balance", "balance_amt", "transaction_id",
	"txn_id", "payment_token", "cardholder_name", "kyc", "kyc_token", "aml",
	"core_banking", "cbs_url", "teller_id", "branch_id", "teller_password",
	"swift_gateway", "fincore", "finacle", "flexcube", "t24", "temenos",
	"otp", "otp_secret", "mfa", "mfa_secret", "2fa", "2fa_seed", "totp",
	"sms_token", "verification_code", "db_user", "db_pass", "db_password",
	"database_url", "redis_url", "mongo_url", "sql_conn", "jdbc_url", "aws_secret",
	"aws_key", "azure_key", "gcp_key", "s3_bucket", "azure_blob", "admin",
	"admin_pass", "admin_user", "root_pass", "superuser", "ssn", "social_security",
	"national_id", "passport_no", "driver_license", "client_id", "client_secret",
	"oauth_token", "bearer_token", "private_key", "public_key", "ssl_cert",
	"cert_password", "keystore_pass", "truststore_pass", "account", "customer_id",
	"cid", "card_expiry", "card_token", "vault_key", "enc_key", "aes_key",
	"des_key", "rsa_key", "mac_key", "pgp_key", "ssh_key", "api_token", "api_secret",
	"app_secret", "app_key", "session_id", "session_token", "cookie_secret",
	"csrf_token", "xsrf_token", "webhook_secret", "slack_token", "twilio_token",
	"sendgrid_key", "mailgun_key", "stripe_key", "paypal_secret", "braintree_key",
	"adyen_key", "square_key", "plaid_secret", "plaid_client", "yodlee_secret",
	"finicity_key", "mastercard_key", "visa_api", "amex_key", "discover_api",
	"western_union", "moneygram", "crypto_key", "wallet_key", "blockchain_api",
	"eth_key", "btc_key", "contract_address", "infura_key", "alchemy_key",
	"moralis_key", "binance_api", "coinbase_api", "kraken_api", "ftx_api",
	"kucoin_api", "huobi_api", "okx_api", "bitfinex_api", "bitstamp_api",
	"gemini_api", "bybit_api", "deribit_api", "paxos_api", "circle_api",
	"tether_api", "usdc_api", "dai_api", "maker_api", "compound_api",
	"aave_api", "uniswap_api", "sushiswap_api", "pancakeswap_api", "1inch_api",
	"curve_api", "balancer_api", "yearn_api", "synthetix_api", "chainlink_api",
	"band_api", "graph_api", "api_url", "api_endpoint", "graphql_url",
	"rest_url", "soap_url", "grpc_url", "rpc_url", "ws_url", "wss_url",
	"socket_url", "mqtt_url", "amqp_url", "kafka_url", "rabbitmq_url",
	"redis_host", "memcached_host", "elastic_host", "kibana_host", "logstash_host",
	"splunk_host", "datadog_key", "newrelic_key", "dynatrace_key", "appdynamics_key",
	"sentry_dsn", "bugsnag_key", "rollbar_token", "raygun_key", "loggly_token",
	"papertrail_port", "sumologic_url", "mixpanel_token", "segment_key",
	"amplitude_key", "heap_id", "hotjar_id", "fullstory_org", "google_maps_key",
	"bing_maps_key", "mapbox_token", "here_app_id", "tomtom_key", "foursquare_id",
	"yelp_key", "zomato_key", "uber_token", "lyft_token", "doordash_key",
	"postmates_key", "grubhub_key", "instacart_key", "shipt_key", "gopuff_key",
	"deliveroo_key", "glovo_key", "rappi_key", "swiggy_key", "zomato_key",
	"foodpanda_key", "talabat_key", "noon_key", "amazon_key", "ebay_key",
	"walmart_key", "target_key", "bestbuy_key", "homedepot_key", "lowes_key",
	"costco_key", "walgreens_key", "cvs_key", "riteaid_key", "kroger_key",
	"albertsons_key", "safeway_key", "publix_key", "heb_key", "meijer_key",
	"wegmans_key", "aldi_key", "lidl_key", "traderjoes_key", "wholefoods_key",
	"sprouts_key", "freshmarket_key", "marianos_key", "jewelosco_key", "vons_key",
	"pavilions_key", "randalls_key", "tomthumb_key", "carrs_key", "acme_key",
	"shaw_key", "starmarket_key", "unitedsupermarkets_key", "marketstreet_key",
	"amigos_key", "albertsonsmarket_key", "safeway_key", "vons_key", "pavilions_key",
	"randalls_key", "tomthumb_key", "carrs_key", "acme_key", "shaws_key",
	"starmarket_key", "united_supermarkets_key", "market_street_key", "amigos_key",
	"albertsons_market_key", "lucky_key", "savemart_key", "foodmax_key", "smartfinal_key",
	"groceryoutlet_key", "winco_key", "staterbros_key", "ralphs_key", "food4less_key",
	"bank_api", "bank_secret", "bank_token", "bank_key", "bank_pass",
	"merchant_id", "merchant_key", "merchant_secret", "terminal_id", "pos_id",
	"acquirer_id", "issuer_id", "bin_number", "card_brand", "card_type",
	"funding_source", "payment_method", "payment_gateway", "payment_processor",
	"clearing_house", "settlement_bank", "correspondent_bank", "intermediary_bank",
	"beneficiary_bank", "originating_bank", "receiving_bank", "sending_bank",
	"wire_transfer", "ach_transfer", "sepa_transfer", "rtgs_transfer", "chaps_transfer",
	"bacs_transfer", "fps_transfer", "zelle_transfer", "venmo_transfer", "cashapp_transfer",
	"paypal_transfer", "applepay_transfer", "googlepay_transfer", "samsungpay_transfer",
}

func GetBankingKeywordRegex() string {
	// Optimizes to: (?i)\b(username|password|...)\b\s*[:=]\s*(['"])([^'"]{5,50})\2
	// This will find assignments to these keys.
	return `(?i)\b(` + strings.Join(BankingKeywordList, "|") + `)\b\s*[:=]\s*(['"])([^'"]{4,80})\2`
}
