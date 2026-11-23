//! Scan-library issue-selection vocabulary: Burp's issue type categories
//! and the "Issues reported" filter. The filter's check-registry-dependent
//! queries stay in the core as `crate::scan_library::filter_allows` and
//! `crate::scan_library::filter_unsupported_selection`.

use serde_json::Value;

/// The value at a dotted key path.
pub fn get_path<'a>(tree: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(tree, |v, k| v.get(k))
}

/// Burp writes issue type ids as `"0x00100200"` strings; a number is
/// accepted too.
pub fn parse_type_index(v: Option<&Value>) -> Option<u32> {
    match v? {
        Value::String(s) => {
            let t = s.trim();
            match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u32::from_str_radix(h, 16).ok(),
                None => t.parse().ok(),
            }
        }
        Value::Number(n) => n.as_u64().and_then(|n| u32::try_from(n).ok()),
        _ => None,
    }
}

/// Burp's scan type categories (burp.Zglb) as bits.
pub const CAT_PASSIVE: u8 = 1;
pub const CAT_LIGHT: u8 = 2;
pub const CAT_MEDIUM: u8 = 4;
pub const CAT_INTRUSIVE: u8 = 8;
pub const CAT_JAVASCRIPT: u8 = 16;
pub const CAT_ACTIVE: u8 = CAT_LIGHT | CAT_MEDIUM | CAT_INTRUSIVE;

/// Each Burp issue type's scan type categories (burp.Zcot's constructor:
/// type index, then `EnumSet<Zglb>`; one of passive / light / medium /
/// intrusive, optionally with JavaScript, asserted in Zcot:238).
pub const BURP_ISSUE_CATEGORIES: [(u32, u8); 183] = [
    (0x00100100, 4),  // OS_COMMAND_INJECTION
    (0x00100200, 8),  // SQL_INJECTION
    (0x00100210, 8),  // SQL_INJECTION_2ND_ORDER
    (0x00100280, 4),  // ASP_NET_TRACING_ENABLED
    (0x00100300, 8),  // FILE_PATH_TRAVERSAL
    (0x00100400, 4),  // XML_EXTERNAL_ENTITY_INJECTION
    (0x00100500, 8),  // LDAP_INJECTION
    (0x00100600, 8),  // XPATH_INJECTION
    (0x00100700, 8),  // XML_INJECTION
    (0x00100800, 4),  // ASP_NET_DEBUGGING_ENABLED
    (0x00100850, 2),  // BROKEN_ACCESS_CONTROL
    (0x00100900, 8),  // HTTP_PUT_METHOD_IS_ENABLED
    (0x00100a00, 4),  // OUT_OF_BAND_RESOURCE_LOAD_HTTP
    (0x00100b00, 4),  // FILE_PATH_MANIPULATION
    (0x00100c00, 4),  // PHP_CODE_INJECTION
    (0x00100d00, 8),  // SERVER_SIDE_JAVASCRIPT_CODE_INJECTION
    (0x00100e00, 4),  // PERL_CODE_INJECTION
    (0x00100f00, 4),  // RUBY_CODE_INJECTION
    (0x00100f10, 4),  // PYTHON_CODE_INJECTION
    (0x00100f20, 4),  // EXPRESSION_LANGUAGE_ENGINE_INJECTION
    (0x00101000, 8),  // UNIDENTIFIED_CODE_INJECTION
    (0x00101080, 4),  // SERVER_SIDE_TEMPLATE_ENGINE_INJECTION
    (0x00101100, 8),  // SSI_INJECTION
    (0x00101200, 4),  // NEXTJS_REACT2SHELL_RCE
    (0x00200100, 4),  // XSS_STORED
    (0x00200140, 8),  // REQUEST_SMUGGLING
    (0x00200141, 8),  // CLIENT_SIDE_DESYNC
    (0x00200180, 8),  // WEB_CACHE_POISONING
    (0x00200200, 4),  // HTTP_RESPONSE_HEADER_INJECTION_REFLECTED
    (0x00200300, 4),  // XSS_REFLECTED
    (0x00200308, 4),  // CLIENT_SIDE_TEMPLATE_ENGINE_INJECTION
    (0x00200310, 17), // XSS_DOM_BASED
    (0x00200311, 20), // XSS_REFLECTED_DOM_BASED
    (0x00200312, 20), // XSS_STORED_DOM_BASED
    (0x00200316, 17), // CLIENT_SIDE_PROTOTYPE_POLLUTION
    (0x00200320, 17), // JAVASCRIPT_INJECTION_DOM_BASED
    (0x00200321, 20), // JAVASCRIPT_INJECTION_REFLECTED_DOM_BASED
    (0x00200322, 20), // JAVASCRIPT_INJECTION_STORED_DOM_BASED
    (0x00200328, 2),  // PATH_RELATIVE_STYLESHEET_IMPORT
    (0x00200330, 17), // CLIENT_SIDE_SQL_INJECTION_DOM_BASED
    (0x00200331, 20), // CLIENT_SIDE_SQL_INJECTION_REFLECTED_DOM_BASED
    (0x00200332, 20), // CLIENT_SIDE_SQL_INJECTION_STORED_DOM_BASED
    (0x00200340, 17), // WEBSOCKET_URL_POISONING_DOM_BASED
    (0x00200341, 20), // WEBSOCKET_URL_POISONING_REFLECTED_DOM_BASED
    (0x00200342, 20), // WEBSOCKET_URL_POISONING_STORED_DOM_BASED
    (0x00200350, 17), // LOCAL_FILE_PATH_MANIPULATION_DOM_BASED
    (0x00200351, 20), // LOCAL_FILE_PATH_MANIPULATION_REFLECTED_DOM_BASED
    (0x00200352, 20), // LOCAL_FILE_PATH_MANIPULATION_STORED_DOM_BASED
    (0x00200360, 17), // CLIENT_SIDE_XPATH_INJECTION_DOM_BASED
    (0x00200361, 20), // CLIENT_SIDE_XPATH_INJECTION_REFLECTED_DOM_BASED
    (0x00200362, 20), // CLIENT_SIDE_XPATH_INJECTION_STORED_DOM_BASED
    (0x00200370, 17), // CLIENT_SIDE_JSON_INJECTION_DOM_BASED
    (0x00200371, 20), // CLIENT_SIDE_JSON_INJECTION_REFLECTED_DOM_BASED
    (0x00200372, 20), // CLIENT_SIDE_JSON_INJECTION_STORED_DOM_BASED
    (0x00200400, 2),  // FLASH_CROSS_DOMAIN_POLICY
    (0x00200500, 2),  // SILVERLIGHT_CROSS_DOMAIN_POLICY
    (0x00200503, 1),  // CONTENT_SECURITY_POLICY_ALLOWLISTED_SCRIPTS
    (0x00200504, 1),  // CONTENT_SECURITY_POLICY_UNTRUSTED_SCRIPTS
    (0x00200505, 1),  // CONTENT_SECURITY_POLICY_UNTRUSTED_STYLES
    (0x00200506, 1),  // CONTENT_SECURITY_POLICY_MALFORMED_SYNTAX
    (0x00200507, 1),  // CONTENT_SECURITY_POLICY_ALLOW_CLICKJACKING
    (0x00200508, 1),  // CONTENT_SECURITY_POLICY_ALLOW_FORM_HIGHJACKING
    (0x00200509, 1),  // CONTENT_SECURITY_POLICY_NOT_ENFORCED
    (0x00200510, 1),  // GRAPHQL_ENDPOINT_FOUND
    (0x00200511, 2),  // GRAPHQL_ENDPOINT_DISCOVERED
    (0x00200512, 2),  // GRAPHQL_INTROSPECTION_ENABLED
    (0x00200513, 2),  // GRAPHQL_SUGGESTIONS_ENABLED
    (0x00200514, 2),  // GRAPHQL_CONTENT_TYPE_NOT_VALIDATED
    (0x00200600, 2),  // CROSS_ORIGIN_RESOURCE_SHARING
    (0x00200601, 2),  // CROSS_ORIGIN_RESOURCE_SHARING_ARBITRARY_ORIGIN
    (0x00200602, 2),  // CROSS_ORIGIN_RESOURCE_SHARING_UNTRUSTED_ORIGIN_TRUSTED
    (0x00200603, 2),  // CROSS_ORIGIN_RESOURCE_SHARING_ALL_SUBDOMAINS_TRUSTED
    (0x00200650, 4),  // WEB_CACHE_DECEPTION
    (0x00200700, 4),  // CROSS_SITE_REQUEST_FORGERY
    (0x00200800, 4),  // SMTP_HEADER_INJECTION
    (0x00200900, 4),  // JWT_SIGNATURE_NOT_VERIFIED
    (0x00200901, 4),  // JWT_NONE_ALG_SUPPORTED
    (0x00200902, 4),  // JWT_JWK_HEADER_SUPPORTED
    (0x00200903, 1),  // JWT_WEAK_HMAC_SECRET
    (0x00200904, 4),  // JWT_JKU_HEADER_SUPPORTED
    (0x00200905, 4),  // JWT_X5U_HEADER_SUPPORTED
    (0x00300100, 1),  // CLEARTEXT_SUBMISSION_OF_PASSWORD
    (0x00300200, 4),  // EXTERNAL_SERVICE_INTERACTION_DNS
    (0x00300210, 4),  // EXTERNAL_SERVICE_INTERACTION_HTTP
    (0x00300220, 4),  // EXTERNAL_SERVICE_INTERACTION_SMTP
    (0x00400100, 2),  // REFERER_DEPENDENT_RESPONSE
    (0x00400110, 2),  // SPOOFABLE_CLIENT_IP
    (0x00400120, 2),  // USER_AGENT_DEPENDENT_RESPONSE
    (0x00400200, 1),  // PASSWORD_RETURNED_IN_LATER_RESPONSE
    (0x00400300, 1),  // PASSWORD_SUBMITTED_USING_GET_METHOD
    (0x00400400, 1),  // PASSWORD_RETURNED_IN_URL_QUERY_STRING
    (0x00400480, 1),  // SQL_STATEMENT_IN_REQUEST_PARAMETER
    (0x00400500, 1),  // CROSS_DOMAIN_POST
    (0x00400600, 1),  // ASP_NET_VIEWSTATE_WITHOUT_MAC_ENABLED
    (0x00400700, 4),  // XML_ENTITY_EXPANSION
    (0x00400800, 1),  // LONG_REDIRECTION_RESPONSE
    (0x00400900, 1),  // SERIALIZED_OBJECT_IN_HTTP_MESSAGE
    (0x00400a00, 1),  // DUPLICATE_COOKIES_SET
    (0x00400b00, 2),  // INPUT_RETRIEVAL_STORED
    (0x00400c00, 2),  // INPUT_RETRIEVAL_REFLECTED
    (0x00400d00, 4),  // SUSPICIOUS_INPUT_TRANSFORMATION_REFLECTED
    (0x00400e00, 4),  // SUSPICIOUS_INPUT_TRANSFORMATION_STORED
    (0x00400f00, 8),  // REQUEST_URL_OVERRIDE
    (0x00500080, 1),  // VULNERABLE_JAVASCRIPT_DEPENDENCY
    (0x00500100, 4),  // OPEN_REDIRECTION_REFLECTED
    (0x00500101, 4),  // OPEN_REDIRECTION_STORED
    (0x00500110, 17), // OPEN_REDIRECTION_DOM_BASED
    (0x00500111, 20), // OPEN_REDIRECTION_REFLECTED_DOM_BASED
    (0x00500112, 20), // OPEN_REDIRECTION_STORED_DOM_BASED
    (0x00500200, 1),  // TLS_COOKIE_WITHOUT_SECURE_FLAG_SET
    (0x00500300, 1),  // COOKIE_SCOPED_TO_PARENT_DOMAIN
    (0x00500400, 1),  // CROSS_DOMAIN_REFERER_LEAKAGE
    (0x00500500, 1),  // CROSS_DOMAIN_SCRIPT_INCLUDE
    (0x00500600, 1),  // COOKIE_WITHOUT_HTTPONLY_FLAG
    (0x00500700, 1),  // SESSION_TOKEN_IN_URL
    (0x00500800, 1),  // PASSWORD_FIELD_WITH_AUTOCOMPLETE_ENABLED
    (0x00500900, 1),  // PASSWORD_VALUE_SET_IN_COOKIE
    (0x00500980, 1),  // FILE_UPLOAD_FUNCTIONALITY
    (0x005009a0, 1),  // FRAMEABLE_RESPONSE_POTENTIAL_CLICKJACKING
    (0x005009b0, 1),  // BROWSER_XSS_FILTER_DISABLED
    (0x00500a00, 4),  // HTTP_TRACE_METHOD_IS_ENABLED
    (0x00500b00, 17), // COOKIE_MANIPULATION_DOM_BASED
    (0x00500b01, 20), // COOKIE_MANIPULATION_REFLECTED_DOM_BASED
    (0x00500b02, 20), // COOKIE_MANIPULATION_STORED_DOM_BASED
    (0x00500c00, 17), // AJAX_REQUEST_HEADER_MANIPULATION_DOM_BASED
    (0x00500c01, 20), // AJAX_REQUEST_HEADER_REFLECTED_MANIPULATION_DOM_BASED
    (0x00500c02, 20), // AJAX_REQUEST_HEADER_STORED_MANIPULATION_DOM_BASED
    (0x00500d00, 17), // DENIAL_OF_SERVICE_DOM_BASED
    (0x00500d01, 20), // DENIAL_OF_SERVICE_REFLECTED_DOM_BASED
    (0x00500d02, 20), // DENIAL_OF_SERVICE_STORED_DOM_BASED
    (0x00500e00, 17), // HTML5_WEB_MESSAGE_MANIPULATION_DOM_BASED
    (0x00500e01, 20), // HTML5_WEB_MESSAGE_MANIPULATION_REFLECTED_DOM_BASED
    (0x00500e02, 20), // HTML5_WEB_MESSAGE_MANIPULATION_STORED_DOM_BASED
    (0x00500f00, 17), // HTML5_STORAGE_MANIPULATION_DOM_BASED
    (0x00500f01, 20), // HTML5_STORAGE_MANIPULATION_REFLECTED_DOM_BASED
    (0x00500f02, 20), // HTML5_STORAGE_MANIPULATION_STORED_DOM_BASED
    (0x00501000, 17), // LINK_MANIPULATION_DOM_BASED
    (0x00501001, 20), // LINK_MANIPULATION_REFLECTED_DOM_BASED
    (0x00501002, 20), // LINK_MANIPULATION_STORED_DOM_BASED
    (0x00501003, 4),  // LINK_MANIPULATION_REFLECTED
    (0x00501004, 4),  // LINK_MANIPULATION_STORED
    (0x00501100, 17), // DOCUMENT_DOMAIN_MANIPULATION_DOM_BASED
    (0x00501101, 20), // DOCUMENT_DOMAIN_MANIPULATION_REFLECTED_DOM_BASED
    (0x00501102, 20), // DOCUMENT_DOMAIN_MANIPULATION_STORED_DOM_BASED
    (0x00501200, 17), // DOM_DATA_MANIPULATION_DOM_BASED
    (0x00501201, 20), // DOM_DATA_MANIPULATION_REFLECTED_DOM_BASED
    (0x00501202, 20), // DOM_DATA_MANIPULATION_STORED_DOM_BASED
    (0x00501300, 4),  // CSS_INJECTION_REFLECTED
    (0x00501301, 4),  // CSS_INJECTION_STORED
    (0x00501400, 4),  // CLIENT_SIDE_HTTP_PARAMETER_POLLUTION_REFLECTED
    (0x00501401, 4),  // CLIENT_SIDE_HTTP_PARAMETER_POLLUTION_STORED
    (0x00501500, 4),  // FORM_ACTION_HIJACKING_REFLECTED
    (0x00501501, 4),  // FORM_ACTION_HIJACKING_STORED
    (0x00600080, 1),  // DATABASE_CONNECTION_STRING_DISCLOSED
    (0x006000b0, 1),  // SOURCE_CODE_DISCLOSURE
    (0x006000d8, 4),  // BACKUP_FILE
    (0x00600100, 1),  // DIRECTORY_LISTING
    (0x00600200, 1),  // EMAIL_ADDRESSES_DISCLOSED
    (0x00600300, 1),  // PRIVATE_IP_ADDRESSES_DISCLOSED
    (0x00600400, 1),  // SOCIAL_SECURITY_NUMBERS_DISCLOSED
    (0x00600500, 1),  // CREDIT_CARD_NUMBERS_DISCLOSED
    (0x00600550, 1),  // PRIVATE_KEY_DISCLOSED
    (0x00600600, 2),  // ROBOTS_TXT_FILE
    (0x00600700, 2),  // JWK_DISCLOSED
    (0x00600800, 1),  // JWT_PRIVATE_KEY_DISCLOSURE
    (0x00600900, 2),  // OPENAPI_DEFINITION_FOUND_ACTIVE
    (0x00600901, 1),  // OPENAPI_DEFINITION_FOUND_PASSIVE
    (0x00700100, 1),  // CACHEABLE_HTTPS_RESPONSE
    (0x00700200, 1),  // BASE_64_ENCODED_DATA_IN_PARAMETER
    (0x00800100, 1),  // MULTIPLE_CONTENT_TYPES_SPECIFIED
    (0x00800200, 1),  // HTML_DOES_NOT_SPECIFY_CHARSET
    (0x00800300, 1),  // HTML_USES_UNRECOGNIZED_CHARSET
    (0x00800400, 1),  // CONTENT_TYPE_INCORRECTLY_STATED
    (0x00800500, 1),  // CONTENT_TYPE_NOT_SPECIFIED
    (0x01000100, 2),  // TLS_CERTIFICATE
    (0x01000200, 1),  // UNENCRYPTED_COMMUNICATIONS
    (0x01000300, 1),  // STRICT_TRANSPORT_SECURITY_NOT_ENFORCED
    (0x01000400, 1),  // MIXED_CONTENT
    (0x01000500, 2),  // HIDDEN_HTTP2
    (0x08000000, 8),  // EXTENSION_GENERATED
    (0x08008000, 8),  // MANUALLY_GENERATED
    (0x09000000, 8),  // BCHECK_GENERATED
    (0x09008000, 8),  // BAMBDA_GENERATED
];

/// The categories of Burp issue type `id`.
pub fn issue_categories(id: u32) -> Option<u8> {
    BURP_ISSUE_CATEGORIES
        .binary_search_by_key(&id, |(t, _)| *t)
        .ok()
        .map(|i| BURP_ISSUE_CATEGORIES[i].1)
}

/// The "Issues reported" part of a configuration: which issue types a scan
/// may run checks for and report.
#[derive(Clone, Debug, PartialEq)]
pub struct IssueFilter {
    /// The scan_type_* switches as CAT_* bits.
    pub types_on: u8,
    /// With select_individual_issues: each listed type id and whether it
    /// is enabled (unlisted types are off).
    pub selected: Option<std::collections::BTreeMap<u32, bool>>,
}

impl IssueFilter {
    /// The filter a combined tree describes; None when it allows every
    /// issue (Burp's default), so a scan without a library selection runs
    /// exactly as before.
    pub fn from_tree(tree: &Value) -> Option<IssueFilter> {
        let flag = |k: &str| {
            get_path(tree, &format!("scanner.issues_reported.{k}"))
                .and_then(Value::as_bool)
                .unwrap_or(true)
        };
        let types_on = [
            ("scan_type_passive", CAT_PASSIVE),
            ("scan_type_light_active", CAT_LIGHT),
            ("scan_type_medium_active", CAT_MEDIUM),
            ("scan_type_intrusive_active", CAT_INTRUSIVE),
            ("scan_type_javascript_analysis", CAT_JAVASCRIPT),
        ]
        .iter()
        .filter(|(k, _)| flag(k))
        .fold(0u8, |m, (_, b)| m | b);
        let individual = get_path(tree, "scanner.issues_reported.select_individual_issues")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let selected = individual.then(|| {
            get_path(tree, "scanner.issues_reported.selected_issues")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|it| {
                            Some((
                                parse_type_index(it.get("type_index"))?,
                                it.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default()
        });
        let f = IssueFilter { types_on, selected };
        (f != IssueFilter {
            types_on: CAT_PASSIVE | CAT_ACTIVE | CAT_JAVASCRIPT,
            selected: None,
        })
        .then_some(f)
    }

    /// Whether issue type `id` is on. Without an individual selection this
    /// is burp.Zr0a.ZY: a type is off when every category it has is
    /// switched off (JavaScript is never in that set), and any JavaScript
    /// type is off when JavaScript analysis is. A type Burp does not
    /// categorise (`categories` None) counts as `fallback`.
    pub fn allows_type(&self, id: u32, fallback: u8) -> bool {
        if let Some(sel) = &self.selected {
            return sel.get(&id).copied().unwrap_or(false);
        }
        let cats = issue_categories(id).unwrap_or(fallback);
        let off = !self.types_on & (CAT_PASSIVE | CAT_ACTIVE);
        if cats & CAT_JAVASCRIPT == 0 && cats & off == cats {
            return false;
        }
        if self.types_on & CAT_JAVASCRIPT == 0 && cats & CAT_JAVASCRIPT != 0 {
            return false;
        }
        true
    }
}

/// Whether checks for the issue named `name` may run and report under the
/// filter. `active` says which kind of check asks, for issue types Burp does
/// not have (WebProbe's own checks): active ones run while any active
/// scan type is on, passive ones while passive is; an individual
/// selection never includes them.
pub fn filter_allows(f: &IssueFilter, name: &str, active: bool) -> bool {
    let id = crate::issues::issue_type_id(name) as u32;
    if id == 0 {
        return f.selected.is_none()
            && f.types_on & if active { CAT_ACTIVE } else { CAT_PASSIVE } != 0;
    }
    f.allows_type(id, if active { CAT_ACTIVE } else { CAT_PASSIVE })
}

// ------------------------------------------------------------------ check lookup

static TYPE_CHECKS: std::sync::OnceLock<fn(u32) -> bool> = std::sync::OnceLock::new();

/// Register the check-catalogue lookup used to flag selected issue types no
/// check reports (called once at app startup; unregistered keeps selections).
pub fn register_type_checks(f: fn(u32) -> bool) {
    let _ = TYPE_CHECKS.set(f);
}

/// Whether any check reports the issue type (true while unregistered).
pub fn type_has_checks(id: u32) -> bool {
    TYPE_CHECKS.get().map(|f| f(id)).unwrap_or(true)
}
