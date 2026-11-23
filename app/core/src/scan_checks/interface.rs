use super::*;

// ---------------------------------------------------------------- interface

/// An active check that runs once per insertion point.
pub(crate) trait PointCheck: Sync {
    /// Stable identifier (exports, tests, future per-check settings).
    /// Check metadata: no runtime reader yet, only the registry tests.
    #[cfg_attr(not(test), allow(dead_code))]
    fn id(&self) -> &'static str;
    /// The issue it reports: Burp's KnowledgeBase name where the check is a
    /// Burp port, otherwise WebProbe's own wording (some WebProbe issues add
    /// the parameter name to it).
    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(&self) -> &'static str;
    /// The insertion-point kinds it applies to: the point-type rules of the
    /// Burp check's applicability test (`Zuit.Zh`). Every implementation
    /// matches every kind explicitly, so a new kind needs a decision.
    fn applies_to(&self, ip: &InsertionPoint) -> bool;
    /// Whether the check is a server-side injection check, which Burp skips
    /// on the skip_server_side_injection_for_parameters list (its `Zh`
    /// calls `Zgx0.Zr`; [`InsertionPoint::skips_server_side`]).
    fn server_side(&self) -> bool;
    /// Audit one insertion point. Reports through `cx.report`.
    fn run(&self, cx: &ScanCtx, st: &mut ScanState, pt: &mut PointRun);
}

/// How often a request-level check runs. Check metadata: the once-per-host
/// bookkeeping itself stays inside those checks (`ScanDedup::openapi_hosts`).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    /// Once per audited request.
    Request,
    /// Once per host (and scan run, see `ScanDedup`).
    Host,
}

/// An active check that runs once per request (or per host), after the
/// insertion-point checks.
pub(crate) trait RequestCheck: Sync {
    /// As [`PointCheck::id`].
    #[cfg_attr(not(test), allow(dead_code))]
    fn id(&self) -> &'static str;
    /// As [`PointCheck::issue`].
    #[cfg_attr(not(test), allow(dead_code))]
    fn issue(&self) -> &'static str;
    #[cfg_attr(not(test), allow(dead_code))]
    fn scope(&self) -> Scope;
    /// Checks in the same group share one stop gate: the group runs when the
    /// scan was not stopped as its first member was reached, and every member
    /// then runs (a member may still look at the stop flag itself). Checks
    /// without a group test the stop flag in `run`.
    fn group(&self) -> Option<&'static str> {
        None
    }
    fn run(&self, cx: &ScanCtx);
}

/// Insertion-point checks, in run order.
pub(crate) static POINT_CHECKS: &[&dyn PointCheck] = &[
    &LightProbes,
    &ExternalInteraction,
    &OsCommandInjection,
    &PathTraversal,
    &LinkManipulation,
    &FilePathManipulation,
    &SsiInjection,
    &TemplateInjection,
    &ReflectedXss,
    &ClientTemplateInjection,
    &PhpCodeInjection,
    &InputReflected,
    &HeaderInjection,
    &OpenRedirect,
    &SqlErrorInjection,
    &SqlBooleanInjection,
    &XmlInjectionOob,
    &XmlInjectionError,
    &LdapInjection,
    &SmtpHeaderInjection,
    &StoredEcho,
    &JwtAttacks,
    &ExpressionLanguageInjection,
    &XPathInjection,
];

/// Request-level and host-level checks, in run order.
pub(crate) static REQUEST_CHECKS: &[&dyn RequestCheck] = &[
    &Cors,
    &PathRelativeStyleSheet,
    &TraceEnabled,
    &OpenApiDefinition,
    &CollaboratorEverywhere,
    &ServerTrace,
    &ServerOptions,
    &HeaderManipulation,
    &XxeFileRead,
    &CsrfTokenNotEnforced,
    &HttpPutEnabled,
    &AspNetTracing,
    &AspNetDebugging,
    &GraphqlIntrospection,
    &GraphqlSuggestions,
    &GraphqlContentType,
    &SpoofableClientIp,
    &BackupFile,
    &GraphqlEndpointDiscovered,
    &cache::WebCachePoisoning,
    &cache::WebCacheDeception,
];

/// Whether `check` audits `ip` under `config`: the point type suits it,
/// it is switched on, and a server-side check leaves the points on Burp's
/// skip_server_side_injection_for_parameters list alone.
pub(crate) fn check_applies(
    check: &dyn PointCheck,
    ip: &InsertionPoint,
    config: &crate::scan_config::ScanConfig,
) -> bool {
    check.applies_to(ip)
        && config.check_enabled(check.id())
        && !(check.server_side() && ip.skips_server_side())
}
