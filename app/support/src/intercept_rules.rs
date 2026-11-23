// Proxy request interception rules.
//
// Burp decides which requests the Intercept tab holds with an ordered rule
// table (Settings > Tools > Proxy > Request interception rules): each row has
// an operator (And / Or, ignored on the first enabled row), a match type, a
// relationship and a condition, and the enabled rows are combined top to
// bottom. The defaults are Burp's: only "File extension does not match
// (^gif$|^jpg$|...)" is ticked.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    And,
    Or,
}

/// What a rule looks at. The regex kinds match case-insensitively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    DomainName,
    Url,
    FileExtension,
    HttpMethod,
    AnyHeader,
    Body,
    /// "Request | Contains parameters".
    HasParameters,
    /// "URL | Is in target scope".
    InScope,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::DomainName,
        Kind::Url,
        Kind::FileExtension,
        Kind::HttpMethod,
        Kind::AnyHeader,
        Kind::Body,
        Kind::HasParameters,
        Kind::InScope,
    ];

    /// Burp's "Match type" column.
    pub fn match_type(self) -> &'static str {
        match self {
            Kind::DomainName => "Domain name",
            Kind::Url | Kind::InScope => "URL",
            Kind::FileExtension => "File extension",
            Kind::HttpMethod => "HTTP method",
            Kind::AnyHeader => "Any header",
            Kind::Body => "Body",
            Kind::HasParameters => "Request",
        }
    }

    /// Burp's "Relationship" column for this kind and sense.
    pub fn relationship(self, negate: bool) -> &'static str {
        match (self, negate) {
            (Kind::HasParameters, false) => "Contains parameters",
            (Kind::HasParameters, true) => "Does not contain parameters",
            (Kind::InScope, false) => "Is in target scope",
            (Kind::InScope, true) => "Is not in target scope",
            (_, false) => "Matches",
            (_, true) => "Does not match",
        }
    }

    /// Whether the rule has a regex condition.
    pub fn takes_condition(self) -> bool {
        !matches!(self, Kind::HasParameters | Kind::InScope)
    }

    /// Label for the kind chooser.
    pub fn label(self) -> &'static str {
        match self {
            Kind::HasParameters => "Request (parameters)",
            Kind::InScope => "URL (target scope)",
            other => other.match_type(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InterceptRule {
    pub enabled: bool,
    pub operator: Operator,
    pub kind: Kind,
    pub negate: bool,
    #[serde(default)]
    pub condition: String,
}

/// Burp's default request interception rules.
pub fn defaults() -> Vec<InterceptRule> {
    vec![
        InterceptRule {
            enabled: true,
            operator: Operator::And,
            kind: Kind::FileExtension,
            negate: true,
            condition: "(^gif$|^jpg$|^png$|^css$|^js$|^ico$|^svg$|^eot$|^woff$|^woff2$|^ttf$)"
                .into(),
        },
        InterceptRule {
            enabled: false,
            operator: Operator::Or,
            kind: Kind::HasParameters,
            negate: false,
            condition: String::new(),
        },
        InterceptRule {
            enabled: false,
            operator: Operator::Or,
            kind: Kind::HttpMethod,
            negate: true,
            condition: "(get|post)".into(),
        },
        InterceptRule {
            enabled: false,
            operator: Operator::And,
            kind: Kind::InScope,
            negate: false,
            condition: String::new(),
        },
    ]
}

/// What the rules can see of a request.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Facts {
    pub domain: String,
    pub url: String,
    pub method: String,
    /// Extension of the URL's file name, without the dot; empty for none.
    pub extension: String,
    /// The header block as text.
    pub headers: String,
    pub body: String,
    pub has_parameters: bool,
    pub in_scope: bool,
}

/// The file extension of a request target: the part after the last dot of
/// the last path segment, query and fragment ignored.
pub fn extension_of(target: &str) -> String {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.')
        .map(|(_, e)| e.to_string())
        .unwrap_or_default()
}

fn regex_hit(condition: &str, text: &str) -> bool {
    regex::RegexBuilder::new(condition)
        .case_insensitive(true)
        .build()
        .map(|re| re.is_match(text))
        .unwrap_or(false)
}

impl InterceptRule {
    /// Whether this single rule holds for the request.
    pub fn holds(&self, f: &Facts) -> bool {
        let positive = match self.kind {
            Kind::DomainName => regex_hit(&self.condition, &f.domain),
            Kind::Url => regex_hit(&self.condition, &f.url),
            Kind::FileExtension => regex_hit(&self.condition, &f.extension),
            Kind::HttpMethod => regex_hit(&self.condition, &f.method),
            Kind::AnyHeader => regex_hit(&self.condition, &f.headers),
            Kind::Body => regex_hit(&self.condition, &f.body),
            Kind::HasParameters => f.has_parameters,
            Kind::InScope => f.in_scope,
        };
        positive != self.negate
    }
}

/// Whether the request should be held: the enabled rules combined top to
/// bottom with their operators (the first enabled rule's operator is
/// ignored). With no enabled rule every request is held.
pub fn should_intercept(rules: &[InterceptRule], facts: &Facts) -> bool {
    let mut result: Option<bool> = None;
    for rule in rules.iter().filter(|r| r.enabled) {
        let v = rule.holds(facts);
        result = Some(match (result, rule.operator) {
            (None, _) => v,
            (Some(acc), Operator::And) => acc && v,
            (Some(acc), Operator::Or) => acc || v,
        });
    }
    result.unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(method: &str, target: &str) -> Facts {
        Facts {
            domain: "app.test".into(),
            url: format!("http://app.test{target}"),
            method: method.into(),
            extension: extension_of(target),
            has_parameters: target.contains('?'),
            ..Default::default()
        }
    }

    #[test]
    fn defaults_hold_everything_except_static_file_types() {
        let rules = defaults();
        assert_eq!(rules.iter().filter(|r| r.enabled).count(), 1);
        for held in [
            "/login",
            "/api/users?id=app.js",
            "/assets/site.css.map",
            "/",
        ] {
            assert!(should_intercept(&rules, &facts("GET", held)), "{held}");
        }
        for skipped in [
            "/assets/site.CSS?version=2",
            "/app.js#main",
            "/logo.png",
            "/f.woff2",
        ] {
            assert!(
                !should_intercept(&rules, &facts("GET", skipped)),
                "{skipped}"
            );
        }
        assert_eq!(
            [
                extension_of("/a/b.tar.gz?x=1.png"),
                extension_of("/a.b/c"),
                extension_of("/x.JS")
            ],
            ["gz", "", "JS"]
        );
    }

    #[test]
    fn rows_combine_top_to_bottom_with_their_operators() {
        let mut rules = defaults();
        // File extension rule AND "URL is in target scope".
        rules[3].enabled = true;
        let mut f = facts("GET", "/login");
        assert!(!should_intercept(&rules, &f));
        f.in_scope = true;
        assert!(should_intercept(&rules, &f));
        // Add "OR HTTP method does not match (get|post)": a PUT to a .png is
        // held even though the extension rule alone would skip it...
        rules[3].enabled = false;
        rules[2].enabled = true;
        assert!(should_intercept(&rules, &facts("PUT", "/logo.png")));
        assert!(!should_intercept(&rules, &facts("get", "/logo.png")));
        // ...and with the scope rule ANDed after it, order matters:
        // (ext OR method) AND scope.
        rules[3].enabled = true;
        assert!(!should_intercept(&rules, &facts("PUT", "/logo.png")));
        // The first enabled row's operator is ignored.
        let only_or = vec![InterceptRule {
            enabled: true,
            operator: Operator::Or,
            kind: Kind::HasParameters,
            negate: false,
            condition: String::new(),
        }];
        assert!(should_intercept(&only_or, &facts("GET", "/s?q=1")));
        assert!(!should_intercept(&only_or, &facts("GET", "/s")));
        // No enabled rule: hold everything.
        assert!(should_intercept(&[], &facts("GET", "/logo.png")));
    }

    #[test]
    fn regex_kinds_match_case_insensitively_and_bad_patterns_never_match() {
        let rule = |kind, negate, condition: &str| InterceptRule {
            enabled: true,
            operator: Operator::And,
            kind,
            negate,
            condition: condition.into(),
        };
        let mut f = facts("POST", "/admin/save");
        f.headers = "Host: app.test\r\nX-Requested-With: XMLHttpRequest\r\n".into();
        f.body = "name=a&ROLE=admin".into();
        assert!(rule(Kind::DomainName, false, "^APP\\.").holds(&f));
        assert!(rule(Kind::Url, false, "/admin/").holds(&f));
        assert!(rule(Kind::AnyHeader, false, "xmlhttprequest").holds(&f));
        assert!(rule(Kind::Body, false, "role=admin").holds(&f));
        assert!(rule(Kind::HttpMethod, true, "(get|head)").holds(&f));
        assert!(!rule(Kind::Url, false, "(unclosed").holds(&f));
        assert!(rule(Kind::Url, true, "(unclosed").holds(&f));
        assert_eq!(
            (Kind::InScope.match_type(), Kind::InScope.relationship(true)),
            ("URL", "Is not in target scope")
        );
        assert_eq!(
            (
                Kind::FileExtension.match_type(),
                Kind::FileExtension.relationship(true)
            ),
            ("File extension", "Does not match")
        );
        assert!(!Kind::HasParameters.takes_condition() && Kind::Body.takes_condition());
    }
}
