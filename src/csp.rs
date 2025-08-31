//! [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
//! implementation for Kvarn.
//!
//! See [`Csp`] for details on how to use this.

use crate::extensions::RuleSet;
use crate::prelude::*;
use std::collections::BTreeMap;

macro_rules! csp_rules {
    (
        $(
            $(#[$docs:meta])*
            ($directive:ident, $default:expr, $($name:expr)+)
        )+
    ) => {
        /// A rule for [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
        /// which covers all directives.
        #[derive(Debug, Clone)]
        #[must_use]
        pub struct Rule {
            $($directive: ValueSet,)+
            undefined: BTreeMap<CompactString, ValueSet>,
        }
        impl Rule {
            /// Creates a new, **empty** CSP rule.
            /// Consider using [`Self::default`] to get sensible defaults, which **include**
            /// `default-src 'self'`.
            /// An empty rule means NO CSP header being sent.
            ///
            /// Populate it with the various directive methods.
            #[inline]
            pub fn empty() -> Self {
                Self {
                    $($directive: ValueSet::empty(),)+
                    undefined: BTreeMap::new(),
                }
            }
            $(
                #[doc = "Overrides the directive described below."]
                #[doc = "By default, Kvarn protects against XSS attacks by sending some defaults."]
                #[doc = ""]
                #[doc = "# Panics"]
                #[doc = ""]
                #[doc = "May panic if [`CspValue::Uri`] contains invalid bytes."]
                #[doc = ""]
                #[doc = "# Info"]
                #[doc = ""]
                $(#[$docs])*
                #[inline]
                pub fn $directive(mut self, values: ValueSet) -> Self {
                    Self::check_values(&values.list);

                    self.$directive = values;
                    self
                }
            )+
            /// Adds a CSP directive with a name not currently tracked by Kvarn. This exists to be
            /// able to add new CSP directives before Kvarn adds options for them.
            ///
            /// # Panics
            ///
            /// May panic if [`CspValue::Uri`] contians invalid bytes.
            pub fn string(mut self, csp_directive_name: impl Into<String>, values: ValueSet) -> Self {
                self.undefined.insert(csp_directive_name.into().to_compact_string(), values);
                self
            }

            /// Returns [`None`] if all the directives are empty.
            /// Else, returns a list of all directives and their values.
            #[must_use]
            pub fn to_header(&self) -> Option<HeaderValue> {
                self.to_header_nonce(None)
            }
            /// Returns [`None`] if all the directives are empty.
            /// Else, returns a list of all directives and their values.
            ///
            /// This also takes an optional `nonce` to be applied.
            /// If it is supplied, a `nonce-<random 128-bit value encoded using Base64>`
            /// is added to [`Self::script_src`], [`Self::script_src_elem`], [`Self::style_src`],
            /// and [`Self::style_src_elem`].
            ///
            /// # Warnings
            ///
            /// Warns (log) if `nonce` is not valid UTF-8. It should be encoded in Base64!
            #[must_use]
            pub fn to_header_nonce(&self, nonce: Option<&HeaderValue>) -> Option<HeaderValue> {
                use bytes::BufMut;
                // `TODO`: Optimize to use only 1 allocation.
                // This should be fine for now, as this shouldn't have very many rules, but it
                // would be optimal.
                // This could be done by creating a iter of all the fields of this struct and
                // flattening the iter with the iter of respective values to use the `utils::join`
                // fn.

                let mut len = 0;
                let mut empty = true;

                {
                    $(
                        $(
                            {
                                let me_len = if self.$directive.list.is_empty() {
                                    0
                                } else {
                                    $name.len() + 2
                                };
                                len += self
                                    .$directive
                                    .list
                                    .iter()
                                    .map(|value| value.as_str().len() + 1)
                                    .sum::<usize>() + me_len;

                                if !self.$directive.list.is_empty() {
                                    empty = false;
                                }
                            }
                        )+
                    )+
                }

                {
                    for (directive, sources) in &self.undefined {
                        let me_len = if sources.list.is_empty() {
                            0
                        } else {
                            directive.len() + 2
                        };
                        len += sources
                            .list
                            .iter()
                            .map(|value| value.as_str().len() + 1)
                            .sum::<usize>() + me_len;

                        if !sources.list.is_empty() {
                            empty = false;
                        }
                    }
                }

                if nonce.is_some() {
                    empty = false;
                    len += "script-src".len() + "style-src".len() + "script-src-elem".len() + "style-src-elem".len()
                        + 4 * (3 + 6 + 24 + " 'self'".len() + 3);
                    // 3 is the space and quotes, 6 is the `nonce-`, 24 is the value, and 3 is for good measure.
                    // 'self' is often added, so it's taken into account
                }

                if empty {
                    return None;
                }

                let mut bytes = BytesMut::with_capacity(len);

                {
                    $(
                        let special = {
                            nonce.is_some() &&
                            (
                            $(
                                $name == "script-src" || $name == "style-src" || $name == "script-src-elem" || $name == "style-src-elem" ||
                            )+
                            // or false
                            false
                            )
                        };
                        if !self.$directive.list.is_empty() || special {
                            // get the actual header
                            let mut s = utils::join(self.$directive.list.iter().map(CspValue::as_str), " ");
                            // pushing this to the HeaderValue is OK, since it originates from a
                            // header value.
                            if special {
                                // UNWRAP: for `special` to be `true`, nonce must satisfy `.is_some`.
                                if let Ok(nonce) = nonce.as_ref().unwrap().to_str() {
                                    if !s.is_empty() {
                                        s.push(' ');
                                    }else {
                                        s.push_str("'self' ");
                                    }

                                    s.push_str("'nonce-");
                                    s.push_str(nonce);
                                    s.push('\'');
                                } else {
                                    warn!("Read bad `csp-nonce` header. It must be valid UTF-8.");
                                }
                            }
                            // this usually only happens once, write to the rule in the CSP
                            // report-to and report-url are aliases, so two are ran here.
                            $(
                                if !bytes.is_empty() {
                                    bytes.put_slice(b"; ");
                                }
                                bytes.put($name.as_bytes());
                                bytes.put_u8(chars::SPACE);
                                bytes.put(s.as_bytes());
                            )+
                        }
                    )+
                }
                {
                    for (directive, sources) in &self.undefined {
                        if !sources.list.is_empty() {
                            // pushing this to the HeaderValue is OK, since it originates from a
                            // header value.
                            // this usually only happens once, write to the rule in the CSP
                            // report-to and report-url are aliases, so two are ran here.
                            if !bytes.is_empty() {
                                bytes.put_slice(b"; ");
                            }
                            bytes.put(directive.as_bytes());
                            bytes.put_u8(chars::SPACE);
                            for source in &sources.list {
                                bytes.put(source.as_str().as_bytes());
                                bytes.put_u8(chars::SPACE);
                            }
                        }
                    }
                }

                // SAFETY: This is safe because of the contract on adding of `CspValue`s always
                // containing valid bytes.
                // See [`CspRule::check_values`], which is called whenever any new values are added
                // here.
                let header = unsafe { HeaderValue::from_maybe_shared_unchecked(bytes) };
                Some(header)
            }
        }
        /// Gives `content-security-policy: default-src 'self'; style-src 'self' 'unsafe-inline'`.
        impl Default for Rule {
            fn default() -> Self {
                CspRule {
                    $($directive: $default,)+
                    undefined: BTreeMap::new(),
                }
            }
        }
    };
}

csp_rules! {
    /// Fallback for frame-src and worker-src.
    ///
    /// Defines the valid sources for web workers and nested browsing contexts loaded using elements such as `<frame>` and `<iframe>`.
    (child_src, ValueSet::empty(), "child-src")

    /// Restricts the URLs which can be loaded using script interfaces
    (connect_src, ValueSet::empty(), "connect-src")

    /// Serves as a fallback for the other fetch directives.
    (default_src, ValueSet::default(), "default-src")

    /// Specifies valid sources for fonts loaded using @font-face.
    (font_src, ValueSet::empty(), "font-src")

    /// Specifies valid sources for nested browsing contexts loading using elements such as `<frame>` and `<iframe>`.
    (frame_src, ValueSet::empty(), "frame-src")

    /// Specifies valid sources of images and favicons.
    (img_src, ValueSet::empty(), "img-src")

    /// Specifies valid sources of application manifest files.
    (manifest_src, ValueSet::empty(), "manifest-src")

    /// Specifies valid sources for loading media using the `<audio>`, `<video>` and `<track>` elements.
    (media_src, ValueSet::empty(), "media-src")

    /// Specifies valid sources for the `<object>`, `<embed>`, and `<applet>` elements.
    ///
    /// > Note: Elements controlled by object-src are perhaps coincidentally considered legacy HTML elements and are not receiving new standardized features (such as the security attributes sandbox or allow for `<iframe>`). Therefore it is recommended to restrict this fetch-directive (e.g., explicitly set object-src 'none' if possible).
    (object_src, ValueSet::empty(), "object-src")

    /// Specifies valid sources to be prefetched or prerendered.
    (prefetch_src, ValueSet::empty(), "prefetch-src")

    /// Fallback for all script_*.
    ///
    /// Specifies valid sources for JavaScript.
    (script_src, ValueSet::empty(), "script-src")

    /// Specifies valid sources for JavaScript `<script>` elements.
    (script_src_elem, ValueSet::empty(), "script-src-elem")

    /// Specifies valid sources for JavaScript inline event handlers.
    (script_src_attr, ValueSet::empty(), "script-src-attr")

    /// Fallback for all style_*.
    ///
    /// Specifies valid sources for stylesheets.
    (style_src, ValueSet::default().unsafe_inline(), "style-src")

    /// Specifies valid sources for stylesheets `<style>` elements and `<link>` elements with rel="stylesheet".
    (style_src_elem, ValueSet::empty(), "style-src-elem")

    /// Specifies valid sources for inline styles applied to individual DOM elements.
    (style_src_attr, ValueSet::empty(), "style-src-attr")

    /// Specifies valid sources for `Worker`, `SharedWorker`, or `ServiceWorker` scripts.
    (worker_src, ValueSet::empty(), "worker-src")

    /// Restricts the URLs which can be used in a document's `<base>` element.
    (base_uri, ValueSet::empty(), "base-uri")

    /// Enables a sandbox for the requested resource similar to the `<iframe>` sandbox attribute.
    (sandbox, ValueSet::empty(), "sandbox")

    /// Restricts the URLs which can be used as the target of a form submissions from a given context.
    (form_action, ValueSet::empty(), "form-action")

    /// Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`.
    (frame_ancestors, ValueSet::empty(), "frame-ancestors")

    /// Restricts the URLs to which a document can initiate navigation by any means, including `<form>` (if form-action is not specified), `<a>`, window.location, window.open, etc.
    (navigate_to, ValueSet::empty(), "navigate-to")

    /// Instructs the user agent to report attempts to violate the Content Security Policy. These [violation reports](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#violation_report_syntax) consist of JSON documents sent via an HTTP `POST` request to the specified URI.
    ///
    /// Use [`CspValue::Uri`] as `value` to supply the path of the violation report endpoint.
    (report, ValueSet::empty(), "report-to" "report-uri")

    /// Requires the use of SRI for scripts or styles on the page.
    (require_sri_for, ValueSet::empty(), "require-sri-for")

    /// Enforces Trusted Types at the DOM XSS injection sinks.
    (require_trusted_types_for, ValueSet::empty(), "require-trused-types-for")

    /// Used to specify an allow-list of Trusted Types policies. Trusted Types allows applications to lock down DOM XSS injection sinks to only accept non-spoofable, typed values in place of strings.
    (trusted_types, ValueSet::empty(), "trusted-types")

    /// Instructs user agents to treat all of a site's insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS). This directive is intended for web sites with large numbers of insecure legacy URLs that need to be rewritten.
    (upgrade_insecure_requests, ValueSet::empty(), "upgrade-insecure-requests")
}

impl Rule {
    /// Guarantees the [`CspValue`] can be converted into a [`HeaderValue`].
    ///
    /// The Scheme option can only contain bytes also valid in `HeaderValue`.
    /// This is part of the HTTP spec.
    fn check_values(values: &[Value]) {
        for byte in values
            .iter()
            .filter_map(|value| match value {
                Value::Uri(s) => Some(s.as_bytes().iter()),
                _ => None,
            })
            .flatten()
            .copied()
        {
            assert!(
                utils::is_valid_header_value_byte(byte),
                "Value of CspValue::Uri contains invalid bytes."
            );
        }
    }
}

/// The values for all directives in [`CspRule`].
///
/// See [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy#values) for more details.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
    /// `none`
    /// Won't allow loading of any resources.
    None,
    /// `self`,
    /// Only allow resources from the current origin.
    Same,
    /// `unsafe-inline`
    /// Allow use of inline resources.
    UnsafeInline,
    /// `unsafe-eval`
    /// Allow use of dynamic code evaluation such as eval, setImmediate, and window.execScript.
    UnsafeEval,
    /// `wasm-unsafe-eval`
    ///
    /// See <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#unsafe_webassembly_execution>
    WasmUnsafeEval,
    /// `strict-dynamic`
    ///
    /// See
    /// <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#strict-dynamic>
    StrictDynamic,
    /// `host`
    /// Only allow loading of resources from a specific host, with optional scheme, port, and path.
    ///
    /// Also used for [`CspRule::report`]. Then, only a path should be supplied.
    Uri(CompactString),
    /// Only allow loading of resources over a specific scheme, should always end with `:`. e.g. `https:`, `http:`, `data:` etc.
    Scheme(CompactString),
    /// Raw CSP rule, for when this enum doesn't provide an adequate alternative
    Raw(CompactString),
}
impl Value {
    /// Returns a string representing `self`.
    ///
    /// See [`CspValue`] for what will be returned.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "'none'",
            Self::Same => "'self'",
            Self::UnsafeInline => "'unsafe-inline'",
            Self::UnsafeEval => "'unsafe-eval'",
            Self::WasmUnsafeEval => "'wasm-unsafe-eval'",
            Self::StrictDynamic => "'strict-dynamic'",
            Self::Uri(s) => s,
            Self::Scheme(scheme) => scheme,
            Self::Raw(v) => v,
        }
    }
}

/// A set of [`Value`]s.
/// Makes it easier to build the [`Rule`].
#[must_use]
#[derive(Debug, Clone)]
pub struct ValueSet {
    list: Vec<Value>,
}
impl ValueSet {
    /// Creates a empty set of [`Value`]s.
    ///
    /// Consider using [`Default::default()`] instead,
    /// as it includes [`Value::Same`] which is almost always wanted.
    #[inline]
    pub fn empty() -> Self {
        Self { list: vec![] }
    }
    /// A set of [`Value`]s with only [`Value::None`].
    #[inline]
    pub fn none() -> Self {
        Self::empty().push(Value::None)
    }
    /// Adds [`Value::UnsafeInline`] to `self`.
    #[inline]
    pub fn unsafe_inline(self) -> Self {
        self.push(Value::UnsafeInline)
    }
    /// Adds [`Value::UnsafeEval`] to `self`.
    #[inline]
    pub fn unsafe_eval(self) -> Self {
        self.push(Value::UnsafeEval)
    }
    /// Adds [`Value::WasmUnsafeEval`] to `self`.
    #[inline]
    pub fn wasm_unsafe_eval(self) -> Self {
        self.push(Value::WasmUnsafeEval)
    }
    /// Adds [`Value::StrictDynamic`] to `self`.
    #[inline]
    pub fn strict_dynamic(self) -> Self {
        self.push(Value::StrictDynamic)
    }
    /// Adds `uri` to `self`.
    #[inline]
    pub fn uri(self, uri: impl Into<String>) -> Self {
        self.push(Value::Uri(uri.into().to_compact_string()))
    }
    /// Adds `scheme` to `self`.
    /// `scheme` has to end in `:`.
    ///
    /// # Panics
    ///
    /// Panics if `scheme` doesn't end with `:`.
    #[inline]
    pub fn scheme(self, scheme: impl Into<String>) -> Self {
        let s = scheme.into();
        assert!(s.ends_with(':'), "scheme has to end with ':'.");
        self.push(Value::Scheme(s.to_compact_string()))
    }
    /// Adds [`Value::Raw`] to `self`.
    /// `source_expression` has to be surrounded in single-quotes.
    #[inline]
    pub fn raw(self, source_expression: impl Into<String>) -> Self {
        let s = source_expression.into();
        assert!(
            s.starts_with('\'') && s.ends_with('\''),
            "source_expression has to start and end with '"
        );
        self.push(Value::Raw(s.to_compact_string()))
    }
    /// Pushes another `value` to the set of values of `self`.
    #[inline]
    pub fn push(mut self, value: Value) -> Self {
        self.list.push(value);
        self
    }
}
impl Default for ValueSet {
    fn default() -> Self {
        Self {
            list: vec![Value::Same],
        }
    }
}

/// A [Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy) ruleset.
///
/// See [`CspRule`] for directives and [`CspValue`] for the values you can set.
///
/// # Examples
///
/// ```
/// # use kvarn::prelude::*;
/// let mut extensions = Extensions::new();
/// extensions.with_csp(
///     Csp::default()
///         .add(
///             "*",
///             CspRule::default().img_src(CspValueSet::default().uri("https://kvarn.org")),
///         )
///         .arc(),
/// );
/// ```
pub type Csp = RuleSet<ComputedRule>;
impl Default for Csp {
    fn default() -> Self {
        Self::empty().add("/*", CspRule::default())
    }
}

/// A rule with the [`HeaderValue`] precomputed (unless you're using nonce).
#[derive(Clone)]
pub struct ComputedRule(pub Rule, Option<HeaderValue>);
impl Debug for ComputedRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl From<Rule> for ComputedRule {
    fn from(value: Rule) -> Self {
        let computed = value.to_header();
        Self(value, computed)
    }
}

impl Extensions {
    /// Sets the set of rules to handle
    /// [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy).
    pub fn with_csp(&mut self, csp: Arc<Csp>) -> &mut Self {
        self.add_package(
            package!(response, request, _host, _, move |csp: Arc<Csp>| {
                if let Some(rule) = csp.get(request.uri().path()) {
                    let nonce = response.headers().get("csp-nonce");
                    let some_nonce = nonce.is_some();
                    let header = if some_nonce {
                        rule.0.to_header_nonce(nonce)
                    } else {
                        rule.1.clone()
                    };
                    if let Some(header) = header {
                        if let Some(header) = response.headers().get("content-security-policy") {
                            warn!(
                                "Overriding current `content-security-policy` \
                                header: {:?} at page {:?}",
                                header,
                                request.uri()
                            );
                        }
                        response
                            .headers_mut()
                            .insert("content-security-policy", header);
                    }
                    if some_nonce {
                        utils::remove_all_headers(response.headers_mut(), "csp-nonce");
                    }
                }
            }),
            Id::new(128, "Add content security policy header"),
        );
        self
    }
}
