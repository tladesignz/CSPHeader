//
//  Directive.swift
//  CSPHeader
//
//  Created by Benjamin Erhart on 01.08.19.
//

import Foundation

/**
 [Spec](https://www.w3.org/TR/CSP2/#policy-syntax)
 */
@objc
public class Directive: NSObject {

    @objc
    public enum Name: Int, RawRepresentable {
        case baseUri
        case childSrc
        case connectSrc
        case defaultSrc
        case fontSrc
        case formAction
        case frameAncestors
        case frameSrc
        case imgSrc
        case mediaSrc
        case objectSrc
        case pluginTypes
        case reportUri
        case reportTo
        case sandbox
        case scriptSrc
        case styleSrc

        public typealias RawValue = String

        public var rawValue: String {
            switch self {
            case .baseUri:
                return "base-uri"
            case .childSrc:
                return "child-src"
            case .connectSrc:
                return "connect-src"
            case .defaultSrc:
                return "default-src"
            case .fontSrc:
                return "font-src"
            case .formAction:
                return "form-action"
            case .frameAncestors:
                return "frame-ancestors"
            case .frameSrc:
                return "frame-src"
            case .imgSrc:
                return "img-src"
            case .mediaSrc:
                return "media-src"
            case .objectSrc:
                return "object-src"
            case .pluginTypes:
                return "plugin-types"
            case .reportUri:
                return "report-uri"
            case .reportTo:
                return "report-to"
            case .sandbox:
                return "sandbox"
            case .scriptSrc:
                return "script-src"
            case .styleSrc:
                return "style-src"
            }
        }

        public init?(rawValue: String) {
            switch rawValue {
            case "base-uri":
                self = .baseUri
            case "child-src":
                self = .childSrc
            case "connect-src":
                self = .connectSrc
            case "default-src":
                self = .defaultSrc
            case "font-src":
                self = .fontSrc
            case "form-action":
                self = .formAction
            case "frame-ancestors":
                self = .frameAncestors
            case "frame-src":
                self = .frameSrc
            case "img-src":
                self = .imgSrc
            case "media-src":
                self = .mediaSrc
            case "object-src":
                self = .objectSrc
            case "plugin-types":
                self = .pluginTypes
            case "report-uri":
                self = .reportUri
            case "report-to":
                self = .reportTo
            case "sandbox":
                self = .sandbox
            case "script-src":
                self = .scriptSrc
            case "style-src":
                self = .styleSrc
            default:
                return nil
            }
        }
    }

    @objc
    public let name: String

    @objc
    private(set) public var sources: [Source]

    @objc
    public class func parse(_ token: String) -> Directive? {
        let pieces = token.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ")

        guard let name = pieces.first else {
            return nil
        }

        var sources = [Source]()

        for rawValue in pieces.dropFirst() {
            let source = String(rawValue)

            if let wellKnown = Source.Value(rawValue: source.lowercased()) {
                switch wellKnown {
                case .allHosts:
                    sources.append(HostSource(url: URL(string: wellKnown.rawValue)!))
                case .none:
                    sources.append(NoneSource())
                case .`self`:
                    sources.append(SelfSource())
                case .unsafeInline:
                    sources.append(UnsafeInlineSource())
                case .unsafeEval:
                    sources.append(UnsafeEvalSource())
                case .allowDownloadsWithoutUserActivation:
                    sources.append(AllowDownloadsWithoutUserActivationSource())
                case .allowForms:
                    sources.append(AllowFormsSource())
                case .allowModals:
                    sources.append(AllowModalsSource())
                case .allowOrientationLock:
                    sources.append(AllowOrientationLockSource())
                case .allowPointerLock:
                    sources.append(AllowPointerLockSource())
                case .allowPopups:
                    sources.append(AllowPopupsSource())
                case .allowPopupsToEscapeSandbox:
                    sources.append(AllowPopupsToEscapeSandboxSource())
                case .allowPresentation:
                    sources.append(AllowPresentationSource())
                case .allowSameOrigin:
                    sources.append(AllowSameOriginSource())
                case .allowScripts:
                    sources.append(AllowScriptsSource())
                case .allowStorageAccessByUserActivation:
                    sources.append(AllowStorageAccessByUserActivationSource())
                case .allowTopNavigation:
                    sources.append(AllowTopNavigationSource())
                case .allowTopNavigationByUserActivation:
                    sources.append(AllowTopNavigationByUserActivationSource())
                }
            }
            else if NonceSource.containsNonce(token: source) {
                sources.append(NonceSource(nonce: source))
            }
            else if HashSource.containsHash(token: source) {
                sources.append(HashSource(rawValue: source))
            }
            else if SchemeSource.containsScheme(token: source) {
                sources.append(SchemeSource(scheme: source))
            }
            else if let url = URL(string: source) {
                sources.append(HostSource(url: url))
            }
            else {
                sources.append(Source(source))
            }
        }

        // As per spec:
        //
        // > If source list is an ASCII case-insensitive match for the string
        // > 'none' (including the quotation marks), return the empty set.
        if sources.count == 1 && sources.first is NoneSource {
            sources = []
        }

        if let wellKnown = Name(rawValue: String(name).lowercased()) {
            switch wellKnown {
            case .baseUri:
                return BaseUriDirective(sources)
            case .childSrc:
                return ChildDirective(sources)
            case .connectSrc:
                return ConnectDirective(sources)
            case .defaultSrc:
                return DefaultDirective(sources)
            case .fontSrc:
                return FontDirective(sources)
            case .formAction:
                return FormActionDirective(sources)
            case .frameAncestors:
                return FrameAncestorsDirective(sources)
            case .frameSrc:
                return FrameDirective(sources)
            case .imgSrc:
                return ImgDirective(sources)
            case .mediaSrc:
                return MediaDirective(sources)
            case .objectSrc:
                return ObjectDirective(sources)
            case .pluginTypes:
                return PluginTypesDirective(sources)
            case .reportUri:
                return ReportUriDirective(sources)
            case .reportTo:
                return ReportToDirective(sources)
            case .sandbox:
                return SandboxDirective(sources)
            case .scriptSrc:
                return ScriptDirective(sources)
            case .styleSrc:
                return StyleDirective(sources)
            }
        }

        return Directive(name: String(name), sources)
    }


    public convenience init(name: String, _ sources: String...) {
        self.init(name: name, sources)
    }

    public convenience init(name: Name, _ sources: String...) {
        self.init(name: name.rawValue, sources)
    }

    @objc(initWithStringName:andSourceStrings:)
    public convenience init(name: String, _ sources: [String]) {
        self.init(name: name, sources.map { Source($0) })
    }

    @objc(initWithName:andSourceStrings:)
    public convenience init(name: Name, _ sources: [String]) {
        self.init(name: name.rawValue, sources)
    }

    public convenience init(name: String, _ sources: Source...) {
        self.init(name: name, sources)
    }

    public convenience init(name: Name, _ sources: Source...) {
        self.init(name: name, sources)
    }

    @objc(initWithStringName:andSources:)
    public init(name: String, _ sources: [Source]) {
        self.name = name
        self.sources = sources
    }

    @objc(initWithName:andSources:)
    public init(name: Name, _ sources: [Source]) {
        self.name = name.rawValue
        self.sources = sources
    }


    // MARK: NSObject

    @objc
    public override var hash: Int {
        return name.hashValue
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        guard let rhs = object as? Directive else {
            return false
        }

        return name == rhs.name
    }

    @objc
    public override var description: String {
        var token = [name]

        if sources.count > 0 {
            for source in sources {
                token.append(String(describing: source))
            }
        }
        else {
            // Return 'none' instead of the empty source list, which is equal
            // as per spec but looks less ambigous.
            token.append(String(describing: NoneSource()))
        }

        return token.joined(separator: " ")
    }


    // MARK: Public Methods

    @discardableResult
    public func append(_ sources: Source...) -> Directive {
        return append(sources)
    }

    @discardableResult
    @objc
    public func append(_ sources: [Source]) -> Directive {
        self.sources.append(contentsOf: sources)

        return self
    }

    @discardableResult
    public func prepend(_ sources: Source...) -> Directive {
        return prepend(sources)
    }

    @discardableResult
    @objc
    public func prepend(_ sources: [Source]) -> Directive {
        var newSources = [Source]()
        newSources.append(contentsOf: sources)
        newSources.append(contentsOf: self.sources)

        self.sources = newSources

        return self
    }

    @discardableResult
    public func replace(_ sources: Source...) -> Directive {
        return replace(sources)
    }

    @discardableResult
    @objc
    public func replace(_ sources: [Source]) -> Directive {
        self.sources = sources

        return self
    }

    @discardableResult
    public func remove(_ sources: Source...) -> Directive {
        return remove(sources)
    }

    @discardableResult
    @objc
    public func remove(_ sources: [Source]) -> Directive {
        self.sources.removeAll { sources.contains($0) }

        return self
    }

    @discardableResult
    @objc(removeSourceOfType:)
    public func remove(_ sourceType: Source.Type) -> Directive {
        self.sources.removeAll { type(of: $0) == sourceType }

        return self
    }

    @discardableResult
    @objc
    public func removeAll() -> Directive {
        return replace([])
    }

    @objc(containsSource:)
    public func contains(source: Source) -> Bool {
        return sources.contains(source)
    }

    @objc(containsSourceValue:)
    public func contains(source: Source.Value) -> Bool {
        return contains(source: Source(source))
    }

    @objc(containsSourceFromString:)
    public func contains(source: String) -> Bool {
        return contains(source: Source(source))
    }

    @objc(filter:)
    public func filter(_ isIncluded: (Source) -> Bool) -> [Source] {
        return sources.filter(isIncluded)
    }

    @objc(containsSourceOfType:)
    public func contains(a sourceType: Source.Type) -> Bool {
        return !(filter { type(of: $0) == sourceType }.isEmpty)
    }

    @objc
    public var isEmpty: Bool {
        return sources.isEmpty
    }
}

/**
 The base-uri directive restricts the URLs that can be used to specify the document base URL.

 Note: base-uri does not fall back to the default sources.

 https://www.w3.org/TR/CSP2/#directive-base-uri
 */
@objc
public class BaseUriDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .baseUri, sources)
    }
}

/**
 The child-src directive governs the creation of nested browsing contexts as well
 as Worker execution contexts.

 [Spec](https://www.w3.org/TR/CSP2/#directive-child-src)
 */
@objc
public class ChildDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .childSrc, sources)
    }
}

/**
 The connect-src directive restricts which URLs the protected resource can load
 using script interfaces.

 [Spec](https://www.w3.org/TR/CSP2/#directive-connect-src)
 */
@objc
public class ConnectDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .connectSrc, sources)
    }
}

/**
 The default-src directive sets a default source list for a number of directives.

 [Spec](https://www.w3.org/TR/CSP2/#directive-default-src")
 */
@objc
public class DefaultDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .defaultSrc, sources)
    }
}

/**
 The font-src directive restricts from where the protected resource can load fonts.

 [Spec](https://www.w3.org/TR/CSP2/#directive-font-src)
 */
@objc
public class FontDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .fontSrc, sources)
    }
}

/**
 The form-action restricts which URLs can be used as the action of HTML form elements.

 Note: form-action does not fall back to the default sources when the directive is not defined.
 That is, a policy that defines default-src 'none' but not form-action will still
 allow form submissions to any target.

 [Spec](https://www.w3.org/TR/CSP2/#directive-form-action)
 */
@objc
public class FormActionDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .formAction, sources)
    }
}

/**
 The frame-ancestors directive indicates whether the user agent should allow
 embedding the resource using a frame, iframe, object, embed or applet element,
 or equivalent functionality in non-HTML resources.

 Resources can use this directive to avoid many UI Redressing attacks by avoiding
 being embedded into potentially hostile contexts.

 Note: frame-ancestors does not fall back to the default sources when the
 directive is not defined. That is, a policy that defines default-src 'none' but
 not frame-ancestors will still allow the resource to be framed from anywhere.

 [Spec](https://www.w3.org/TR/CSP2/#directive-frame-ancestors)
 */
@objc
public class FrameAncestorsDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .frameAncestors, sources)
    }
}

/**
 The frame-src directive is deprecated. Authors who wish to govern nested browsing
 contexts SHOULD use the child-src directive instead.

 The frame-src directive restricts from where the protected resource can embed frames.

 [Spec](https://www.w3.org/TR/CSP2/#directive-frame-src)
 */
@objc
public class FrameDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .frameSrc, sources)
    }
}

/**
 The img-src directive restricts from where the protected resource can load images.

 [Spec](https://www.w3.org/TR/CSP2/#directive-img-src)
 */
@objc
public class ImgDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .imgSrc, sources)
    }
}

/**
 The media-src directive restricts from where the protected resource can load
 video, audio, and associated text tracks.

 [Spec](https://www.w3.org/TR/CSP2/#directive-media-src)
 */
@objc
public class MediaDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .mediaSrc, sources)
    }
}

/**
 The object-src directive restricts from where the protected resource can load plugins.

 [Spec](https://www.w3.org/TR/CSP2/#directive-object-src)
 */
@objc
public class ObjectDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .objectSrc, sources)
    }
}

/**
 The plugin-types directive restricts the set of plugins that can be invoked by
 the protected resource by limiting the types of resources that can be embedded.

 [Spec](https://www.w3.org/TR/CSP2/#directive-plugin-types)
 */
@objc
public class PluginTypesDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .pluginTypes, sources)
    }
}

/**
 The report-uri directive specifies a URL to which the user agent sends reports
 about policy violation.

 [Spec](https://www.w3.org/TR/CSP2/#directive-report-uri)
 */
@objc
public class ReportUriDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .reportUri, sources)
    }
}

@objc
public class ReportToDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
        self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .reportTo, sources)
    }
}

/**
 The sandbox directive specifies an HTML sandbox policy that the user agent applies
 to the protected resource.

 [Spec](https://www.w3.org/TR/CSP2/#directive-sandbox)
 */
@objc
public class SandboxDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .sandbox, sources)
    }
}

/**
 The script-src directive restricts which scripts the protected resource can execute.
 The directive also controls other resources, such as XSLT style sheets [XSLT],
 which can cause the user agent to execute script.

 [Spec](https://www.w3.org/TR/CSP2/#directive-script-src)
 */
@objc
public class ScriptDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .scriptSrc, sources)
    }
}

/**
 The style-src directive restricts which styles the user may applies to the
 protected resource.

 [Spec](https://www.w3.org/TR/CSP2/#directive-style-src)
 */
@objc
public class StyleDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

    @objc(initWithSourceStrings:)
    public convenience init(_ sources: [String]) {
        self.init(sources.map { Source($0) })
    }

    public convenience init(_ sources: Source.Value...) {
        self.init(sources)
    }

    public convenience init(_ sources: [Source.Value]) {
        self.init(sources.map { Source($0) })
    }

   public convenience init(_ sources: Source...) {
    self.init(sources)
    }

    @objc(initWithSources:)
    public init(_ sources: [Source]) {
        super.init(name: .styleSrc, sources)
    }
}
