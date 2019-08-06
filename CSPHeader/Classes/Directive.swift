//
//  Directive.swift
//  CSPHeader
//
//  Created by Benjamin Erhart on 01.08.19.
//

import Foundation

public class Directive: Hashable, CustomStringConvertible {

    public enum Name: String {
        case baseUri = "base-uri"
        case childSrc = "child-src"
        case connectSrc = "connect-src"
        case defaultSrc = "default-src"
        case fontSrc = "font-src"
        case formAction = "form-action"
        case frameAncestors = "frame-ancestors"
        case frameSrc = "frame-src"
        case imgSrc = "img-src"
        case mediaSrc = "media-src"
        case objectSrc = "object-src"
        case pluginTypes = "plugin-types"
        case reportUri = "report-uri"
        case sandbox = "sandbox"
        case scriptSrc = "script-src"
        case styleSrc = "style-src"
    }


    public let name: String

    private(set) public var sources: [Source]

    public class func parse(token: String) -> Directive? {
        let pieces = token.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: " ")

        guard let name = pieces.first else {
            return nil
        }

        var sources = [Source]()

        for rawValue in pieces.dropFirst() {
            let source = String(rawValue).lowercased()

            if let wellKnown = Source.Value(rawValue: source) {
                switch wellKnown {
                case .allHosts:
                    sources.append(HostSource(url: URL(string: wellKnown.rawValue)!))
                case .none:
                    sources.append(NoneSource())
                case .self:
                    sources.append(SelfSource())
                case .unsafeInline:
                    sources.append(UnsafeInlineSource())
                case .unsafeEval:
                    sources.append(UnsafeEvalSource())
                case .allowForms:
                    sources.append(AllowFormsSource())
                case .allowPointerLock:
                    sources.append(AllowPointerLockSource())
                case .allowPopups:
                    sources.append(AllowPopups())
                case .allowSameOrigin:
                    sources.append(AllowSameOrigin())
                case .allowScripts:
                    sources.append(AllowScripts())
                case .allowTopNavigation:
                    sources.append(AllowTopNavigationSource())
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

    public convenience init(name: String, _ sources: [String]) {
        self.init(name: name, sources.map { Source($0) })
    }

    public convenience init(name: Name, _ sources: [String]) {
        self.init(name: name.rawValue, sources)
    }

    public convenience init(name: String, _ sources: Source...) {
        self.init(name: name, sources)
    }

    public convenience init(name: Name, _ sources: Source...) {
        self.init(name: name, sources)
    }

    public init(name: String, _ sources: [Source]) {
        self.name = name
        self.sources = sources
    }

    public init(name: Name, _ sources: [Source]) {
        self.name = name.rawValue
        self.sources = sources
    }


    // MARK: Hashable

    public func hash(into hasher: inout Hasher) {
        hasher.combine(name)
    }


    // MARK: Equatable

    public static func == (lhs: Directive, rhs: Directive) -> Bool {
        return lhs.name == rhs.name
    }


    // MARK: CustomStringConvertible

    public var description: String {
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


    @discardableResult
    public func append(_ sources: Source...) -> Directive {
        return append(sources)
    }

    @discardableResult
    public func append(_ sources: [Source]) -> Directive {
        self.sources.append(contentsOf: sources)

        return self
    }

    @discardableResult
    public func prepend(_ sources: Source...) -> Directive {
        return prepend(sources)
    }

    @discardableResult
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
    public func replace(_ sources: [Source]) -> Directive {
        self.sources = sources

        return self
    }

    @discardableResult
    public func removeAll() -> Directive {
        return replace([])
    }

    public func contains(source: Source) -> Bool {
        return sources.contains(source)
    }

    public func contains(source: Source.Value) -> Bool {
        return contains(source: Source(source))
    }

    public func contains(source: String) -> Bool {
        return contains(source: Source(source))
    }

    public func filter(_ isIncluded: (Source) -> Bool) -> [Source] {
        return sources.filter(isIncluded)
    }

    public func contains(a sourceType: Source.Type) -> Bool {
        return !(filter { type(of: $0) == sourceType }.isEmpty)
    }

    public var isEmpty: Bool {
        return sources.isEmpty
    }
}

public class BaseUriDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .baseUri, sources)
    }
}

public class ChildDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .childSrc, sources)
    }
}

public class ConnectDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .connectSrc, sources)
    }
}

public class DefaultDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .defaultSrc, sources)
    }
}

public class FontDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .fontSrc, sources)
    }
}

public class FormActionDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .formAction, sources)
    }
}

public class FrameAncestorsDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .frameAncestors, sources)
    }
}

@available(*, deprecated, message: "The frame-src directive is deprecated. Authors who wish to govern nested browsing contexts SHOULD use the child-src directive instead.")
public class FrameDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .frameSrc, sources)
    }
}

public class ImgDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .imgSrc, sources)
    }
}

public class MediaDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .mediaSrc, sources)
    }
}

public class ObjectDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .objectSrc, sources)
    }
}

public class PluginTypesDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .pluginTypes, sources)
    }
}

public class ReportUriDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .reportUri, sources)
    }
}

public class SandboxDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .sandbox, sources)
    }
}

public class ScriptDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .scriptSrc, sources)
    }
}

public class StyleDirective: Directive {

    public convenience init(_ sources: String...) {
        self.init(sources)
    }

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

    public init(_ sources: [Source]) {
        super.init(name: .styleSrc, sources)
    }
}
