//
//  CSPHeader.swift
//  CSPHeader
//
//  Created by Benjamin Erhart on 01.08.19.
//

import Foundation

/**
 A parser/generator for Content-Security-Headers.

 It tries to follow the spec in
 https://www.w3.org/TR/CSP2/#syntax-and-algorithms

 However, it's not complete and doesn't really implement a stream tokenizer
 as the spec implicitely requires but relies on string splitting, so there
 might be some exotic edge cases, where it fails on a valid CSP header.
 */
@objc
public class CSPHeader: NSObject {

    private static let headerNames = ["Content-Security-Policy", "X-WebKit-CSP"]

    /**
     The NSMutableOrderedSet provides exactly the required behaviour as per spec.

     Specification extract:

     > If the set of directives already contains a directive whose name is a
     > case insensitive match for directive name, ignore this instance of the
     > directive and continue to the next token.

    */
    private var directives = [Directive]()

    @objc(initWithToken:)
    public init(token: String) {
        let directiveTokens = token.split(separator: ";")

        for token in directiveTokens {
            if let directive = Directive.parse(String(token)) {
                if !directives.contains(directive) {
                    directives.append(directive)
                }
            }
        }
    }

    /**
     Init from a dictionary of HTTP headers which might contain a CSP header.

     "Content-Security-Policy" and "X-WebKit-CSP" headers are respected (in that
     order), the match is case-insensitive.
    */
    @objc(initFromHeaders:)
    public convenience init(headers: [String: String]) {
        var token = ""

        for name in CSPHeader.headerNames {
            for key in headers.keys {
                if key.caseInsensitiveCompare(name) == .orderedSame {
                    token = headers[key]!
                    break
                }
            }

            if !token.isEmpty {
                break
            }
        }

        self.init(token: token)
    }

    public convenience init(_ directives: Directive...) {
        self.init(directives: directives)
    }

    @objc(initWithDirectives:)
    public init(directives: [Directive]) {
        for directive in directives {
            if !self.directives.contains(directive) {
                self.directives.append(directive)
            }
        }
    }


    // MARK: NSObject

    @objc
    public override var hash: Int {
        return directives.hashValue
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        guard let rhs = object as? CSPHeader else {
            return false
        }

        return String(describing: self) == String(describing: rhs)
    }

    @objc
    public override var description: String {
        return directives.map { String(describing: $0) }.joined(separator: "; ")
    }


    // MARK: Public methods

    /**
     Searches for the first `Directive` of the given type and returns it.

     - parameter directiveType: The type of `Directive` to search for.
     - returns: The first directive of the given type, or `nil` if not contained.
    */
    public func get<T: Directive>(_ directiveType: T.Type) -> T? {
        return directives.first { type(of: $0) == directiveType } as? T
    }

    /**
     Searches for the first `Directive` of the given type and returns it.

     This is the non-generic version to support Objective-C, which can't use
     Swift generics.

     - parameter directiveType: The type of `Directive` to search for.
     - returns: The first directive of the given type, or `nil` if not contained.
     */
    @objc(get:)
    public func __get(_ directiveType: Directive.Type) -> Directive? {
        return get(directiveType)
    }

    /**
     Prepend the sources of a given directive to the directive with the same name,
     **if it already exists** in the header.

     If a directive doesn't already exist, it will be ignored and
     **not** added to the header!

     If a directive contains the `NoneSource`, that will be removed, as the
     `NoneSource` shall not stand with anything else.

     - parameter directive: A directive which' sources get prepended.
     - returns: self for fluency.
    */
    @discardableResult
    @objc(prependDirective:)
    public func prepend(_ directive: Directive) -> CSPHeader {
        if let original = get(type(of: directive)) {
            original.remove(NoneSource.self)
                .prepend(directive.sources)
        }

        return self
    }

    /**
     Prepend the sources of the given directives to the directives with the same
     name, **if they already exist** in the header.

     If a directive doesn't already exist, it will be ignored and
     **not** added to the header!

     If a directive contains the `NoneSource`, that will be removed, as the
     `NoneSource` shall not stand with anything else.

     - parameter directives: List of directives which' sources get prepended.
     - returns: self for fluency.
     */
    @discardableResult
    @objc(prependDirectives:)
    public func prepend(_ directives: [Directive]) -> CSPHeader {
        for directive in directives {
            prepend(directive)
        }

        return self
    }

    /**
     Replaces a directive at the position of the original, if already one exists,
     otherwise, the directive gets added at the end.

     - parameter directive: Directive to replace or add.
     - returns: self for fluency.
    */
    @discardableResult
    @objc(addOrReplaceDirective:)
    public func addOrReplace(_ directive: Directive) -> CSPHeader {
        let idx = directives.firstIndex(of: directive)

        if let idx = idx {
            directives[idx] = directive
        }
        else {
            directives.append(directive)
        }

        return self
    }

    /**
     Replaces each of the given directives at the position of the original,
     if already one exists with the same name, or otherwise, adds it at the end.

     Attention: For your convenience, an array is used instead of a NSOrderedSet.
     This has the drawback, that, if you define directives multiple times,
     the last one will win!

     - parameter directives: List of directives to replace or add.
     - returns: self for fluency.
     */
    @discardableResult
    @objc(addOrReplaceDirectives:)
    public func addOrReplace(_ directives: [Directive]) -> CSPHeader {
        for directive in directives {
            addOrReplace(directive)
        }

        return self
    }

    @discardableResult
    @objc(removeDirective:)
    public func remove(_ directive: Directive) -> CSPHeader {
        directives.removeAll { $0 == directive }

        return self
    }

    @discardableResult
    @objc(removeDirectives:)
    public func remove(_ directives: [Directive]) -> CSPHeader {
        for directive in directives {
            remove(directive)
        }

        return self
    }

    /**
     Makes a script available, which you injected using a ˚script˚ tag.

     Logic is as follows:

     Use a `NonceSource` as `source`, if you provide a `nonce`, else use 'unsafe-inline'.

     - Check if script-src is available. If so,
       - check, if it contains 'unsafe-inline' and do nothing, if so.
       - check, if it contains 'none'. In that case, replace with new `source`.
       - check, if it is empty. In that case, replace with new `source`.
       - else, prepend new `source` to source list.

     - else, check if default-src is available, If so,
       - check, if it contains 'unsafe-inline' and do nothing, if so.
       - check, if it contains 'none'. In that case, replace with new `source`.
       - check, if it is empty. In that case, replace with new `source`.
       - else, prepend new `source` to source list.

     - parameter nonce: The nonce you added as attribute to the `script` tag.
        OPTIONAL but **very recommended**! If you don't provide a nonce, 'unsafe-inline'
        will be used, which opens the page up for other (probably unwanted) injections.

     - returns: self for fluency.
    */
    @discardableResult
    @objc
    public func allowInjectedScript(nonce: String? = nil) -> CSPHeader {
        if let scriptDirective = directives.first(where: { $0 is ScriptDirective }) {
            inject(scriptDirective, nonce)
        }
        else if let defaultDirective = directives.first(where: { $0 is DefaultDirective }) {
            inject(defaultDirective, nonce)
        }

        return self
    }

    /**
     Makes a style available, which you injected using a ˚style˚ tag.

     Logic is as follows:

     Use a `NonceSource` as `source`, if you provide a `nonce`, else use 'unsafe-inline'.

     - Check if style-src is available. If so,
       - check, if it contains 'unsafe-inline' and do nothing, if so.
       - check, if it contains 'none'. In that case, replace with new `source`.
       - check, if it is empty. In that case, replace with new `source`.
       - else, prepend new `source` to source list.

     - else, check if default-src is available, If so,
       - check, if it contains 'unsafe-inline' and do nothing, if so.
       - check, if it contains 'none'. In that case, replace with new `source`.
       - check, if it is empty. In that case, replace with new `source`.
       - else, prepend new `source` to source list.

     - parameter nonce: The nonce you added as attribute to the `style` tag.
     OPTIONAL but **very recommended**! If you don't provide a nonce, 'unsafe-inline'
     will be used, which opens the page up for other (probably unwanted) injections.

     - returns: self for fluency.
     */
    @discardableResult
    @objc
    public func allowInjectedStyle(nonce: String? = nil) -> CSPHeader {
        if let styleDirective = directives.first(where: { $0 is StyleDirective }) {
            inject(styleDirective, nonce)
        }
        else if let defaultDirective = directives.first(where: { $0 is DefaultDirective }) {
            inject(defaultDirective, nonce)
        }

        return self
    }

    /**
     Applies this CSP header to a dictionary of HTTP headers.

     All existing versions of "Content-Security-Policy" and "X-WebKit-CSP"
     (regardless of casing) will be removed and 2 new headers with the respective
     names will be added.

     An empty CSP header *will not be added*. Old headers which were contained
     before, will be deleted, however!

     - parameter headers: A dictionary of HTTP headers.
     - returns: The headers dictionary with all old CSP headers removed and the new ones added, if any.
    */
    @objc
    public func applyTo(headers: [String: String]) -> [String: String] {
        let csp = String(describing: self)
        var headers = headers

        for name in CSPHeader.headerNames {
            for key in headers.keys {
                if key.caseInsensitiveCompare(name) == .orderedSame {
                    headers[key] = nil
                }
            }

            if !csp.isEmpty {
                headers[name] = csp
            }
        }

        return headers
    }


    // MARK: Private Methods

    /**
     Helper method to be used in `allowInjectedScript` and `allowInjectedStyle`.

     - parameter directive: The directive to work on.
     - parameter source: The source to prepend/overwrite with.
    */
    private func inject(_ directive: Directive, _ nonce: String?) {
        if directive.contains(source: .unsafeInline) {
            // Can be safely injected anyway, we're done, no problem.
            return
        }

        let source = nonce != nil ? NonceSource(nonce: nonce!) : UnsafeInlineSource()

        if directive.contains(source: .none) || directive.isEmpty {
            // Nothing allowed at all. Allow ours specifically, if we have a nonce
            // or all inline, if we don't have one.
            directive.replace(source)

            return
        }

        // No inline allowed. Allow ours specifically, if we have a nonce
        // or all inline, if we don't have one.
        directive.prepend(source)
    }
}
