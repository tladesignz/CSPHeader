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

    /**
     The NSMutableOrderedSet provides exactly the required behaviour as per spec.

     Specification extract:

     > If the set of directives already contains a directive whose name is a
     > case insensitive match for directive name, ignore this instance of the
     > directive and continue to the next token.

    */
    private var directives = [Directive]()


    public init(token: String) {
        let directiveTokens = token.split(separator: ";")

        for token in directiveTokens {
            if let directive = Directive.parse(token: String(token)) {
                if !directives.contains(directive) {
                    directives.append(directive)
                }
            }
        }
    }

    public convenience init(_ directives: Directive...) {
        self.init(directives: directives)
    }

    public init(directives: [Directive]) {
        for directive in directives {
            if !self.directives.contains(directive) {
                self.directives.append(directive)
            }
        }
    }


    // MARK: NSObject

    public override var hash: Int {
        return directives.hashValue
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let rhs = object as? CSPHeader else {
            return false
        }

        return String(describing: self) == String(describing: rhs)
    }

    public override var description: String {
        return directives.map { String(describing: $0) }.joined(separator: "; ")
    }


    // MARK: Public methods

    /**
     Prepend the sources of a given directive to the directive with the same name,
     **if it already exists** in the header.

     If a directive doesn't already exist, it will be ignored and
     **not** added to the header!

     - parameter directive: A directive which' sources get prepended.
     - returns: self for fluency.
    */
    @discardableResult
    public func prepend(_ directive: Directive) -> CSPHeader {
        let original = directives.first { $0 == directive }

        if let original = original {
            original.prepend(directive.sources)
        }

        return self
    }

    /**
     Prepend the sources of the given directives to the directives with the same
     name, **if they already exist** in the header.

     If a directive doesn't already exist, it will be ignored and
     **not** added to the header!

     - parameter directives: List of directives which' sources get prepended.
     - returns: self for fluency.
     */
    @discardableResult
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
    public func addOrReplace(_ directives: [Directive]) -> CSPHeader {
        for directive in directives {
            addOrReplace(directive)
        }

        return self
    }

    /**
     Makes an script available, which you injected using a ˚script˚ tag.

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
     Makes an style available, which you injected using a ˚style˚ tag.

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

     - parameter nonce: The nonce you added as attribute to the `script` tag.
     OPTIONAL but **very recommended**! If you don't provide a nonce, 'unsafe-inline'
     will be used, which opens the page up for other (probably unwanted) injections.

     - returns: self for fluency.
     */
    @discardableResult
    public func allowInjectedStyle(nonce: String? = nil) -> CSPHeader {
        if let styleDirective = directives.first(where: { $0 is StyleDirective }) {
            inject(styleDirective, nonce)
        }
        else if let defaultDirective = directives.first(where: { $0 is DefaultDirective }) {
            inject(defaultDirective, nonce)
        }

        return self
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
