//
//  Source.swift
//  CSPHeader
//
//  Created by Benjamin Erhart on 01.08.19.
//

import UIKit

@objc
public class Source: NSObject {

    public enum Value: String {
        case none = "'none'"
        case `self` = "'self'"
        case unsafeInline = "'unsafe-inline'"
        case unsafeEval = "'unsafe-eval'"

        case allHosts = "*"

        /**
         Only in sandbox directive.
        */
        case allowForms = "allow-forms"

        /**
         Only in sandbox directive.
         */
        case allowPointerLock = "allow-pointer-lock"

        /**
         Only in sandbox directive.
         */
        case allowPopups = "allow-popups"

        /**
         Only in sandbox directive.
         */
        case allowSameOrigin = "allow-same-origin"

        /**
         Only in sandbox directive.
         */
        case allowScripts = "allow-scripts"

        /**
         Only in sandbox directive.
         */
        case allowTopNavigation = "allow-top-navigation"
    }

    public enum HashAlgo: String, CaseIterable {
        case sha256 = "sha256"
        case sha384 = "sha384"
        case sha512 = "sha512"
    }

    
    private let value: String


    public init(_ value: String) {
        self.value = value
    }

    public init(_ value: Value) {
        self.value = value.rawValue
    }


    // MARK: NSObject

    public override var hash: Int {
        return value.hashValue
    }

    public override func isEqual(_ object: Any?) -> Bool {
        guard let rhs = object as? Source else {
            return false
        }

        return value == rhs.value
    }

    public override var description: String {
        return value
    }
}

public class NoneSource: Source {

    public init() {
        super.init(.none)
    }
}

public class SelfSource: Source {

    public init() {
        super.init(.`self`)
    }
}

public class UnsafeInlineSource: Source {

    public init() {
        super.init(.unsafeInline)
    }
}

public class UnsafeEvalSource: Source {

    public init() {
        super.init(.unsafeEval)
    }
}

public class SchemeSource: Source {

    public init(scheme: String) {
        super.init(scheme.contains(":") ? scheme : "\(scheme):")
    }

    public class func containsScheme(token: String) -> Bool {
        return token.range(of: "^\\w+:$", options: [.regularExpression, .caseInsensitive]) != nil
    }
}

public class HostSource: Source {

    public init(url: URL) {
        super.init(url.absoluteString)
    }
}

public class NonceSource: Source {

    private static let regEx = try? NSRegularExpression(pattern: "^'?nonce-(.*?)'?$", options: .caseInsensitive)

    private static let length = 128 /* Bit */ / 8

    public let nonce: String

    /**
     Instantiate a `NonceSource` from the given nonce string.

     The nonce string can contain the complete token, in which case the actual
      nonce is extracted and the token is created fresh from that.
    */
    public init(nonce: String) {
        self.nonce = NonceSource.extractNonce(token: nonce) ?? nonce

        super.init("'nonce-\(self.nonce)'")
    }

    /**
     Create a nonce and init `NonceSource` with that.

     `#generateNonce` can fail therefore this is optional.

     You can get the generated nonce without the decoration on `#nonce`.
    */
    public convenience init?() {
        if let nonce = NonceSource.generateNonce() {
            self.init(nonce: nonce)
        }
        else {
            return nil
        }
    }

    /**
     Tries to extract the nonce from a nonce source token.

     - parameter token: The nonce source token.
     - returns: The extracted nonce or nil, if the token isn't a valid nonce token.
    */
    public class func extractNonce(token: String) -> String? {
        let matches = regEx?.matches(in: token, options: [], range: NSRange(token.startIndex..., in: token))

        if let nsRange = matches?.first?.range(at: 1),
            nsRange.location != NSNotFound,
            let range = Range(nsRange, in: token),
            !range.isEmpty {

            return String(token[range])
        }

        return nil
    }

    public class func containsNonce(token: String) -> Bool {
        return extractNonce(token: token) != nil
    }

    /**
     Generate a cryptographically secure nonce which complies with requirements.

     https://www.w3.org/TR/CSP2/#source-list-syntax

     > The generated value SHOULD be at least 128 bits long (before encoding),
     > and generated via a cryptographically secure random number generator.
    */
    public class func generateNonce() -> String? {
        if let data = NSMutableData(length: length),
            SecRandomCopyBytes(kSecRandomDefault, data.count, data.mutableBytes) == errSecSuccess {

            return data.base64EncodedString(options: [])
        }

        return nil
    }
}

public class HashSource: Source {

    public init(algo: HashAlgo, hash: String) {
        super.init("'\(algo.rawValue)-\(hash)'")
    }

    init(rawValue: String) {
        super.init(rawValue)
    }

    public class func containsHash(token: String) -> Bool {
        let algos = HashAlgo.allCases.map { $0.rawValue }.joined(separator: "|")

        return token.range(of: "^'?(\(algos))", options: [.regularExpression, .caseInsensitive]) != nil
    }
}

public class AllowFormsSource: Source {

    public init() {
        super.init(.allowForms)
    }
}

public class AllowPointerLockSource: Source {

    public init() {
        super.init(.allowPointerLock)
    }
}

public class AllowPopups: Source {

    public init() {
        super.init(.allowPopups)
    }
}

public class AllowSameOrigin: Source {

    public init() {
        super.init(.allowSameOrigin)
    }
}

public class AllowScripts: Source {

    public init() {
        super.init(.allowScripts)
    }
}
public class AllowTopNavigationSource: Source {

    public init() {
        super.init(.allowTopNavigation)
    }
}
