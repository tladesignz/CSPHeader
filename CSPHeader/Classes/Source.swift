//
//  Source.swift
//  CSPHeader
//
//  Created by Benjamin Erhart on 01.08.19.
//

import UIKit

/**
 [Spec](https://www.w3.org/TR/CSP2/#source-list-syntax)

 More sandbox directive sources:
 https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox
 */
@objc
public class Source: NSObject {

    @objc
    public enum Value: Int, RawRepresentable {
        case none
        case `self`
        case unsafeInline
        case unsafeEval

        case allHosts

        /**
         Only in sandbox directive.
        */
        case allowDownloadsWithoutUserActivation

        /**
         Only in sandbox directive.
        */
        case allowForms

        /**
         Only in sandbox directive.
        */
        case allowModals

        /**
         Only in sandbox directive.
        */
        case allowOrientationLock

        /**
         Only in sandbox directive.
         */
        case allowPointerLock

        /**
         Only in sandbox directive.
         */
        case allowPopups

        /**
         Only in sandbox directive.
         */
        case allowPopupsToEscapeSandbox

        /**
         Only in sandbox directive.
         */
        case allowPresentation

        /**
         Only in sandbox directive.
         */
        case allowSameOrigin

        /**
         Only in sandbox directive.
         */
        case allowScripts

        /**
         Only in sandbox directive.
         */
        case allowStorageAccessByUserActivation

        /**
         Only in sandbox directive.
         */
        case allowTopNavigation

        /**
         Only in sandbox directive.
         */
        case allowTopNavigationByUserActivation

        public typealias RawValue = String

        public var rawValue: String {
            switch self {
            case .none:
                return "'none'"
            case .self:
                return "'self'"
            case .unsafeInline:
                return "'unsafe-inline'"
            case .unsafeEval:
                return "'unsafe-eval'"
            case .allHosts:
                return "*"
            case .allowDownloadsWithoutUserActivation:
                return "allow-downloads-without-user-activation"
            case .allowForms:
                return "allow-forms"
            case .allowModals:
                return "allow-modals"
            case .allowOrientationLock:
                return "allow-orientation-lock"
            case .allowPointerLock:
                return "allow-pointer-lock"
            case .allowPopups:
                return "allow-popups"
            case .allowPopupsToEscapeSandbox:
                return "allow-popups-to-escape-sandbox"
            case .allowPresentation:
                return "allow-presentation"
            case .allowSameOrigin:
                return "allow-same-origin"
            case .allowScripts:
                return "allow-scripts"
            case .allowStorageAccessByUserActivation:
                return "allow-storage-access-by-user-activation"
            case .allowTopNavigation:
                return "allow-top-navigation"
            case .allowTopNavigationByUserActivation:
                return "allow-top-navigation-by-user-activation"
            }
        }

        public init?(rawValue: String) {
            switch rawValue {
            case "'none'":
                self = .none
            case "'self'":
                self = .`self`
            case "'unsafe-inline'":
                self = .unsafeInline
            case "'unsafe-eval'":
                self = .unsafeEval
            case "*":
                self = .allHosts
            case "allow-downloads-without-user-activation":
                self = .allowDownloadsWithoutUserActivation
            case "allow-forms":
                self = .allowForms
            case "allow-modals":
                self = .allowModals
            case "allow-orientation-lock":
                self = .allowOrientationLock
            case "allow-pointer-lock":
                self = .allowPointerLock
            case "allow-popups":
                self = .allowPopups
            case "allow-popups-to-escape-sandbox":
                self = .allowPopupsToEscapeSandbox
            case "allow-presentation":
                self = .allowPresentation
            case "allow-same-origin":
                self = .allowSameOrigin
            case "allow-scripts":
                self = .allowScripts
            case "allow-storage-access-by-user-activation":
                self = .allowStorageAccessByUserActivation
            case "allow-top-navigation":
                self = .allowTopNavigation
            case "allow-top-navigation-by-user-activation":
                self = .allowTopNavigationByUserActivation
            default:
                return nil
            }
        }
    }

    @objc
    public enum HashAlgo: Int, RawRepresentable, CaseIterable {

        case sha256
        case sha384
        case sha512

        public typealias RawValue = String

        public var rawValue: String {
            switch self {
                case .sha256:
                    return "sha256"
                case .sha384:
                    return "sha384"
                case .sha512:
                    return "sha512"
            }
        }

        public init?(rawValue: String) {
            switch rawValue {
            case "sha256":
                self = .sha256
            case "sha384":
                self = .sha384
            case "sha512":
                self = .sha512
            default:
                return nil
            }
        }
    }

    
    private let value: String


    @objc(initWithString:)
    public init(_ value: String) {
        self.value = value
    }

    @objc(initWithValue:)
    public init(_ value: Value) {
        self.value = value.rawValue
    }


    // MARK: NSObject

    @objc
    public override var hash: Int {
        return value.hashValue
    }

    @objc
    public override func isEqual(_ object: Any?) -> Bool {
        guard let rhs = object as? Source else {
            return false
        }

        return value == rhs.value
    }

    @objc
    public override var description: String {
        return value
    }
}

@objcMembers
public class NoneSource: Source {

    public init() {
        super.init(.none)
    }
}

@objcMembers
public class SelfSource: Source {

    public init() {
        super.init(.`self`)
    }
}

@objcMembers
public class UnsafeInlineSource: Source {

    public init() {
        super.init(.unsafeInline)
    }
}

@objcMembers
public class UnsafeEvalSource: Source {

    public init() {
        super.init(.unsafeEval)
    }
}

@objcMembers
public class SchemeSource: Source {

    public init(scheme: String) {
        super.init(scheme.contains(":") ? scheme : "\(scheme):")
    }

    public class func containsScheme(token: String) -> Bool {
        return token.range(of: "^\\w+:$", options: [.regularExpression, .caseInsensitive]) != nil
    }
}

@objcMembers
public class HostSource: Source {

    public class func all() -> HostSource {
        return HostSource(url: URL(string: Value.allHosts.rawValue)!)
    }

    public init(url: URL) {
        super.init(url.absoluteString)
    }
}

@objcMembers
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

@objcMembers
public class HashSource: Source {

    @objc(initWithHashAlgo:andHash:)
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


@objcMembers
public class AllowDownloadsWithoutUserActivationSource: Source {

    public init() {
        super.init(.allowDownloadsWithoutUserActivation)
    }
}

@objcMembers
public class AllowFormsSource: Source {

    public init() {
        super.init(.allowForms)
    }
}

@objcMembers
public class AllowModalsSource: Source {

    public init() {
        super.init(.allowModals)
    }
}

@objcMembers
public class AllowOrientationLockSource: Source {

    public init() {
        super.init(.allowOrientationLock)
    }
}

@objcMembers
public class AllowPointerLockSource: Source {

    public init() {
        super.init(.allowPointerLock)
    }
}

@objcMembers
public class AllowPopupsSource: Source {

    public init() {
        super.init(.allowPopups)
    }
}

@objcMembers
public class AllowPopupsToEscapeSandboxSource: Source {

    public init() {
        super.init(.allowPopupsToEscapeSandbox)
    }
}

@objcMembers
public class AllowPresentationSource: Source {

    public init() {
        super.init(.allowPresentation)
    }
}

@objcMembers
public class AllowSameOriginSource: Source {

    public init() {
        super.init(.allowSameOrigin)
    }
}

@objcMembers
public class AllowScriptsSource: Source {

    public init() {
        super.init(.allowScripts)
    }
}

@objcMembers
public class AllowStorageAccessByUserActivationSource: Source {

    public init() {
        super.init(.allowStorageAccessByUserActivation)
    }
}

@objcMembers
public class AllowTopNavigationSource: Source {

    public init() {
        super.init(.allowTopNavigation)
    }
}

@objcMembers
public class AllowTopNavigationByUserActivationSource: Source {

    public init() {
        super.init(.allowTopNavigationByUserActivation)
    }
}
