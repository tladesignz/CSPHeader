//
//  Source.swift
//  CSPHeader
//
//  Created by Benjamin Erhart on 01.08.19.
//

import UIKit

public class Source: Hashable, CustomStringConvertible {

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

    public enum HashAlgo: String {
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


    // MARK: Hashable

    public func hash(into hasher: inout Hasher) {
        hasher.combine(value)
    }


    // MARK: Equatable

    public static func == (lhs: Source, rhs: Source) -> Bool {
        return lhs.value == rhs.value
    }


    // MARK: CustomStringConvertible

    public var description: String {
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
}

public class HostSource: Source {

    public init(url: URL) {
        super.init(url.absoluteString)
    }
}

public class NonceSource: Source {

    public init(nonce: String) {
        super.init(nonce.contains("'nonce-") ? nonce : "'nonce-\(nonce)'")
    }
}

public class HashSource: Source {

    public init(algo: HashAlgo, hash: String) {
        super.init("'\(algo.rawValue)-\(hash)'")
    }

    init(rawValue: String) {
        super.init(rawValue)
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
