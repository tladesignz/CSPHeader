// https://github.com/Quick/Quick

import Quick
import Nimble
import CSPHeader

class CSPHeaderSpec: QuickSpec {
    override func spec() {
        describe("a basic default-src header") {
            let token = "default-src *"
            let header1 = CSPHeader(DefaultDirective(.allHosts))
            let header2 = CSPHeader(token: token)

            it("is rendered correctly") {
                expect(String(describing: header1)).to(equal(token))
            }

            it("is parsed correctly") {
                expect(header2).to(equal(header1))
            }
        }

        describe("a more complex header") {
            let token = "default-src *; script-src 'self' 'unsafe-inline'"
            let header1 = CSPHeader(DefaultDirective(.allHosts), ScriptDirective(.`self`, .unsafeInline))
            let header2 = CSPHeader(token: token)

            it("is rendered correctly") {
                expect(String(describing: header1)).to(equal(token))
            }

            it("is parsed correctly") {
                expect(header2).to(equal(header1))
            }
        }

        describe("a header with a nonce") {
            let token = "style-src 'nonce-foobar'"
            let header1 = CSPHeader(StyleDirective(NonceSource(nonce: "foobar")))
            let header2 = CSPHeader(token: token)

            it("is rendered correctly") {
                expect(String(describing: header1)).to(equal(token))
            }

            it("is parsed correctly") {
                expect(header2).to(equal(header1))
            }

            it("creates nonces correctly") {
                let nonce = NonceSource.generateNonce()

                expect(nonce).toNot(beNil())

                print("[\(String(describing: type(of: self)))] nonce=\(nonce!)")

                let source1 = NonceSource(nonce: nonce!)
                expect(String(describing: source1)).to(equal("'nonce-\(nonce!)'"))

                let source2 = NonceSource(nonce: "nonce-\(nonce!)")
                expect(String(describing: source2)).to(equal("'nonce-\(nonce!)'"))

                let source3 = NonceSource(nonce: "'NonCe-\(nonce!)'")
                expect(String(describing: source3)).to(equal("'nonce-\(nonce!)'"))

                let source4 = NonceSource(nonce: "NONC-\(nonce!)'")
                expect(String(describing: source4)).to(equal("'nonce-NONC-\(nonce!)''"))
            }

            it("detects nonces correctly") {
                expect(NonceSource.extractNonce(token: "'nonce-foobar'")).to(equal("foobar"))
                expect(NonceSource.containsNonce(token: "'nonce-foobar'")).to(beTrue())
                expect(NonceSource.containsNonce(token: "NoNcE-foobar'")).to(beTrue())
                expect(NonceSource.containsNonce(token: "'nonce-'")).to(beFalse())
                expect(NonceSource.containsNonce(token: "'foobar:'")).to(beFalse())
                expect(NonceSource.containsNonce(token: "'nonce:'")).to(beFalse())
                expect(NonceSource.containsNonce(token: "'http://www.example.com/'")).to(beFalse())
                expect(NonceSource.containsNonce(token: "'unsafe-eval'")).to(beFalse())
            }
        }

        describe("a header with a hash") {
            let token = "font-src 'sha256-foobar'"
            let header1 = CSPHeader(FontDirective(HashSource(algo: .sha256, hash: "foobar")))
            let header2 = CSPHeader(token: token)

            it("is rendered correctly") {
                expect(String(describing: header1)).to(equal(token))
            }

            it("is parsed correctly") {
                expect(header2).to(equal(header1))
            }

            it("is detected correctly") {
                expect(HashSource.containsHash(token: "'sha256-ksadfhjkasdfhsdkaf'")).to(beTrue())
                expect(HashSource.containsHash(token: "sha256-ksadfhjkasdfhsdkaf")).to(beTrue())
                expect(HashSource.containsHash(token: "sha384-ksadfhjkasdfhsdkaf")).to(beTrue())
                expect(HashSource.containsHash(token: "sha512-ksadfhjkasdfhsdkaf")).to(beTrue())
                expect(HashSource.containsHash(token: "sha1235-ksadfhjkasdfhsdkaf")).to(beFalse())
            }
        }

        describe("prepend a scheme") {
            let token = "default-src 'self'"

            it("renders corectly when directive there") {
                let header = CSPHeader(token: token)
                header.prepend(DefaultDirective(SchemeSource(scheme: "foobar")))

                expect(String(describing: header)).to(equal("default-src foobar: 'self'"))
            }

            it("renders corectly when directive not there") {
                let header = CSPHeader(token: token)
                header.prepend(ScriptDirective(SchemeSource(scheme: "foobar")))

                expect(String(describing: header)).to(equal(token))
            }
        }

        describe("inject script") {
            it("leaves unsafe-inline alone") {
                let token = "script-src 'unsafe-inline'"
                let header = CSPHeader(token: token)

                header.allowInjectedScript(nonce: "foobar")

                expect(String(describing: header)).to(equal(token))
            }

            it("updates 'none'") {
                let token = "script-src 'none'"
                let header = CSPHeader(token: token)

                header.allowInjectedScript(nonce: "foobar")

                expect(String(describing: header)).to(equal("script-src 'nonce-foobar'"))
            }

            it("prepends other") {
                let token = "script-src 'self'"
                let header = CSPHeader(token: token)

                header.allowInjectedScript(nonce: "foobar")

                expect(String(describing: header)).to(equal("script-src 'nonce-foobar' 'self'"))
            }

            it("works correctly with default-src unsafe-inline and no script-src") {
                let token = "default-src 'unsafe-inline' 'self'"
                let header = CSPHeader(token: token)

                header.allowInjectedScript(nonce: "foobar")

                expect(String(describing: header)).to(equal("default-src 'unsafe-inline' 'self'"))
            }

            it("injects unsafe-inline when no nonce provided") {
                let token = "default-src 'self' https://api.jquery.com/"
                let header = CSPHeader(token: token)

                header.allowInjectedScript()

                expect(String(describing: header)).to(equal("default-src 'unsafe-inline' 'self' https://api.jquery.com/"))
            }

            it("doesn't modify header if no script-src and default-src directive") {
                let token = "connect-src 'self'"
                let header = CSPHeader(token: token)

                header.allowInjectedScript()

                expect(String(describing: header)).to(equal(token))
            }
        }

        describe("inject style") {
            it("leaves unsafe-inline alone") {
                let token = "style-src 'unsafe-inline'"
                let header = CSPHeader(token: token)

                header.allowInjectedStyle(nonce: "foobar")

                expect(String(describing: header)).to(equal(token))
            }

            it("updates 'none'") {
                let token = "style-src 'none'"
                let header = CSPHeader(token: token)

                header.allowInjectedStyle(nonce: "foobar")

                expect(String(describing: header)).to(equal("style-src 'nonce-foobar'"))
            }

            it("prepends other") {
                let token = "style-src 'self'"
                let header = CSPHeader(token: token)

                header.allowInjectedStyle(nonce: "foobar")

                expect(String(describing: header)).to(equal("style-src 'nonce-foobar' 'self'"))
            }

            it("works correctly with default-src unsafe-inline and no style-src") {
                let token = "default-src 'unsafe-inline' 'self'"
                let header = CSPHeader(token: token)

                header.allowInjectedStyle(nonce: "foobar")

                expect(String(describing: header)).to(equal("default-src 'unsafe-inline' 'self'"))
            }

            it("injects unsafe-inline when no nonce provided") {
                let token = "style-src 'self' https://api.jquery.com/"
                let header = CSPHeader(token: token)

                header.allowInjectedStyle()

                expect(String(describing: header)).to(equal("style-src 'unsafe-inline' 'self' https://api.jquery.com/"))
            }

            it("doesn't modify header if no style-src and default-src directive") {
                let token = "connect-src 'self'"
                let header = CSPHeader(token: token)

                header.allowInjectedStyle()

                expect(String(describing: header)).to(equal(token))
            }
        }

        describe("cleaning") {
            it("trims excessive whitespaces") {
                let header = CSPHeader(token: "   frame-src   'self'   ;    default-src 'self'")

                expect(String(describing: header)).to(equal("frame-src 'self'; default-src 'self'"))
            }

            it("sets 'none' for an empty source list") {
                let d1 = DefaultDirective([Source]())
                let d2 = DefaultDirective(.none)

                expect(String(describing: d1)).to(equal(String(describing: d2)))

            }

            it("are equal") {
                let d1 = DefaultDirective(.`self`)
                let d2 = DefaultDirective(.none)

                expect(d1).to(equal(d2))
            }

            it("removes second definition of a directive") {
                let header = CSPHeader(token: "default-src 'self'; default-src 'none'")

                expect(String(describing: header)).to(equal("default-src 'self'"))
            }
        }

        describe("compatibility") {
            it("allows unkown directives and sources") {
                let token = "foo bar; bam 'baz'"
                let header = CSPHeader(token: token)

                expect(String(describing: header)).to(equal(token))
            }
        }

        describe("headers dictionary support") {
            let token = "default-src 'self'"

            it("inits from a crazy-cased x-webkit-csp header") {
                let header = CSPHeader(headers: ["X-WEBkit-csp": token])

                expect(String(describing: header)).to(equal(token))
            }

            it("standard header wins over webkit header") {
                let header = CSPHeader(headers: ["content-security-policy": token, "X-WebKit-CSP": "foo bar"])

                expect(String(describing: header)).to(equal(token))
            }

            it("replaces headers correctly") {
                let addition = "; script-src 'none'"

                var headers = ["Foo": "bar",
                               "CONTENT-Security-Policy": token,
                               "x-webkit-csp": token,]

                let expected = ["Foo": "bar",
                                "Content-Security-Policy": token + addition,
                                "X-WebKit-CSP": token + addition,]

                let header = CSPHeader(headers: headers)

                header.addOrReplace(ScriptDirective(NoneSource()))

                header.applyTo(headers: &headers)

                expect(headers).to(equal(expected))
            }
        }

        describe("special all-hosts source") {
            it("is created correctly") {
                let header = CSPHeader(DefaultDirective(HostSource.all()))

                expect(String(describing: header)).to(equal("default-src *"))
            }
        }
    }
}
