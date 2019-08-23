//
//  ObjcTest.m
//  CSPHeader_Tests
//
//  Created by Benjamin Erhart on 06.08.19.
//  Copyright © 2019 CocoaPods. All rights reserved.
//

#import <XCTest/XCTest.h>
@import CSPHeader;

@interface ObjcTest : XCTestCase

@end

@implementation ObjcTest

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testAccess {
    CSPHeader *header = [[CSPHeader alloc] initWithToken:@"default-src *"];
    XCTAssertEqualObjects(header.description, @"default-src *");

    Source *source = [[Source alloc] initWithString:@"foo"];
    XCTAssertEqualObjects(source.description, @"foo");

    NoneSource *none = [[NoneSource alloc] init];
    XCTAssertEqualObjects(none.description, @"'none'");

    HashSource *hash = [[HashSource alloc] initWithHashAlgo: HashAlgoSha256 andHash: @"foo"];
    XCTAssertEqualObjects(hash.description, @"'sha256-foo'");

    CSPHeader *header2 = [[CSPHeader alloc] initFromHeaders:@{@"Content-Security-Policy": @"default-src 'self'"}];
    XCTAssertEqualObjects(header2.description, @"default-src 'self'");

    XCTAssertEqualObjects([header2 get:DefaultDirective.self], [[DefaultDirective alloc] initWithSourceStrings:@[@"'self'"]]);

    HostSource *all = [HostSource all];
    XCTAssertEqualObjects(all.description, @"*");

    NSDictionary *expected = @{@"Content-Security-Policy": @"default-src 'self'", @"X-WebKit-CSP": @"default-src 'self'"};
    XCTAssertEqualObjects([header2 applyToHeaders: @{}], expected);

    Directive *directive = [Directive parse:@"default-src 'self' 'unsafe-inline'"];
    [directive remove:@[[[SelfSource alloc] init]]];
    XCTAssertEqualObjects(directive.description, @"default-src 'unsafe-inline'");

    [directive removeSourceOfType: UnsafeInlineSource.self];
    XCTAssertEqualObjects(directive.description, @"default-src 'none'");
}

@end
