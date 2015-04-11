//
//  JWTTests.swift
//  JWTTests
//
//  Created by Stan P. van de Burgt on 3/31/15.
//  Copyright (c) 2015 RoundZero bv. All rights reserved.
//

import XCTest
import JWT
import Sodium

class JWTTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func test_HS256_JWT_from_dicts() {
        // This is an example of a functional test case.
        let expected_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.lnneNaoem98xYFES3mi2CJJjnMONuWAu-FTWB3XJN14"
        let jwt = JWT(header: ["alg":"HS256"], body: ["hello":"world"], algorithms: ["HS256","HS512","RS512"])
        let s = jwt.dumps("secret", jti_len: 0) // without jti to enable replay
        XCTAssert(s != nil, "JWT.dumps() failed")
        XCTAssert(s! == expected_jwt, "JWT.dumps() unexpected jwt")
    }

    func test_NaCl_JWT_from_string() {
        let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiWE43VnBFWDF1Q3h4aHZ3VXVhY1lodVU5dDZ1eGdMYWhSaUxlU0VIRU5payJ9.eyJmb28iOiJiYXIifQ.a2dDcKXByKxiouOLnXUm7YUKHMGOU3yn_g91C90e8YmKjlF1_9ylAKukfMm6Y6WS3dZp2ysaglzzTnVxnRYyDQ"
        let sk = "YHWUUc0P6SY46WaDdnssE8NpFsQQxJrvmdOrpU9X0wU"
        let pk = "XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"
        let jwt = JWTNaCl(algorithms: ["Ed25519"])
        XCTAssert(jwt.loads(jwt_ed, b64key: pk, verify: true), "loading a NaCl signed JWT and specified public (verification) key")
        XCTAssert(jwt.loads(jwt_ed, key: nil, verify: true), "loading a NaCl signed JWT and with implicit (verification) key 'kid'")
        let kid = jwt.header["kid"] as? String
        XCTAssert(kid != nil && kid! == pk, "mismatch PK / kid in loaded JWT")
    }

    func test_HS256_JWT_from_string() {
        let jwt_hs256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFCR293UEhjSXRwb3ZlVnpyclFzU25rNjVjX3FoS3ZmamQtNHd5UFVmVVEifQ.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTQ3ODk4NjA1Iiwic2NvcGUiOiJwaG9uZSIsImF1ZCI6Imh0dHBzOi8vNS1kb3QtYXV0aGVudGlxaW8uYXBwc3BvdC5jb20iLCJzdWIiOiJhQkdvd1BIY0l0cG92ZVZ6cnJRc1NuazY1Y19xaEt2ZmpkLTR3eVBVZlVRIiwidHlwZSI6Im1vYmlsZSJ9.qrq-939iZydNFdNsTosbSteghjc2VcK9EZVklxfQgiU"
        let jwt = JWT(algorithms: ["HS256","HS512","RS512"])
        XCTAssert(jwt.loads(jwt_hs256, key: "secret", verify: true), "loading a HS256 signed JWT and specified (verification) hash")
        XCTAssert(jwt.body["phone_number"] as? String == "+306947898605", "wrong 'phone' scope in loaded JWT")
        var jwtn = JWTNaCl(algorithms: ["HS512","RS512"])
        XCTAssert(jwt.loads(jwt_hs256, key: "secret", verify: true), "loading a HS256 signed JWT in a NaCl subclass should work too")
    }

    func test_random_string_as_JWT() {
        var error: NSError?
        var jwt = JWT(algorithms: ["HS512","RS512"])
        XCTAssert(jwt.loads("randomstring", verify: false, error: &error) == false, "random string should not load")
        XCTAssert(jwt.body.count == 0, "loading garbage should leave body empty")
    }

    func test_alg_none_with_sig() {
        let jwt_none_sig = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.qrq-939iZydNFdNsTosbSteghjc2VcK9EZVklxfQgiU"
        var jwt = JWT(algorithms: ["none","HS512","RS512"])
        XCTAssert(jwt.loads(jwt_none_sig, verify: true) == false, "alg=none with a signature is not valid")
        jwt = JWT(algorithms: ["HS512","RS512"])
        XCTAssert(jwt.loads(jwt_none_sig, verify: false) == false, "none is not on whitelist")
    }

    func test_timestamps() {
        let date = NSDate()
        let now = UInt(date.timeIntervalSince1970)
        let jwt = JWT(algorithms: ["none","HS512","RS512"])
        var jwt_dated = JWT(algorithms: ["none","HS512","RS512"])
        var s = ""
        jwt_dated.body["exp"] = now-100
        s = jwt_dated.dumps()!
        XCTAssert(jwt.loads(s, verify: true) == false, "exp in past \(s)")
        jwt_dated.body["exp"] = now+100 // and leave it there for next tests
        s = jwt_dated.dumps()!
        XCTAssert(jwt.loads(s, verify: true) == true, "exp in future \(s)")
        jwt_dated.body["nbf"] = now+100
        s = jwt_dated.dumps()!
        XCTAssert(jwt.loads(s, verify: true) == false, "nbf in future \(s)")
        jwt_dated.body["nbf"] = now-100 // and leave it there for next tests
        s = jwt_dated.dumps()!
        XCTAssert(jwt.loads(s, verify: true) == true, "nbf in past \(s)")
        jwt_dated.body["iat"] = now+100
        s = jwt_dated.dumps()!
        XCTAssert(jwt.loads(s, verify: true) == false, "iat in future \(s)")
        jwt_dated.body["iat"] = now-100 // and leave it there for next tests
        s = jwt_dated.dumps()!
        XCTAssert(jwt.loads(s, verify: true) == true, "iat in past \(s)")
    }

    func test_NaCl_JWT_load_dump_load() {
        let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiYUJHb3dQSGNJdHBvdmVWenJyUXNTbms2NWNfcWhLdmZqZC00d3lQVWZVUSJ9.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTQ3ODk4NjA1Iiwic2NvcGUiOiJwaG9uZSIsImF1ZCI6Imh0dHBzOlwvXC81LWRvdC1hdXRoZW50aXFpby5hcHBzcG90LmNvbSIsInN1YiI6ImFCR293UEhjSXRwb3ZlVnpyclFzU25rNjVjX3FoS3ZmamQtNHd5UFVmVVEiLCJ0eXBlIjoibW9iaWxlIn0.kD4YcuAb7v3cxlRZTrUbew1lWiY3G8uEmRguizy1KJs"
        // generate keys
        let sodium = Sodium()!
        let seed = NSMutableData(length: sodium.sign.SeedBytes)!
        SecRandomCopyBytes(kSecRandomDefault, UInt(sodium.sign.SeedBytes), UnsafeMutablePointer<UInt8>(seed.mutableBytes))
        let kp = sodium.sign.keyPair(seed: seed)
        // This is an example of a functional test case.
        XCTAssert(kp != nil, "Key pair generation")
        var jwt = JWTNaCl(algorithms: ["Ed25519"])
        XCTAssert(jwt.loads(jwt_ed, key: kp!.publicKey, verify: true) == false, "NaCl JWT should not validate with wrong key")
        // but is still loaded (DO WE WANT THAT?) NOW FAILS
        jwt = JWTNaCl(header: ["alg":"Ed25519","kid":"XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"], body: ["hello":"world"], algorithms: ["Ed25519"])
        let jwt_str = jwt.dumps(key: kp!.secretKey)! // valid Ed25519 signed token
        XCTAssert(jwt.loads(jwt_str, verify: true) == false, "verify a generated JWT with wrong kid when signed with fresh key")
        XCTAssert(jwt.loads(jwt_str, key: kp!.publicKey, verify: true), "verify a generated JWT with its public key")
    }

    func testPerformanceVerify() {
        // This is an example of a performance test case.
        let jwt_str = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiYUJHb3dQSGNJdHBvdmVWenJyUXNTbms2NWNfcWhLdmZqZC00d3lQVWZVUSJ9.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTQ3ODk4NjA1Iiwic2NvcGUiOiJwaG9uZSIsImF1ZCI6Imh0dHBzOlwvXC81LWRvdC1hdXRoZW50aXFpby5hcHBzcG90LmNvbSIsInN1YiI6ImFCR293UEhjSXRwb3ZlVnpyclFzU25rNjVjX3FoS3ZmamQtNHd5UFVmVVEiLCJ0eXBlIjoibW9iaWxlIn0.kD4YcuAb7v3cxlRZTrUbew1lWiY3G8uEmRguizy1KJs"
        var jwt = JWTNaCl(algorithms: ["none","HS512","RS512"])
        self.measureBlock() {
            let ok = jwt.loads(jwt_str, verify: true)
        }
    }
    
}
