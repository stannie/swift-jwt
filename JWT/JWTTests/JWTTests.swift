//
//  JWTTests.swift
//  JWTTests
//
//  Created by Stan P. van de Burgt on 3/31/15.
//  Copyright (c) 2015 RoundZero bv. All rights reserved.
//

import XCTest
import SwiftJWT
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
        let expected_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6IndvcmxkIn0.bqxXg9VwcbXKoiWtp-osd0WKPX307RjcN7EuXbdq-CE"
        let jwt = JWT(header: ["alg":"HS256"], body: ["hello":"world"], algorithms: ["HS256","HS512","RS512"])
        let s = try! jwt.dumps("secret", jti_len: 0) // without jti to enable replay
        XCTAssert(s == expected_jwt, "JWT.dumps() unexpected jwt")
    }

    func test_NaCl_JWT_from_string() {
        let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiWE43VnBFWDF1Q3h4aHZ3VXVhY1lodVU5dDZ1eGdMYWhSaUxlU0VIRU5payJ9.eyJmb28iOiJiYXIifQ.a2dDcKXByKxiouOLnXUm7YUKHMGOU3yn_g91C90e8YmKjlF1_9ylAKukfMm6Y6WS3dZp2ysaglzzTnVxnRYyDQ"
        // let sk = "YHWUUc0P6SY46WaDdnssE8NpFsQQxJrvmdOrpU9X0wU"
        let pk = "XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"
        let jwt = JWTNaCl(algorithms: ["Ed25519"])
        
        XCTempAssertNoThrowError("loading a NaCl signed JWT and specified public (verification) key") {
            try jwt.loads(jwt_ed, b64key: pk, verify: true)
        }
        
        XCTempAssertNoThrowError("loading a NaCl signed JWT and with implicit (verification) key 'kid'") {
            try jwt.loads(jwt_ed, key: nil, verify: true)
        }

        let kid = jwt.header["kid"] as? String
        XCTAssert(kid != nil && kid! == pk, "mismatch PK / kid in loaded JWT")
    }

    func test_HS256_JWT_from_string() {
        let jwt_hs256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFCR293UEhjSXRwb3ZlVnpyclFzU25rNjVjX3FoS3ZmamQtNHd5UFVmVVEifQ.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTQ3ODk4NjA1Iiwic2NvcGUiOiJwaG9uZSIsImF1ZCI6Imh0dHBzOi8vNS1kb3QtYXV0aGVudGlxaW8uYXBwc3BvdC5jb20iLCJzdWIiOiJhQkdvd1BIY0l0cG92ZVZ6cnJRc1NuazY1Y19xaEt2ZmpkLTR3eVBVZlVRIiwidHlwZSI6Im1vYmlsZSJ9.qrq-939iZydNFdNsTosbSteghjc2VcK9EZVklxfQgiU"
        let jwt = JWT(algorithms: ["HS256","HS512","RS512"])
        XCTempAssertNoThrowError("loading a HS256 signed JWT and specified (verification) hash") {
            try jwt.loads(jwt_hs256, key: "secret", verify: true)
        }

        XCTAssert(jwt.body["phone_number"] as? String == "+306947898605", "wrong 'phone' scope in loaded JWT")
        let jwtn = JWTNaCl(algorithms: ["HS256","HS512","RS512"])
        XCTempAssertNoThrowError("loading a HS256 signed JWT in a NaCl subclass should work too") {
            try jwtn.loads(jwt_hs256, key: "secret", verify: true)
        }
    }

    func test_random_string_as_JWT() {
        let jwt = JWT(algorithms: ["HS512","RS512"])
        
        XCTAssertThrowsSpecificError(JWTError.NotValid) {
            try jwt.loads("randomstring", verify: false)
        }
        XCTAssert(jwt.body.count == 0, "loading garbage should leave body empty")
    }

    func test_alg_none_with_sig() {
        let jwt_none_sig = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.qrq-939iZydNFdNsTosbSteghjc2VcK9EZVklxfQgiU"
        var jwt = JWT(algorithms: ["none","HS512","RS512"])
        
        XCTAssertThrowsSpecificError(JWTError.VerifyFailed) {
            try jwt.loads(jwt_none_sig, verify: true)
        }
        XCTAssert(jwt.body.count == 0, "loading garbage should leave body empty")
        
        jwt = JWT(algorithms: ["HS512","RS512"])
        
        XCTAssertThrowsSpecificError(JWTError.AlgorithmIsNotWhitelisted) {
            try jwt.loads(jwt_none_sig, verify: false)
        }
    }

    func test_timestamps() {
        let date = NSDate()
        let now = UInt(date.timeIntervalSince1970)
        let jwt = JWT(algorithms: ["none","HS512","RS512"])
        let jwt_dated = JWT(algorithms: ["none","HS512","RS512"])
        var s = ""
        jwt_dated.body["exp"] = now-100
        s = try! jwt_dated.dumps()
        XCTAssertThrowsSpecificError(JWTError.VerifyFailed) {
            try jwt.loads(s, verify: true)
            // "exp in past \(s)"
        }
        
        jwt_dated.body["exp"] = now+100 // and leave it there for next tests
        s = try! jwt_dated.dumps()
        XCTempAssertNoThrowError("exp in future \(s)") {
            try jwt.loads(s, verify: true)
        }
        jwt_dated.body["nbf"] = now+100
        s = try! jwt_dated.dumps()
        XCTAssertThrowsSpecificError(JWTError.VerifyFailed) {
            try jwt.loads(s, verify: true)
            // "nbf in future \(s)"
        }
        
        jwt_dated.body["nbf"] = now-100 // and leave it there for next tests
        s = try! jwt_dated.dumps()
        XCTempAssertNoThrowError("nbf in past \(s)") {
            try jwt.loads(s, verify: true)
        }
        
        jwt_dated.body["iat"] = now+100
        s = try! jwt_dated.dumps()
        XCTAssertThrowsSpecificError(JWTError.VerifyFailed) {
            try jwt.loads(s, verify: true)
            // "iat in future \(s)"
        }
        
        jwt_dated.body["iat"] = now-100 // and leave it there for next tests
        s = try! jwt_dated.dumps()
        XCTempAssertNoThrowError("iat in past \(s)") {
            try jwt.loads(s, verify: true)
        }
    }

    func test_NaCl_JWT_load_dump_load() {
        let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiYUJHb3dQSGNJdHBvdmVWenJyUXNTbms2NWNfcWhLdmZqZC00d3lQVWZVUSJ9.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTQ3ODk4NjA1Iiwic2NvcGUiOiJwaG9uZSIsImF1ZCI6Imh0dHBzOlwvXC81LWRvdC1hdXRoZW50aXFpby5hcHBzcG90LmNvbSIsInN1YiI6ImFCR293UEhjSXRwb3ZlVnpyclFzU25rNjVjX3FoS3ZmamQtNHd5UFVmVVEiLCJ0eXBlIjoibW9iaWxlIn0.kD4YcuAb7v3cxlRZTrUbew1lWiY3G8uEmRguizy1KJs"
        // generate keys
        let sodium = Sodium()!
        let seed = NSMutableData(length: sodium.sign.SeedBytes)!
        SecRandomCopyBytes(kSecRandomDefault, sodium.sign.SeedBytes, UnsafeMutablePointer<UInt8>(seed.mutableBytes))
        let kpp = sodium.sign.keyPair(seed: seed)
        XCTAssert(kpp != nil, "Key pair generation")
        let kp = kpp!
        var jwt = JWTNaCl(algorithms: ["Ed25519"])
        XCTAssertThrowsSpecificError(JWTError.VerifyFailed) {
            try jwt.loads(jwt_ed, key: kp.publicKey, verify: true)
            // "NaCl JWT should not validate with wrong key")
        }
        
        // but is still loaded (DO WE WANT THAT?) NOW FAILS
        jwt = JWTNaCl(header: ["alg":"Ed25519","kid":"XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"], body: ["hello":"world"], algorithms: ["Ed25519"])
        let jwt_str = try! jwt.dumps(kp.secretKey) // valid Ed25519 signed token
        XCTAssertThrowsSpecificError(JWTError.VerifyFailed) {
            try jwt.loads(jwt_str, verify: true)
            //"verify a generated JWT with wrong kid when signed with fresh key")
        }
        
        XCTempAssertNoThrowError("verify a generated JWT with its public key") {
            try jwt.loads(jwt_str, key: kp.publicKey, verify: true)
        }
    }

    func test_NaCl_JWT_loadHS256_dumpEd() {
        let jwt_hs256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFCR293UEhjSXRwb3ZlVnpyclFzU25rNjVjX3FoS3ZmamQtNHd5UFVmVVEifQ.eyJwaG9uZV9udW1iZXIiOiIrMzA2OTQ3ODk4NjA1Iiwic2NvcGUiOiJwaG9uZSIsImF1ZCI6Imh0dHBzOi8vNS1kb3QtYXV0aGVudGlxaW8uYXBwc3BvdC5jb20iLCJzdWIiOiJhQkdvd1BIY0l0cG92ZVZ6cnJRc1NuazY1Y19xaEt2ZmpkLTR3eVBVZlVRIiwidHlwZSI6Im1vYmlsZSJ9.qrq-939iZydNFdNsTosbSteghjc2VcK9EZVklxfQgiU"
        // generate keys
        let sodium = Sodium()!
        let seed = NSMutableData(length: sodium.sign.SeedBytes)!
        SecRandomCopyBytes(kSecRandomDefault, sodium.sign.SeedBytes, UnsafeMutablePointer<UInt8>(seed.mutableBytes))
        let kpp = sodium.sign.keyPair(seed: seed)
        XCTAssert(kpp != nil, "Key pair generation")
        let kp = kpp!

        let jwtn = JWTNaCl(algorithms: ["Ed25519","HS256"])
        XCTempAssertNoThrowError("could not load a HS256 JWT") {
            try jwtn.loads(jwt_hs256, key: "secret", verify: true)
        }
        
        XCTempAssertNoThrowError("could not stringify a HS256 JWT") {
            try jwtn.dumps("secret")
        }
        
        jwtn.header["alg"] = "Ed25519" // set alg to NaCl type tokens
        // try! jwtn.dumps("secret") // THIS -> nil ; WHY?
        
        XCTempAssertNoThrowError("could not stringify a HS256 JWT") {
            let myjwt = try jwtn.dumps(kp.secretKey) // valid Ed25519 signed token
            
            XCTempAssertNoThrowError("loading of generated Ed25519 JWT failed") {
                try jwtn.loads(myjwt, key: kp.publicKey, verify: true)
            }
        }
    }

    func testPerformanceVerify() {
        // This is an example of a performance test case.
        let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiWE43VnBFWDF1Q3h4aHZ3VXVhY1lodVU5dDZ1eGdMYWhSaUxlU0VIRU5payJ9.eyJmb28iOiJiYXIifQ.a2dDcKXByKxiouOLnXUm7YUKHMGOU3yn_g91C90e8YmKjlF1_9ylAKukfMm6Y6WS3dZp2ysaglzzTnVxnRYyDQ"
        let pk = "XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"
        let jwt = JWTNaCl(algorithms: ["Ed25519"])
        self.measureBlock() {
            let _ = try! jwt.loads(jwt_ed, b64key: pk, verify: true)
        }
    }
}
