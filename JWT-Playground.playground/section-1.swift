// Playground - noun: a place where people can play

/*:
 ### Table of Contents
 
 1. [HS256 Load](HS256 Load)
 2. [HS256 Dump](HS256 Dump)
 3. [Ed25519 Dump](Ed25519 Dump)
 */

import SwiftJWT

/*:
 ### HS256 Load
 Example: load a HS256 signed JWT from a string, and generate a new one with a new password
 */

let jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6InBob25lIiwicGhvbmVfbnVtYmVyIjoiKzE2NTAyODU1NjAwIiwidHlwZSI6ImxhbmRsaW5lIiwiYXVkIjoiaHR0cHM6Ly9hdXRoZW50aXEuY29tIn0.CAqNpbmOA9lz9aq7Sp1NqqbdLJARmFKY3L7CKcgXLNU"

var jwt = JWT(algorithms: ["none", "HS256"])

do {
    try jwt.loads(jwt_str, key: "secret")
    print(jwt.header)
    print(jwt.body)

    let new_jwt = try jwt.dumps("geheim")
    
    assert(jwt_str != new_jwt)

} catch {
    print(error)
    print("Validate of SignedJWT failed")
}


/*:
 ### HS256 Dump
 Example: dump a HS256 signed JWT from a dictionary
 */

jwt = JWT(header: ["alg":"HS256"],
            body: [
                "sub": "1234567890",
                "name": "John Doe",
                "admin": true
            ], algorithms: nil)

do {
    print(try jwt.dumps("secret"))

} catch {
    print(error)
    print("Validate of SignedJWT failed")
}


/*:
 ### Ed25519 Load
 Example: load an Ed25519 signed JWT from a string
 */

let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiWE43VnBFWDF1Q3h4aHZ3VXVhY1lodVU5dDZ1eGdMYWhSaUxlU0VIRU5payJ9.eyJmb28iOiJiYXIifQ.a2dDcKXByKxiouOLnXUm7YUKHMGOU3yn_g91C90e8YmKjlF1_9ylAKukfMm6Y6WS3dZp2ysaglzzTnVxnRYyDQ"
let sk = "YHWUUc0P6SY46WaDdnssE8NpFsQQxJrvmdOrpU9X0wU"
let pk = "XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"


jwt = JWTNaCl(algorithms: ["Ed25519"])

do {
    try jwt.loads(jwt_ed, verify: false, mandatory: ["foo"])
    
    print(jwt.header)
    print(jwt.body)
    
} catch {
    print(error)
    print("Validate of SignedJWT failed")
}
