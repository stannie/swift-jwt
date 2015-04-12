// Playground - noun: a place where people can play

import SwiftJWT

// Example: load a HS256 signed JWT from a sting, and generate a new one with a new password

let jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6InBob25lIiwicGhvbmVfbnVtYmVyIjoiKzE2NTAyODU1NjAwIiwidHlwZSI6ImxhbmRsaW5lIiwiYXVkIjoiaHR0cHM6Ly9hdXRoZW50aXEuY29tIn0.CAqNpbmOA9lz9aq7Sp1NqqbdLJARmFKY3L7CKcgXLNU"

var jwt = JWT(algorithms: ["none","HS256"])
var j = jwt.loads(jwt_str, key: "secret")
println(jwt.dumps("geheim"))

let jwt_ed = "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIiwia2lkIjoiWE43VnBFWDF1Q3h4aHZ3VXVhY1lodVU5dDZ1eGdMYWhSaUxlU0VIRU5payJ9.eyJmb28iOiJiYXIifQ.a2dDcKXByKxiouOLnXUm7YUKHMGOU3yn_g91C90e8YmKjlF1_9ylAKukfMm6Y6WS3dZp2ysaglzzTnVxnRYyDQ"
let sk = "YHWUUc0P6SY46WaDdnssE8NpFsQQxJrvmdOrpU9X0wU"
let pk = "XN7VpEX1uCxxhvwUuacYhuU9t6uxgLahRiLeSEHENik"
jwt = JWTNaCl(algorithms: ["Ed25519","none"])
jwt.loads(jwt_ed)
jwt.header["alg"] = "none"
println(jwt.dumps()!)
