//
//  SwiftJWT.swift
//
//  Stan P. van de Burgt
//  stan@vandeburgt.com
//  (c) RoundZero 2015
//  Project Authentiq

import Foundation

public enum JWTError: ErrorType {
    case NotValid
    case LoadFailed
    case DecodeFailed
    
    case AlgorithmIsNotWhitelisted
    case VerifyFailed
    case DumpFailed
    
    case ExpiredIAT
    case ExpiredNBF
    case ExpiredEXP
}

public class JWT {
    // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
    // base class; supports alg: none, HS256, HS384, HS512
    // TODO: add support for RS256, RS384, RS512 (almost there!)
    // TODO: add support for PS256, PS384, PS512
    
    public var header: [String: AnyObject] = ["alg": "none", "typ": "JWT", ] {
        // JWT header
        didSet {
            if header["alg"] as? String == nil {
                self.header["alg"] = "none"     // if not present, insert alg
            }
        }
    }
    public var body: [String: AnyObject] = [:]  // JWT payload
    var algorithms: [String] = []               // algorithms that are valid on loads(), dumps() and setting 'alg' header
    
    public init(algorithms: [String]) {
        self.algorithms = implemented(algorithms) // only add algoritms that are implemented()
    }
    
    //    public init(header: [String: AnyObject], body: [String: AnyObject]) {
    //        self.init(header: header, body: body, algorithms: nil) {
    //    }
    
    public init(header: [String: AnyObject], body: [String: AnyObject], algorithms: [String]?) {
        self.header = header
        self.body = body
        if header["alg"] as? String == nil {
            self.header["alg"] = "none"         // if not present, insert 'alg'
        }
        if let alg = algorithms {
            // TODO: decide if this was smart, as it could introduce a vulnerability for the caller
            self.algorithms = implemented(alg) // only add algoritms that are implemented()
        }
        else {
            self.algorithms = [self.header["alg"] as! String]
        }
        if header["typ"] as? String == nil {
            self.header["typ"] = "JWT"          // if not present, insert 'typ' element
        }
    }
    
    public func loads(jwt: String, key: NSData? = nil, verify: Bool = true, mandatory: [String] = []) throws {
        
        // load a JWT string into this object
        var sig = ""
        
        // clear object properties
        self.header = [:]
        self.body = [:]
        
        // split JWT string into parts: header, body, optional signature
        let parts: [String] = jwt.componentsSeparatedByString(".")
        switch parts.count {
        case 2: break
        case 3: sig = parts[2]
        default:
            throw JWTError.NotValid
        }
        
        // decode the header (a URL-safe, base 64 encoded JSON dict) from 1st part
        let hdr_data = parts[0].base64SafeUrlDecode()
        guard let hdr = try NSJSONSerialization.JSONObjectWithData(hdr_data, options: NSJSONReadingOptions(rawValue: 0)) as? [String: AnyObject] else {
            
            throw JWTError.DecodeFailed
        }
        
        // check that "alg" header is on whitelist (and thus implemented) ; even if verify == false
        guard let algorithm = hdr["alg"] as? String
            where self.whitelisted(algorithm) else {
                
                throw JWTError.AlgorithmIsNotWhitelisted
        }
        
        // decode the body (a URL-safe base 64 encoded JSON dict) from the 2nd part
        let body_data = parts[1].base64SafeUrlDecode()
        guard let payload = try NSJSONSerialization.JSONObjectWithData(body_data, options: NSJSONReadingOptions(rawValue: 0))  as? [String: AnyObject] else {
            
            throw JWTError.DecodeFailed
        }
        
        // all went well so far, so let's set the object properties
        // TODO: set properties even later (but are needed by verification methods now)
        self.header = hdr
        self.body = payload
        
        if verify {
            // verify the signature, a URL-safe base64 encoded string
            let hdr_body: String = parts[0] + "." + parts[1] // header & body of a JWT
            let data = hdr_body.dataUsingEncoding(NSUTF8StringEncoding)!
            if self.verify_signature(data, signature: sig, algorithm: algorithm, key: key) == false {
                self.header = [:]; self.body = [:] // reset
                
                throw JWTError.VerifyFailed
            }
            
            // verify content fields
            do {
                try self.verify_content()
                
            } catch {
                self.header = [:]; self.body = [:] // reset
                
                throw error
            }
        }
    }
    
    // convenience method for plain strings as key
    public func loads(jwt: String, key: String, verify: Bool = true, mandatory: [String] = []) throws {
        let key_raw = key.dataUsingEncoding(NSUTF8StringEncoding)!
        try loads(jwt, key: key_raw, verify: verify, mandatory: mandatory)
    }
    
    // convenience method for base64 strings as key
    public func loads(jwt: String, b64key: String, verify: Bool = true, mandatory: [String] = []) throws {
        let key_raw = b64key.base64SafeUrlDecode()
        try loads(jwt, key: key_raw, verify: verify, mandatory: mandatory)
    }
    
    public func dumps(key: NSData? = nil, jti_len: UInt = 16) throws -> String {
        
        // create a JWT string from this object
        // TODO: some way to indicate that some fields should be generated, next to jti; e.g. nbf and iat
        var payload = self.body
        // if 'jti' (the nonce) not present in body, and it is requested (jti_len > 0), set one
        if payload["jti"] as? String == nil && jti_len > 0 {
            // generate a random string (nonce) of length jti_len for body item 'jti'
            // https://developer.apple.com/library/ios/documentation/Security/Reference/RandomizationReference/index.html
            let bytes = NSMutableData(length: Int(jti_len))!
            // SecRandomCopyBytes(rnd: SecRandomRef, count: Int, bytes: UnsafeMutablePointer<UInt8>)
            SecRandomCopyBytes(kSecRandomDefault, Int(jti_len), UnsafeMutablePointer<UInt8>(bytes.mutableBytes))
            payload["jti"] = bytes.base64SafeUrlEncode()
        }
        // TODO: set iat, nbf in payload here if not set & requested?
        do {
            let h = try NSJSONSerialization.dataWithJSONObject(self.header, options: [])
            var data = h.base64SafeUrlEncode()
            
            let b = try NSJSONSerialization.dataWithJSONObject(payload, options: [])
            data = data + "." + b.base64SafeUrlEncode()
            // check that "alg" header is on whitelist (and thus implemented)
            let alg = self.header["alg"] as? String
            if !self.whitelisted(alg) {
                throw JWTError.AlgorithmIsNotWhitelisted
            }
            
            let data_raw = data.dataUsingEncoding(NSUTF8StringEncoding)!
            if let sig = self.signature(data_raw, algorithm: alg!, key: key) {
                return data + "." + sig
            }
            
        } catch {
            // no need to handle something here
            // JSON Encode might throw here
        }
        
        throw JWTError.DumpFailed
    }
    
    // convenience method for plain strings as key
    public func dumps(key: String, jti_len: UInt = 16) throws -> String {
        let key_raw = key.dataUsingEncoding(NSUTF8StringEncoding)!
        return try dumps(key_raw, jti_len: jti_len)
    }
    
    func whitelisted(algorithm: String?) -> Bool {
        for alg in self.algorithms {
            if alg == algorithm {
                return true
            }
        }
        return false
    }
    
    func implemented(algorithm: String?) -> Bool {
        let algorithms = ["none", "HS256", "HS384", "HS512"]
        // TODO: add RS256, RS384, RS512, PS256, PS384, PS512 when rsa_* methods below are done
        for alg in algorithms {
            if alg == algorithm {
                return true
            }
        }
        return false
    }
    
    func implemented(algorithms: [String]) -> [String] {
        var result: [String] = []
        for alg in algorithms {
            if implemented(alg) {
                result.append(alg)
            }
        }
        return result
    }
    
    func signature(msg: NSData, algorithm: String, key: NSData?) -> String? {
        // internal function to compute the signature (third) part of a JWT
        if let key_raw = key {
            switch algorithm {
            case "HS256": return msg.base64digest(HMACAlgorithm.SHA256, key: key_raw)
            case "HS384": return msg.base64digest(HMACAlgorithm.SHA384, key: key_raw)
            case "HS512": return msg.base64digest(HMACAlgorithm.SHA512, key: key_raw)
            case "RS256": return msg.rsa_signature(HMACAlgorithm.SHA256, key: key_raw)
            case "RS384": return msg.rsa_signature(HMACAlgorithm.SHA384, key: key_raw)
            case "RS512": return msg.rsa_signature(HMACAlgorithm.SHA512, key: key_raw)
            case "PS256": return msg.rsa_signature(HMACAlgorithm.SHA256, key: key_raw) // TODO: convert PS to RS key
            case "PS384": return msg.rsa_signature(HMACAlgorithm.SHA384, key: key_raw)
            case "PS512": return msg.rsa_signature(HMACAlgorithm.SHA512, key: key_raw)
            default:      return nil
            }
        }
        else {
            return algorithm == "none" ? "" : nil
        }
    }
    
    func verify_signature(msg: NSData, signature: String, algorithm: String, key: NSData? = nil) -> Bool {
        // internal function to verify the signature (third) part of a JWT
        if key == nil && algorithm != "none" {
            return false
        }
        switch algorithm {
        case "none":  return signature == "" // if "none" then the signature shall be empty
        case "HS256": return msg.base64digest(HMACAlgorithm.SHA256, key: key!) == signature
        case "HS384": return msg.base64digest(HMACAlgorithm.SHA384, key: key!) == signature
        case "HS512": return msg.base64digest(HMACAlgorithm.SHA512, key: key!) == signature
        case "RS256": return msg.rsa_verify(HMACAlgorithm.SHA256, signature: signature, key: key!)
        case "RS384": return msg.rsa_verify(HMACAlgorithm.SHA384, signature: signature, key: key!)
        case "RS512": return msg.rsa_verify(HMACAlgorithm.SHA512, signature: signature, key: key!)
        case "PS256": return msg.rsa_verify(HMACAlgorithm.SHA256, signature: signature, key: key!) // TODO: convert PS to RS key
        case "PS384": return msg.rsa_verify(HMACAlgorithm.SHA384, signature: signature, key: key!)
        case "PS512": return msg.rsa_verify(HMACAlgorithm.SHA512, signature: signature, key: key!)
        default:      return false
        }
    }
    
    // TODO: some way to enforce that e.g. iat and nbf are present
    // TODO: verification of iss and aud when given in loads()
    func verify_content() throws {
        // internal function to verify the content (header and body) parts of a JWT
        let date = NSDate()
        let now = UInt(date.timeIntervalSince1970)
        
        guard let typ = self.header["typ"] as? String
            where typ == "JWT" else {
                throw JWTError.NotValid // 'typ' shall be 'JWT'
        }
        
        if let exp = self.body["exp"] as? UInt
            where now > exp {
            
            // TODO: also false if "exp" is not of type UInt
            throw JWTError.ExpiredEXP
        }
        if let nbf = self.body["nbf"] as? UInt
            where now < nbf {
            
            // TODO: also false if "nbf" is not of type UInt
            throw JWTError.ExpiredNBF
        }
        if let iat = self.body["iat"] as? UInt
            where now < iat {
            
            // TODO: also false if "iat" is not of type UInt
            throw JWTError.ExpiredIAT
        }
    }
}

// END