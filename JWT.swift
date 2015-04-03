//
//  JWT.swift
//  
//  Stan P. van de Burgt
//  stan@vandeburgt.com
//  (c) 2015

import Foundation

public class JWT {
    // https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-4
    // base class; supports alg: none, HS256, HS384, HS512

    public var header: [String: AnyObject] = ["alg": "none"] {
        didSet {
            if header["alg"] as? String == nil {
                self.header["alg"] = "none"     // if not present, insert alg
            }
        }
    }
    public var body: [String: AnyObject] = [:]
    var blacklist: [String] = []                // algorithms that are deemed invalid

    public init(blacklist: [String] = []) {
        self.blacklist = blacklist
    }

    public init(header: [String: AnyObject], body: [String: AnyObject], blacklist: [String] = []) {
        self.header = header
        self.body = body
        self.blacklist = blacklist
        if header["alg"] as? String == nil {
            self.header["alg"] = "none"         // if not present, insert alg (copy of didSet{} ad init does not trigger it)
        }
    }

    public func loads(jwt: String, key: NSData?, verify: Bool = true, error: NSErrorPointer = nil) -> Bool {
        // load a JWT string into this object
        self.header = [:]
        self.body = [:]
        var sig = ""

        // split into parts, header, body, optional signature
        let parts: [String] = jwt.componentsSeparatedByString(".")
        switch parts.count {
        case 2: break
        case 3: sig = parts[2]
        default:
            if error != nil {
                error.memory = NSError(domain: "JWT", code: 1, userInfo: nil) // TODO: actual error details
            }
            return false
        }

        // decode the header (a URL-safe, base 64 encoded JSON dict) from 1st part
        let hdr_data = parts[0].base64SafeUrlDecode()
        if let dictionary = NSJSONSerialization.JSONObjectWithData(hdr_data, options: NSJSONReadingOptions(0), error: error)  as? [String: AnyObject] {
            self.header = dictionary // also sets self.alg and value for "alg" key by the didSet{} observer
        }
        else {
            return false
        }
        // check whether alg parameter is on blacklist
        let algorithm = header["alg"] as? String
        for alg in self.blacklist {
            if alg == algorithm {
                return false
            }
        }
        // decode the body (a URL-safe base 64 encoded JSON dict) from the 2nd part
        if parts.count > 1 {
            let body_data = parts[1].base64SafeUrlDecode()
            if let dictionary = NSJSONSerialization.JSONObjectWithData(body_data, options: NSJSONReadingOptions(0), error: error)  as? [String: AnyObject] {
                self.body = dictionary
            }
        }
        else {
            return false // TODO: populate NSError
        }

        if verify {
            // verify the signature, a URL-safe base64 encoded string
            let hdr_body: String = parts[0] + "." + parts[1] // header & body of a JWT
            let data = hdr_body.dataUsingEncoding(NSUTF8StringEncoding)!
            if self.verify_signature(data, signature: sig, algorithm: algorithm!, key: key) == false {
                return false // TODO: populate NSError
            }
            // verify content fields
            if self.verify_content() == false {
                return false
            }
        }
        return true
    }

    // helper function for plain strings as key
    public func loads(jwt: String, key: String, verify: Bool = true, error: NSErrorPointer = nil) -> Bool {
        let key_raw = key.dataUsingEncoding(NSUTF8StringEncoding)!
        return loads(jwt, key: key_raw, verify: verify, error: error)
    }
    
    // helper function for base64 strings as key
    public func loads(jwt: String, b64key: String, verify: Bool = true, error: NSErrorPointer = nil) -> Bool {
        let key_raw = b64key.base64SafeUrlDecode()
        return loads(jwt, key: key_raw, verify: verify, error: error)
    }

    public func dumps(key: NSData, error: NSErrorPointer = nil) -> String? {
        var data = ""
        if let h = NSJSONSerialization.dataWithJSONObject(self.header, options: nil, error: error) {
            data = h.base64SafeUrlEncode()
            if let b = NSJSONSerialization.dataWithJSONObject(self.body, options: nil, error: error) {
                data = data + "." + b.base64SafeUrlEncode()
                let data_raw = data.dataUsingEncoding(NSUTF8StringEncoding)!
                let algorithm = header["alg"] as? String
                if let sig = self.signature(data_raw, algorithm: algorithm!, key: key) {
                    return data + "." + sig
                }
            }
        }
        return nil // TODO: populate NSError
    }

    // helper function for plain strings as key
    public func dumps(key: String, error: NSErrorPointer = nil) -> String? {
        let key_raw = key.dataUsingEncoding(NSUTF8StringEncoding)!
        return dumps(key_raw, error: error)
    }

    public func setnonce(length: Int = 32) -> String {
        var bytes = NSMutableData(length: length)!
        SecRandomCopyBytes(kSecRandomDefault, UInt(length), UnsafeMutablePointer<UInt8>(bytes.mutableBytes))
        let jti = bytes.base64SafeUrlEncode()
        self.body["jti"] = jti
        return jti
    }
    
    func signature(msg: NSData, algorithm: String, key: NSData) -> String? {
        switch algorithm {
        case "none":  return ""
        case "HS256": return msg.base64digest(HMACAlgorithm.SHA256, key: key)
        case "HS384": return msg.base64digest(HMACAlgorithm.SHA384, key: key)
        case "HS512": return msg.base64digest(HMACAlgorithm.SHA512, key: key)
        default:      return nil
        }
    }

    func verify_signature(msg: NSData, signature: String, algorithm: String, key: NSData? = nil) -> Bool {
        if key == nil && algorithm != "none" {
            return false
        }
        switch algorithm {
        case "none":  return signature == "" // if "none" then the signature shall be empty
        case "HS256": return msg.base64digest(HMACAlgorithm.SHA256, key: key!) == signature
        case "HS384": return msg.base64digest(HMACAlgorithm.SHA384, key: key!) == signature
        case "HS512": return msg.base64digest(HMACAlgorithm.SHA512, key: key!) == signature
        default:      return false
        }
    }

    func verify_content() -> Bool {
        let date = NSDate()
        let now = UInt(date.timeIntervalSince1970)

        if let exp = self.body["exp"] as? UInt {
            if now > exp { return false }
        }
        if let nbf = self.body["nbf"] as? UInt {
            if now < nbf { return false }
        }
        if let iat = self.body["iat"] as? UInt {
            if now < iat { return false }
        }
        return true
    }
}

// MARK: - NaCl signatures
// subclass with additional sign/verify for "Ed25519" signatures

public class JWTNaCl: JWT {

    override func signature(msg: NSData, algorithm: String, key: NSData) -> String? {
        if algorithm == "Ed25519" {
            return msg.nacl_signature(key)
        }
        else {
            return super.signature(msg, algorithm: algorithm, key: key)
        }
    }

    override func verify_signature(msg: NSData, signature: String, algorithm: String, key: NSData? = nil) -> Bool {
        if algorithm == "Ed25519" {
            if key == nil {
                // use the "kid" field as base64 key string as key if no key provided.
                if let kid = header["kid"] as? String {
                    return msg.nacl_verify(signature, key: kid.base64SafeUrlDecode())
                }
            }
            else {
                return msg.nacl_verify(signature, key: key!)
            }
        }
        else {
            return super.verify_signature(msg, signature: signature, algorithm: algorithm, key: key)
        }
        return false
    }

    override func verify_content() -> Bool {
        if let kid = self.header["kid"] as? String {
            let pk = kid.base64SafeUrlDecode(nil)
            if pk == nil || pk!.length != 32 {
                return false
            }
        }
        else {
            return false // kid is not optional
        }
        if let sub = self.body["sub"] as? String {
            let id = sub.base64SafeUrlDecode(nil)
            if id == nil || id!.length != 32 {
                return false
            }
        }
        return super.verify_content() // run the parent tests too
    }
}

// MARK: - base64 extensions

extension String {
    func base64SafeUrlDecode() -> NSData { // ! ?
        return self.base64SafeUrlDecode(nil)
    }
    
    func base64SafeUrlDecode(options: NSDataBase64DecodingOptions) -> NSData! {
        var s: String = self;
        
        s = s.stringByReplacingOccurrencesOfString("-", withString: "+") // 62nd char of encoding
        s = s.stringByReplacingOccurrencesOfString("_", withString: "/") // 63rd char of encoding
        
        switch (countElements(s) % 4) {     // Pad with trailing '='s
        case 0: break; // No pad chars in this case
        case 2: s += "=="; break; // Two pad chars
        case 3: s += "="; break; // One pad char
        default: return nil
        }
        
        return NSData(base64EncodedString: s, options: options)!
    }
}

extension NSData {
    func base64SafeUrlEncode() -> String {
        return self.base64SafeUrlEncode(nil)
    }
    
    func base64SafeUrlEncode(options: NSDataBase64EncodingOptions) -> String {
        var s: String = self.base64EncodedStringWithOptions(options)
        if let idx = find(s, "=") {
            s = s.substringToIndex(idx) // remove trailing '='s
        }
        s = s.stringByReplacingOccurrencesOfString("/", withString: "_") // 63rd char of encoding
        s = s.stringByReplacingOccurrencesOfString("+", withString: "-") // 62nd char of encoding
        return s
    }
}

// MARK: - HMACAlgorithm
// See http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework (answer from stephencelis)

import CommonCrypto

// Inspired by: http://stackoverflow.com/questions/24099520/commonhmac-in-swift

enum HMACAlgorithm {
    case MD5, SHA1, SHA224, SHA256, SHA384, SHA512
    
    func toCCEnum() -> CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .MD5:
            result = kCCHmacAlgMD5
        case .SHA1:
            result = kCCHmacAlgSHA1
        case .SHA224:
            result = kCCHmacAlgSHA224
        case .SHA256:
            result = kCCHmacAlgSHA256
        case .SHA384:
            result = kCCHmacAlgSHA384
        case .SHA512:
            result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    func digestLength() -> Int {
        var result: CInt = 0
        switch self {
        case .MD5:
            result = CC_MD5_DIGEST_LENGTH
        case .SHA1:
            result = CC_SHA1_DIGEST_LENGTH
        case .SHA224:
            result = CC_SHA224_DIGEST_LENGTH
        case .SHA256:
            result = CC_SHA256_DIGEST_LENGTH
        case .SHA384:
            result = CC_SHA384_DIGEST_LENGTH
        case .SHA512:
            result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

import Sodium
// swift wrapper of LibSodium, a NaCl implementation https://github.com/jedisct1/swift-sodium
// git checkout 176033d7c1cbc4dfe4bed648aa230c9e14ab9426 # for Swift 1.1, as latest is 1.2

extension NSData {

    func base64digest(algorithm: HMACAlgorithm, key: NSData) -> String! {
        let data = self.bytes
        let dataLen = UInt(self.length)
        let digestLen = algorithm.digestLength()
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        let keyData = key.bytes
        let keyLen = UInt(key.length)
        
        CCHmac(algorithm.toCCEnum(), keyData, keyLen, data, dataLen, result)
        let hdata = NSData(bytes: result, length: digestLen)
        result.destroy()
        
        return hdata.base64SafeUrlEncode()
    }

    func nacl_signature(key: NSData) -> String! {
        let sodium = Sodium()
        if let sig = sodium?.sign.signature(self, secretKey: key) {
            return sig.base64SafeUrlEncode()
        }
        return nil
    }
    func nacl_verify(signature: String, key: NSData) -> Bool {
        if let sodium = Sodium() {
            let sig_raw = signature.base64SafeUrlDecode()
            return sodium.sign.verify(self, publicKey: key, signature: sig_raw)
        }
        return false
    }
}

// END
