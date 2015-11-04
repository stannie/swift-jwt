//
//  String+JWT.swift
//  SwiftJWT
//
//  Created by Chris Ziogas on 05/11/15.
//  Copyright © 2015 RoundZero bv. All rights reserved.
//

import Foundation

extension String {
    
    // MARK: - base64 extensions
    func base64SafeUrlDecode() -> NSData {
        return self.base64SafeUrlDecode([])
    }
    
    func base64SafeUrlDecode(options: NSDataBase64DecodingOptions) -> NSData {
        var s: String = self;
        
        s = s.stringByReplacingOccurrencesOfString("-", withString: "+") // 62nd char of encoding
        s = s.stringByReplacingOccurrencesOfString("_", withString: "/") // 63rd char of encoding
        
        switch (s.characters.count % 4) {     // Pad with trailing '='s
        case 0: break; // No pad chars in this case
        case 2: s += "=="; break; // Two pad chars
        case 3: s += "="; break; // One pad char
        default: print("Illegal base64url string!")
        }
        
        return NSData(base64EncodedString: s, options: options)!
    }
}