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
    func base64SafeUrlDecode(_ options: Data.Base64DecodingOptions = []) -> Data? {
        var s = self
        
        s = s.replacingOccurrences(of: "-", with: "+") // 62nd char of encoding
        s = s.replacingOccurrences(of: "_", with: "/") // 63rd char of encoding
        
        switch (s.characters.count % 4) {     // Pad with trailing '='s
        case 0: break; // No pad chars in this case
        case 2: s += "=="; break; // Two pad chars
        case 3: s += "="; break; // One pad char
        default: print("Illegal base64url string!")
        }
        
        return NSData(base64Encoded: s, options: options) as? Data
    }
}
