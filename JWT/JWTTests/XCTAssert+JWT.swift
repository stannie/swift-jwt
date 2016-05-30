//
//  XCTAssert+JWT.swift
//  SwiftJWT
//
//  Created by Chris Ziogas on 05/11/15.
//  Copyright © 2015 RoundZero bv. All rights reserved.
//

import XCTest

func XCTempAssertNoThrowError(message: String = "", file: StaticString = #file, line: UInt = #line, _ block: () throws -> ())
{
    do {try block()}
    catch
    {
        let msg = (message == "") ? "Tested block threw unexpected error." : message
        XCTFail(msg, file: file, line: line)
    }
}

// assert if a method throws the expected ErrorType
func XCTAssertThrowsSpecificError(kind: ErrorType, _ message: String = "", file: StaticString = #file, line: UInt = #line, _ block: () throws -> ())
{
    do
    {
        try block()
        
        let msg = (message == "") ? "Tested block did not throw expected \(kind) error." : message
        XCTFail(msg, file: file, line: line)
    }
    catch let error as NSError
    {
        let expected = kind as NSError
        if ((error.domain != expected.domain) || (error.code != expected.code))
        {
            let msg = (message == "") ? "Tested block threw \(error), not expected \(kind) error." : message
            XCTFail(msg, file: file, line: line)
        }
    }
}