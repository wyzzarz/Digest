//
//  Foundation+Digest.swift
//
//  Copyright 2018 Warner Zee
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

import Foundation

extension Array where Element == UInt8 {
  
  /// A textual representation of the array where each byte is output as its hexadecimal value.
  public var hexDescription: String {
    let count = self.count
    var description = "\(count):["
    withUnsafeBytes { (p: UnsafeRawBufferPointer) in
      for i in 0..<count {
        if i > 0 { description += ", " }
        description += String(p[i], radix: 16, uppercase: false)
      }
    }
    description += "]"
    return description
  }
  
}

extension Array where Element == UInt32 {
  
  /// A textual representation of the array where each byte is output as its hexadecimal value.
  public var hexDescription: String {
    let count = self.count * 4
    var description = "\(count):["
    withUnsafeBytes { (p: UnsafeRawBufferPointer) in
      for i in 0..<count {
        if i > 0 { description += ", " }
        description += String(p[i], radix: 16, uppercase: false)
      }
    }
    description += "]"
    return description
  }
  
}

extension Data {
  
  /// A textual representation of the data where each byte is output as its hexadecimal value.
  public var hex: String {
    var hex = String()
    for char in self {
      if char <= 0xf { hex.append("0") }
      hex.append(String(char, radix: 16, uppercase: false))
    }
    return hex
  }
  
}

extension DateFormatter {
  
  /// Date formatted as `HH:mm:ss.SSS`.
  public static let CompactTime: DateFormatter = {
    let df = DateFormatter()
    df.dateFormat = "HH:mm:ss.SSS"
    return df
  }()
  
  /// Converts a date to a string using this date format.
  ///
  /// - Parameter date: Date to be converted.
  /// - Returns: Date formatted as a string or `nil` if there is no date.
  public func string(optional date: Date?) -> String? {
    guard let date = date else { return nil }
    return string(from: date)
  }
  
}

extension String {
  
  /// Writes string to standard output prefixed by when and were the `log` was called from.
  ///
  /// - Parameters:
  ///   - file: Defaults to name of file for caller.
  ///   - line: Defaults to line number for caller.
  ///   - column: Defaults to column number for caller.
  ///   - function: Defaults to function calling `log`.
  ///   - padding: Total width of log.  Default is no padding.
  public func log(file: NSString = #file, line: Int = #line, column: Int = #column, function: String = #function, padding: Int? = nil) {
    let str = "\(DateFormatter.CompactTime.string(from: Date())) \(((file.lastPathComponent) as NSString).deletingPathExtension).\(function):\(line)"
    print("\(str)\(padding != nil ? String(repeating: " ", count: max(1, padding! - str.count - 1)) : " ")- \(self)")
  }
  
}

extension UInt32 {
  
  /// Shifts bits to the right by `n`.
  ///
  /// - Parameter n: Number of bits to shift to the right.
  /// - Returns: A new integer.
  public func shiftRight(by n: Int) -> UInt32 {
    return (self >> n)
  }
  
  /// Circular rotation of bits to the right.
  ///
  /// - Parameter n: Number of bits to shift from the right and over to the left.
  /// - Returns: A new integer.
  public func rotateRight(by n: Int) -> UInt32 {
    return (self >> (n & 31)) | (self << (32 - (n & 31)))
  }
  
  /// Pack four bytes (four 8 bit unsigned integers) into a 32 bit unsigned integer.
  ///
  /// - Parameter bytes: Array of four bytes to be packed.
  /// - Returns: A new integer.
  public static func pack(bytes: [UInt8]) -> UInt32 {
    var x = (UInt32(bytes[0]) << 24)
    x |= UInt32(bytes[1]) << 16
    x |= UInt32(bytes[2]) << 8
    x |= UInt32(bytes[3])
    return x
  }
  
}

extension UInt64 {
  
  /// Unpack a 64 bit unsigned integer into eight bytes (eight 8 bit unsigned integers).
  ///
  /// - Returns: Array of eight bytes.
  public func unpack() -> [UInt8] {
    var x = self.bigEndian
    let l = MemoryLayout<UInt64>.size
    let bytesPtr = withUnsafePointer(to: &x) { $0.withMemoryRebound(to: UInt8.self, capacity: l, { UnsafeBufferPointer(start: $0, count: l) }) }
    return Array(bytesPtr)
  }
  
}

public struct Elapsed: CustomStringConvertible {
  
  public typealias Id = String
  
  fileprivate var elapsed: [Id: TimeInterval] = [:]
  
  fileprivate var started: [Id: Date] = [:]

  public mutating func start(id: Id) {
    stop(id: id)
    started[id] = Date()
  }

  public mutating func stop(id: Id) {
    guard let started = started[id] else { return }
    elapsed[id] = (elapsed[id] ?? 0) - started.timeIntervalSinceNow
    self.started[id] = nil
  }
  
  public mutating func stopAll() {
    for id in started.keys {
      stop(id: id)
    }
  }
  
  public mutating func reset(id: Id) {
    elapsed[id] = nil
    started[id] = nil
  }
  
  public mutating func resetAll() {
    elapsed.removeAll()
    started.removeAll()
  }
  
  public var byIdDescription: String {
    var description = ""
    for id in elapsed.keys.sorted() {
      if description.count > 0 { description += ", \n" }
      description += "  \"\(id)\" : \(elapsed[id] ?? 0)"
    }
    return "{\n\(description)\n}"
  }

  public var description: String {
    return byIdDescription
  }
  
}
