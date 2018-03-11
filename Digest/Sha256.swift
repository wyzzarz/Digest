//
//  Sha256.swift
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

///
/// `Sha256` is a Swift implementation of the SHA-256 standard similar to `Sha256_Nist`.  Please
/// refer to `Sha256_Nist` for further details.
///
/// It should not be used in a production environment as this Swift implementation severely
/// underperforms when compared to CommonCrypto.  It is understood that the CommonCrypto
/// implemtation leverages hardware acceleration.
///
/// Unlike `Sha256_Nist`, `Sha256` utilizes an `InputStream` to decrease memory usage while
/// processing a file.  And pointers.
///

public struct Sha256 {

  fileprivate static let h: [UInt32] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]
  
  fileprivate static let k: [UInt32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]
  
  /// 256 bit message digest.
  public var digest: Data?
  
  /// Produce a SHA-256 message digest from a resource on a remote server or local file.
  ///
  /// Returns `nil` if an input stream cannot be created from the url.
  ///
  /// - Parameter url: URL for resource to be hashed.
  public init?(url: URL) {
    guard let input = InputStream(url: url) else { return nil }
    self.init(input: input)
  }
  
  /// Produce a SHA-256 message digest from a string
  ///
  /// Returns `nil` if the string cannot be encoded to a byte buffer using `utf8`.
  ///
  /// - Parameter url: String to be hashed.
  public init?(string: String) {
    guard let data = string.data(using: .utf8) else { return nil }
    self.init(data: data)
  }
  
  /// Produce a SHA-256 message digest from a data source.
  ///
  /// - Parameter data: Data source to be hashed.
  public init(data: Data) {
    self.init(input: InputStream(data: data))
  }

  /// Produce a SHA-256 message digest from an input stream.
  ///
  /// - Parameter input: Input stream to be hashed.
  public init(input: InputStream) {
    digest = W(input: input).digest
  }

  ///
  /// Message schedule to generate message digest from an input message.
  ///
  fileprivate struct W {

    /// Length of the message in bits.
    fileprivate var length: UInt64 = 0

    /// 256 bit message digest.
    public var digest: Data?
    
    ///
    /// 'Pointer' provides a wrapper to read and write to memory.  It automatically allocates
    /// memory and releases memory when no longer used.
    ///
    fileprivate class Pointer<T> {

      fileprivate enum PointerError: Error {
        
        case InvalidType
        
      }
      
      /// Instances for this type to be allocated - per block.
      fileprivate let count: Int
      
      /// Number of blocks to be held.
      fileprivate let blocks: Int

      /// Number of instances in this block.
      fileprivate var length: Int {
        guard let start = start else { return 0 }
        return min((totalBytes - start) / stride, count)
      }
      
      /// Number of bytes to be allocated.
      fileprivate let bytes: Int
      
      /// Number of bytes for this type.
      fileprivate var stride: Int { return MemoryLayout<T>.stride }
      
      /// Alignment of bytes for this type.
      fileprivate var alignment: Int { return MemoryLayout<T>.alignment }
      
      /// Pointer to bytes.
      fileprivate let p: UnsafeMutableRawPointer
      
      /// Pointer to typed bytes.
      fileprivate lazy var p32: UnsafeMutablePointer<UInt32>? = {
        return T.self == UInt32.self ? p.bindMemory(to: UInt32.self, capacity: count) : nil
      }()
      fileprivate lazy var p8: UnsafeMutablePointer<UInt8>? = {
        return T.self == UInt8.self ? p.bindMemory(to: UInt8.self, capacity: count) : nil
      }()
      
      /// Index to start of block.
      fileprivate var start: Int?
      
      /// Total bytes in the buffer.
      fileprivate var totalBytes: Int = 0
      
      /// Holds reference to input stream.
      fileprivate weak var lastInputStream: InputStream?
      
      /// Allocates a pointer for the specified type 'T' to hold the specified number of instances.
      ///
      /// The pointer will be automatically released.
      ///
      /// - Parameters:
      ///   - count: Number of instances to allocate per block.
      ///   - blocks: Number of blocks to allocate.  Default is 1.
      fileprivate init(count: Int, blocks: Int = 1) {
        self.count = count
        self.blocks = blocks
        bytes = MemoryLayout<T>.stride * count * blocks
        totalBytes = bytes
        p = UnsafeMutableRawPointer.allocate(bytes: bytes, alignedTo: MemoryLayout<T>.alignment)
      }
      
      deinit {
        p8?.deinitialize(count: count)
        p32?.deinitialize(count: count)
        p.deallocate(bytes: bytes, alignedTo: alignment)
      }
      
      /// A textual representation of bytes as decimal values.
      fileprivate var description: String {
        var description = ""
        for i in start == nil ? 0..<totalBytes : start!..<min(start!+count,totalBytes) {
          if description.count > 0 { description += ", " }
          let x = p.load(fromByteOffset: i, as: UInt8.self)
          description += "\(x)"
        }
        return "\(start == nil ? totalBytes : min(totalBytes-start!, count)):[" + description + "]"
      }

      /// A textual representation of bytes as hexadecimal values.
      fileprivate var hexDescription: String {
        var description = ""
        for i in start == nil ? 0..<totalBytes : start!..<min(start!+count,totalBytes) {
          if description.count > 0 { description += ", " }
          let x = p.load(fromByteOffset: i, as: UInt8.self)
          description += String(x, radix: 16, uppercase: false)
        }
        return "\(start == nil ? totalBytes : min(totalBytes-start!, count)):[" + description + "]"
      }
      
      fileprivate func reset(to: T, count: Int) {
        start = 0
        totalBytes = count
        p32?.initialize(to: to as? UInt32 ?? 0, count: count)
        p8?.initialize(to: to as? UInt8 ?? 0, count: count)
      }
      
      fileprivate func hasBytesAvailable(input: InputStream) -> Bool {
        if start != nil && start! < totalBytes { return true }
        return input.hasBytesAvailable
      }
      
      fileprivate func load(input: InputStream) throws -> Int {
        // Exit if there is no buffer pointer.
        guard p8 != nil else { throw PointerError.InvalidType }

        if lastInputStream != input {
          totalBytes = 0
          lastInputStream = input
        }

        // Advance to next block.
        if start != nil {
          start! += count
          // Reset start if we are at the end of the buffer.
          if start! >= totalBytes { start = nil }
        }

        // Read data from input - if necessary.
        if start == nil {
          // Exit if there are no more bytes to read.
          guard input.hasBytesAvailable else {
            totalBytes = 0
            lastInputStream = nil
            return 0
          }

          // Read into buffer.
          totalBytes = input.read(p8!, maxLength: bytes)

          // Exit if there was an error reading from the input stream.
          if let error = input.streamError { throw error }

          // Exit if there is no more data in the input stream.
          if totalBytes == 0 { return 0 }

          start = 0
        }

        // Return number of bytes in this block.
        return length
      }
      
    }
    
    /// Hash value.
    fileprivate let h = Pointer<UInt32>(count: 8)

    /// Message schedule.
    fileprivate let w = Pointer<UInt32>(count: 64)
    
    /// Message buffer.
    fileprivate let b = Pointer<UInt8>(count: 64, blocks: 8192)
    
    // Timers
    var timer = Elapsed()

    /// Creates a message schedule from the input stream.
    ///
    /// - Parameter input: Input stream for message.
    fileprivate init(input: InputStream) {
      // Open the messsage input stream.
      input.open()
      defer { input.close() }

      // Initialize hash value.
      for (i, x) in Sha256.h.enumerated() { (h.p32! + i).pointee = x }

      // Process input.
      if !input.hasBytesAvailable {
        // Handle empty message.
        b.reset(to: 0, count: 0)
        _ = add(pointer: b)
      } else {
        // Process message in 512 bit blocks.
        do {
          while b.hasBytesAvailable(input: input) {
            let rc = try b.load(input: input)
            length += UInt64(rc * 8)
            if add(pointer: b) { break }
          }
        } catch {
          return
        }
      }
      
      // Prepare the 256 bit message digest.
      final()
    }
    
    /// Add message block to hash.
    ///
    /// - Parameters:
    ///   - pointer: Pointer to message block.
    fileprivate mutating func add(pointer: Pointer<UInt8>, padding: Bool = true) -> Bool {
      // Pad last message block.
      let last = pointer.length < pointer.count
      var overflow: Pointer<UInt8>?
      if padding && last {
        overflow = pad(pointer: pointer)
      }
      
      // Copy message block into beginning of message schedule.
      stride(from: 0, to: 64, by: 4).forEach { (i) in
        let wp = w.p + i
        let pi = pointer.p8! + (pointer.start ?? 0) + i
        (wp).storeBytes(of: (pi + 3).pointee, as: UInt8.self)
        (wp + 1).storeBytes(of: (pi + 2).pointee, as: UInt8.self)
        (wp + 2).storeBytes(of: (pi + 1).pointee, as: UInt8.self)
        (wp + 3).storeBytes(of: (pi).pointee, as: UInt8.self)
      }

      // Fill remainder of message schedule.
      for i in 16...63 {
        let wp = w.p32! + i
        let s0: (_ x: UInt32) -> UInt32 = { (x) in return x.rotateRight(by: 7) ^ x.rotateRight(by: 18) ^ x.shiftRight(by: 3) }
        let s1: (_ x: UInt32) -> UInt32 = { (x) in return x.rotateRight(by: 17) ^ x.rotateRight(by: 19) ^ x.shiftRight(by: 10) }
        wp.pointee = (wp - 16).pointee &+ s0((wp - 15).pointee) &+ (wp - 7).pointee &+ s1((wp - 2).pointee)
      }

      // Initialize working variables.
      var a_ = h.p32![0]
      var b_ = h.p32![1]
      var c_ = h.p32![2]
      var d_ = h.p32![3]
      var e_ = h.p32![4]
      var f_ = h.p32![5]
      var g_ = h.p32![6]
      var h_ = h.p32![7]

      // Calculate working variables.
      var wp = w.p32!
      for i in 0...63 {
        let s1 = e_.rotateRight(by: 6) ^ e_.rotateRight(by: 11) ^ e_.rotateRight(by: 25)
        let ch = (e_ & f_) ^ (~e_ & g_)
        let t1 = h_ &+ s1 &+ ch &+ Sha256.k[i] &+ wp.pointee
        let s0 = a_.rotateRight(by: 2) ^ a_.rotateRight(by: 13) ^ a_.rotateRight(by: 22)
        let maj = (a_ & b_) ^ (a_ & c_) ^ (b_ & c_)
        let t2 = s0 &+ maj
        h_ = g_
        g_ = f_
        f_ = e_
        e_ = d_ &+ t1
        d_ = c_
        c_ = b_
        b_ = a_
        a_ = t1 &+ t2
        wp = wp.advanced(by: 1)
      }

      // Calculate hash value
      let hp = h.p32!
      hp.pointee = a_ &+ (hp).pointee
      (hp + 1).pointee = b_ &+ (hp + 1).pointee
      (hp + 2).pointee = c_ &+ (hp + 2).pointee
      (hp + 3).pointee = d_ &+ (hp + 3).pointee
      (hp + 4).pointee = e_ &+ (hp + 4).pointee
      (hp + 5).pointee = f_ &+ (hp + 5).pointee
      (hp + 6).pointee = g_ &+ (hp + 6).pointee
      (hp + 7).pointee = h_ &+ (hp + 7).pointee

      // Process overflow padding - if necessary.
      if overflow != nil {
        _ = add(pointer: overflow!, padding: false)
        return true
      }
      
      return last
    }
    
    // Pad message such that the length is a multiple of 512 bits.  Pad with '1' bit, '0' bits,
    // and length of message (as a 64 bit unsigned integer).
    fileprivate func pad(pointer: Pointer<UInt8>) -> Pointer<UInt8>? {
      // Append the bit “1” to the end of the message.
      let p = pointer.p8!.advanced(by: (pointer.start ?? 0) + pointer.length)
      p.pointee = 0x80

      // '0' padding.
      let k = b.count - pointer.length - 1 - MemoryLayout<UInt64>.stride

      // Handle overflow
      if (pointer.length + 1 + MemoryLayout<UInt64>.stride) > b.count {
        // Pad this message block
        let k0 = pointer.count - pointer.length - 1
        (p + 1).initialize(to: 0, count: k0)
        pointer.totalBytes = pointer.count

        // Create a new overflow message block
        let overflow = Pointer<UInt8>(count: b.count)
        let k1 = pointer.count - MemoryLayout<UInt64>.stride
        let op = overflow.p8!
        op.initialize(to: 0, count: k1)
        (op + k1).withMemoryRebound(to: UInt64.self, capacity: 1) { (p64: UnsafeMutablePointer<UInt64>) in
          p64.pointee = self.length.bigEndian
        }
        overflow.totalBytes = overflow.count
        return overflow
      }

      // Otherwise pad this message block
      (p + 1).initialize(to: 0, count: k)
      (p + 1 + k).withMemoryRebound(to: UInt64.self, capacity: 1) { (p64: UnsafeMutablePointer<UInt64>) in
        p64.pointee = self.length.bigEndian
      }
      pointer.totalBytes += 1 + k + MemoryLayout<UInt64>.stride
      
      return nil
    }
    
    /// Creates the 256 bit message digest from the working variables.
    fileprivate mutating func final() {
      var digest = Data()
      for i in 0..<h.count {
        var x = (h.p32! + i).pointee.bigEndian
        digest.append(UnsafeBufferPointer<UInt32>(start: &x, count: 1))
      }
      self.digest = digest
    }

  }
  
}

