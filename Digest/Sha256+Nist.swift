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
/// Sha256_Nist  is a Swift implementation of the SHA-256 standard.  It should be used as a
/// reference only and not be used in a production environment.  It is not a high performance
/// solution.
///
/// Sha256_Nist is based on the FIPS 180-4 Secure Hash Standard (SHS) publication provided by the
/// National Institute of Standards and Technology (NIST).
///
/// See https://csrc.nist.gov/publications/detail/fips/180/4/final for details on the publication.
/// See http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf for a copy of the publication.
///
/// The details of SHA-256 can be found in section 6.2 of the publication.  The notes and comments
/// below reflect the text included in the publication.
///
/// Definition:
///
/// (6.2) SHA-256 may be used to hash a message, M, having a length of l bits, where 0 <= l < 2^64.
/// The algorithm uses 1) a message schedule of sixty-four 32-bit words, 2) eight working variables
/// of 32 bits each, and 3) a hash value of eight 32-bit words. The final result of SHA-256 is a
/// 256-bit message digest.
///
/// The words of the message schedule are labeled W0, W1,..., W63. The eight working variables are
/// labeled a, b, c, d, e, f, g, and h. The words of the hash value are labeled H0(i), H1(i), ...,
/// H7(i), which will hold the initial hash value, H(0), replaced by each successive intermediate
/// hash value (after each message block is processed), H(i), and ending with the final hash value,
/// H(N). SHA- 25 also uses two temporary words, T1 and T2.
///
public struct Sha256_Nist {
  
  /// (5.3.3) The initial hash value, H(0), shall consist of the following eight 32-bit words, in
  /// hex.  These words were obtained by taking the roots of the first eight prime numbers.
  fileprivate static let h: [UInt32] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]
  
  /// (4.2.2) SHA-256 Constants as a sequence of sixty-four constanst 32-bit words, K0{256}, K1{256},
  /// ..., K63{256}. These words represent the first thirty-two bits of the fractional parts of the
  /// cube roots of the first sixty-four prime numbers.
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
  
  struct Size {
    
    static let chunk = 64
    
  }
  
  /// Length of the message in bits.
  fileprivate var length: UInt64 = 0
  
  //// 256-bit message digest.
  public var digest: Data?
  
  /// (6.2.1) Set the initial hash value, H(0).
  fileprivate var h: [UInt32] = Sha256_Nist.h
  
  /// Message schedule of sixty-four 32-bit words.
  fileprivate var w = Array<UInt32>(repeating: 0, count: 64)
  
  /// Produce a SHA-256 message digest from a data source.
  ///
  /// - Parameter data: Data source to be hashed.
  public init(data: Data) {
    process(data: data)
  }
  
  /// Produce a SHA-256 message digest from a resource on a remote server or local file.
  ///
  /// Returns `nil` if an input stream cannot be created from the url.
  ///
  /// - Parameter url: URL for resource to be hashed.
  public init?(url: URL) {
    guard let data = try? Data(contentsOf: url) else { return nil }
    self.init(data: data)
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
  
  /// (5.2) The message and its padding must be parsed into N 512-bit blocks, M(1), M(2),..., M(N).
  fileprivate mutating func process(data: Data) {
    if data.count == 0 {
      // Handle empty message
      chunk(chunk: Array<UInt8>())
    } else {
      data.withUnsafeBytes { (p: UnsafePointer<UInt8>) in
        stride(from: 0, to: data.count, by: 64).forEach { i in
          let length = min(64, data.count - i)
          self.length += UInt64(length * 8)
          let bytes = Array(UnsafeBufferPointer<UInt8>(start: (p + i), count: length / MemoryLayout<UInt8>.stride))
          chunk(chunk: bytes)
        }
        if (data.count % 64 == 0) {
          // Ensure message padding is added when the message block is already a multiple of
          // 512 bits.
          chunk(chunk: Array<UInt8>())
        }
      }
    }
    
    // Prepare the 256-bit message digest.
    prepareMessageDigest()
  }
  
  /// (6.2.2) The SHA-256 hash computation uses functions and constants previously defined in
  /// Sec. 4.1.2 and Sec. 4.2.2, respectively. Addition (+) is performed modulo 2^32.
  fileprivate mutating func chunk(chunk: [UInt8]) {
    var bytes = chunk

    // (5.1) Padding the message to ensure that the message is a multiple of 512 bits.  Padding
    // can be inserted before hash computation begins on a message, or at any other time during the
    // hash computation prior to processing the block(s) that will contain the padding.
    //
    // (5.1.1) Suppose that the length of the message, M, is l bits. Append the bit “1” to the end
    // of the message, followed by k zero bits, where k is the smallest, non-negative solution to
    // the equation l + 1 + k = 448 mod 512 . Then append the 64-bit block that is equal to the
    // number l expressed using a binary representation.  The length of the padded message should
    // now be a multiple of 512 bits.
    let count = bytes.count
    if count < Size.chunk {
      // Length of the padded message should be 512 bits (or 1024 bits when appending the "1" bit
      // and length of the message exceeds 512 bits).
      let k = (count < 56 ? Size.chunk : Size.chunk * 2) - 1 - count - MemoryLayout<UInt64>.stride
      // Append the bit “1” to the end of the message.
      bytes.append(0x80)
      // Followed by k zero bits.
      bytes.append(contentsOf: Array<UInt8>(repeating: 0x00, count: k))
      // Then append the 64-bit block that is equal to the number l expressed using a binary
      // representation.
      bytes.append(contentsOf: length.unpack())
    }

    // (6.2.2.1) Prepare the message schedule.
    
    // Copy the message block into the first 16 words of the message schedule.
    for i in 0...15 {
      w[i] = UInt32.pack(bytes: Array<UInt8>(bytes[(i * 4)...(i * 4 + 3)]))
    }
    
    // Fill the remainder of the message schedule with 48 words.
    for i in 16...63 {
      let s0: (_ x: UInt32) -> UInt32 = { (x) in return x.rotateRight(by: 7) ^ x.rotateRight(by: 18) ^ x.shiftRight(by: 3) }
      let s1: (_ x: UInt32) -> UInt32 = { (x) in return x.rotateRight(by: 17) ^ x.rotateRight(by: 19) ^ x.shiftRight(by: 10) }
      w[i] = w[i - 16] &+ s0(w[i - 15]) &+ w[i - 7] &+ s1(w[i - 2])
    }

    // (6.2.2.2) Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the
    // (i-1)st hash value.
    var a = h[0]
    var b = h[1]
    var c = h[2]
    var d = h[3]
    var e = h[4]
    var f = h[5]
    var g = h[6]
    var h_ = h[7]
    
    // (6.2.2.3) For t=0 to 63.
    for i in 0...63 {
      let s1 = e.rotateRight(by: 6) ^ e.rotateRight(by: 11) ^ e.rotateRight(by: 25)
      let ch = (e & f) ^ (~e & g)
      let t1 = h_ &+ s1 &+ ch &+ Sha256_Nist.k[i] &+ w[i]
      let s0 = a.rotateRight(by: 2) ^ a.rotateRight(by: 13) ^ a.rotateRight(by: 22)
      let maj = (a & b) ^ (a & c) ^ (b & c)
      let t2 = s0 &+ maj
      h_ = g
      g = f
      f = e
      e = d &+ t1
      d = c
      c = b
      b = a
      a = t1 &+ t2
    }
    
    // (6.2.2.4) Compute the ith intermediate hash value H(i).
    h[0] = a &+ h[0]
    h[1] = b &+ h[1]
    h[2] = c &+ h[2]
    h[3] = d &+ h[3]
    h[4] = e &+ h[4]
    h[5] = f &+ h[5]
    h[6] = g &+ h[6]
    h[7] = h_ &+ h[7]

    // Process any overflow when chunk is padded to 1024 bits.
    if bytes.count > 64 {
      bytes.removeSubrange(0..<64)
      self.chunk(chunk: bytes)
    }
  }
  
  /// Concatenates the eight 32 bit hash values into the 256 bit message digest.
  fileprivate mutating func prepareMessageDigest() {
    // After repeating steps one through four (6.2.2) a total of N times (i.e., after processing
    // M(N)), the resulting 256 bit message digest of the message, M, is
    //   H0(N)||H1(N)||H2(N)||H3(N)||H4(N)||H5(N)||H6(N)||H7(N)
    var digest = Data()
    for element in h {
      var x = element.bigEndian
      digest.append(UnsafeBufferPointer<UInt32>(start: &x, count: 1))
    }
    self.digest = digest
  }
  
}
