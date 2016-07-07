package scorex.crypto.authds.skiplist

import scorex.crypto.authds.DataProof
import scorex.crypto.authds.merkle.MerkleTree.Position
import scorex.crypto.encode._
import scorex.crypto.hash.CryptographicHash


case class SLPath(levHashes: Seq[(CryptographicHash#Digest, Int)]) extends DataProof {

  lazy val hashes: Seq[CryptographicHash#Digest] = levHashes.map(_._1)

  override def toString: String = s"(hashes: ${hashes.map(Base58.encode)})"
}