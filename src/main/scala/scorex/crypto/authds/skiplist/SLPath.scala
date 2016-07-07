package scorex.crypto.authds.skiplist

import scorex.crypto.authds.DataProof
import scorex.crypto.authds.merkle.MerkleTree.Position
import scorex.crypto.encode._
import scorex.crypto.hash.CryptographicHash


case class SLPath(hashes: Seq[CryptographicHash#Digest], directions: Seq[Direction] = Seq()) extends DataProof {

  //directions should be empty for usual proof and contains hash directions for extended proof
  require(directions.isEmpty || directions.length == hashes.length)

  override def toString: String = s"(hashes: ${hashes.map(Base58.encode)})"
}

sealed trait Direction

case object Right extends Direction

case object Down extends Direction