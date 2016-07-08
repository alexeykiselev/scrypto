package scorex.crypto.authds.skiplist

import com.google.common.primitives.Ints
import play.api.libs.json._
import scorex.crypto.authds.AuthData
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{CommutativeHash, CryptographicHash}

import scala.annotation.tailrec
import scala.util.Try

sealed trait SLProof extends AuthData[SLPath] {
  type Digest = CryptographicHash#Digest

  def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hashFunction: HF): Boolean

  def bytes: Array[Byte]

  /**
   * Returns false if the element is in skiplist, true otherwise.
   */
  def isEmpty: Boolean

  /**
   * Returns true if the element is in skiplist, false otherwise.
   */
  def isDefined: Boolean = !isEmpty


}

/**
 * SLProof that is enough to recalculate root hash without whole skiplist
 */
sealed trait ExtendedSLProof extends SLProof

object ExtendedSLProof {
  type Digest = CryptographicHash#Digest


  //  def recalculate[HF <: CommutativeHash[_]](proof: ExtendedSLProof, newEl: SLElement, maxLev: Int)
  //                                           (implicit hf: HF): Digest = {
  //    proof match {
  //      case SLNonExistenceProof(e, left, right) =>
  //        require(e == newEl)
  //        val rightHash: Digest = left.proof.hashes.head
  //        val newProofs = (hf(rightHash, hf(newEl.bytes)), 0) +: left.proof.levHashes.tail
  //
  //        //Все что приходило справа в левый пруф на высоте <=, чем высота, на которую мы добавили элемент попадает в новый элемент
  //        //При этом из левого пруфа они убираются, и вместо их все добавляется хеш на высоте нового элемента
  //
  //
  ////        newProofs.foldLeft(hf.hash(left.e.bytes)) { (x, y) =>
  ////          //x - calculated, y - from list
  ////          val replaced = toReplace.getOrElse(Base58.encode(y._1), y._1)
  ////          println(s"calc: ${Base58.encode(x)}, ${Base58.encode(replaced)}")
  ////          hf.hash(x, y._1)
  ////        }
  //      case _ => ???
  //    }
  //
  //  }


  //начинаем справа налево и обновляем доказательства
  def recalculateProofs[HF <: CommutativeHash[_]](proofs: Seq[ProofToRecalculate])
                                                 (implicit hf: HF): Seq[ProofToRecalculate] = {
    val sorted = proofs.sortBy(_.newEl).reverse

    @tailrec
    def loop(proofsRest: Seq[ProofToRecalculate], acc: Seq[ProofToRecalculate] = Seq()): Seq[ProofToRecalculate] = {
      val p = proofsRest.head
      val leftProofs = proofsRest.tail
      //pairs of old and rew elements in self chain
      @tailrec
      def calcNewSelfElements(v1: Digest, v2: Digest, restProofs: Seq[LevHash],
                              acc: Seq[(LevHash, LevHash)]): Seq[(LevHash, LevHash)] = {
        if (restProofs.nonEmpty) {
          val currentProof = restProofs.head
          val lev = currentProof.l
          val pair: (LevHash, LevHash) = (LevHash(hf(v1, currentProof.h), lev), LevHash(hf(v2, currentProof.h), lev))
          calcNewSelfElements(pair._1.h, pair._2.h, restProofs.tail, pair +: acc)
        } else {
          acc
        }
      }
      val elHashes = (LevHash(hf(p.eProof.e.bytes), 0), LevHash(hf(p.newEl.bytes), 0))
      val toReplace = calcNewSelfElements(elHashes._1.h, elHashes._2.h, p.eProof.proof.levHashes, Seq(elHashes))

      val recalculated: Seq[ProofToRecalculate] = leftProofs map { p =>
        val newHashes: Seq[LevHash] = p.eProof.proof.levHashes.map { lh =>
          val replace = toReplace.find(tr => lh.l == tr._1.l && (lh.h sameElements tr._1.h)).map(_._2).getOrElse(lh)
          require(replace.l == lh.l)
          require(replace.h sameElements lh.h)
          replace
        }
        val newPath = SLPath(newHashes)
        val newProof = p.eProof.copy(proof = newPath, e = p.newEl)
        p.copy(eProof = newProof)
      }
      if (proofsRest.tail.nonEmpty) {
        loop(recalculated, p +: acc)
      } else p +: acc
    }

    //right element proof won`t change
    val newEProof = proofs.head.eProof.copy(e = proofs.head.newEl)
    loop(proofs.head.copy(eProof = newEProof) +: proofs.tail, Seq())
  }

}

case class ProofToRecalculate(newEl: SLElement, eProof: SLExistenceProof)

/**
 *
 * @param e
 * @param left
 * @param right - None for MaxSlElement, Some for others
 */
case class SLNonExistenceProof(e: SLElement, left: SLExistenceProof, right: Option[SLExistenceProof]) extends SLProof
with ExtendedSLProof {
  lazy val bytes: Array[Byte] = {
    val eSize = Ints.toByteArray(e.bytes.length)
    val leftSize = Ints.toByteArray(left.bytes.length)
    val rightSize = Ints.toByteArray(right.map(r => r.bytes.length).getOrElse(0))

    Array(0: Byte) ++ eSize ++ leftSize ++ rightSize ++ e.bytes ++ left.bytes ++ right.map(_.bytes).getOrElse(Array())
  }

  override def isEmpty: Boolean = true

  override def check[HF <: CommutativeHash[_]](rootHash: Digest)(implicit hf: HF): Boolean = {
    val linked: Boolean = right match {
      case None => left.proof.hashes.head sameElements hf(MaxSLElement.bytes)
      case Some(rp) =>
        val tower = left.proof.hashes.head sameElements hf(rp.e.bytes)
        val nonTower = left.proof.hashes.head sameElements hf.hash(hf(rp.e.bytes), rp.proof.hashes.head)
        tower || nonTower
    }
    val rightCheck = right.map(rp => e < rp.e && rp.check(rootHash)).getOrElse(true)

    linked && e > left.e && left.check(rootHash)
  }
}

/**
 * @param e - element to proof
 * @param proof - skiplist path, complementary to data block
 */
case class SLExistenceProof(e: SLElement, proof: SLPath) extends SLProof {

  override def isEmpty: Boolean = false

  lazy val bytes: Array[Byte] = {
    require(proof.hashes.nonEmpty, "Merkle path cannot be empty")
    val dataSize = Ints.toByteArray(e.bytes.length)
    val proofLength = Ints.toByteArray(proof.hashes.length)
    val proofSize = Ints.toByteArray(proof.hashes.head.length)
    val proofBytes = proof.hashes.foldLeft(Array.empty: Array[Byte])((b, mp) => b ++ mp)
    Array(1: Byte) ++ dataSize ++ proofLength ++ proofSize ++ e.bytes ++ proofBytes
  }

  /**
   * Checks that this block is at position $index in tree with root hash = $rootHash
   */
  def check[HF <: CommutativeHash[_]](currentRootHash: Digest)(implicit hashFunction: HF): Boolean = {
    rootHash() sameElements currentRootHash
  }


  def rootHash[HF <: CommutativeHash[_]]()(implicit hashFunction: HF): Digest = {
    proof.hashes.foldLeft(hashFunction.hash(e.bytes)) { (x, y) =>
//      println(s"hash(${Base58.encode(x).take(12)}, ${Base58.encode(y).take(12)}})")
      hashFunction.hash(x, y)
    }
  }
}


object SLProof {
  def decode[HashFunction <: CryptographicHash](bytes: Array[Byte]): Try[SLProof] = Try {
    if (bytes.head == (1: Byte)) {
      decodeExistenceProof(bytes.tail)
    } else {
      decodeNonExistenceProof(bytes.tail)
    }
  }

  private def decodeNonExistenceProof[HashFunction <: CryptographicHash](bytes: Array[Byte]): SLNonExistenceProof = {
    val eSize = Ints.fromByteArray(bytes.slice(0, 4))
    val leftSize = Ints.fromByteArray(bytes.slice(4, 8))
    val rightSize = Ints.fromByteArray(bytes.slice(8, 12))
    val e = SLElement.parseBytes(bytes.slice(12, 12 + eSize)).get
    val left = decodeExistenceProof(bytes.slice(12 + eSize, 12 + eSize + leftSize).tail)
    val right = if (rightSize == 0) None
    else Some(decodeExistenceProof(bytes.slice(12 + eSize + leftSize, 12 + eSize + leftSize + rightSize).tail))
    SLNonExistenceProof(e, left, right)
  }

  private def decodeExistenceProof[HashFunction <: CryptographicHash](bytes: Array[Byte]): SLExistenceProof = {
    val dataSize = Ints.fromByteArray(bytes.slice(0, 4))
    val merklePathLength = Ints.fromByteArray(bytes.slice(4, 8))
    val merklePathSize = Ints.fromByteArray(bytes.slice(8, 12))
    val data = bytes.slice(12, 12 + dataSize)
    val e = SLElement.parseBytes(data).get
    val merklePathStart = 12 + dataSize
    val merklePath = (0 until merklePathLength).map { i =>
      bytes.slice(merklePathStart + i * merklePathSize, merklePathStart + (i + 1) * merklePathSize)
    }
    //TODO parse levels
    SLExistenceProof(e, SLPath(merklePath.map(h => LevHash(h, -1))))
  }
}

object SLExistenceProof {
  implicit def authDataBlockReads[T, HashFunction <: CryptographicHash]
  (implicit fmt: Reads[T]): Reads[SLExistenceProof] = new Reads[SLExistenceProof] {
    def reads(json: JsValue): JsResult[SLExistenceProof] = JsSuccess(SLExistenceProof(
      Base58.decode((json \ "data").as[String]).flatMap(SLElement.parseBytes).get,
      SLPath(
        (json \ "merklePath").get match {
          case JsArray(ts) => ts.map { t =>
            t match {
              case JsString(digest) =>
                Base58.decode(digest)
              case m =>
                throw new RuntimeException("MerklePath MUST be array of strings" + m + " given")
            }
          }.map(h => LevHash(h.get, -1))
          //TODO parse levels
          case m =>
            throw new RuntimeException("MerklePath MUST be a list " + m + " given")
        })
    ))
  }

  implicit def authDataBlockWrites[T, HashFunction <: CryptographicHash](implicit fmt: Writes[T]): Writes[SLExistenceProof]
  = new Writes[SLExistenceProof] {
    def writes(ts: SLExistenceProof) = JsObject(Seq(
      "data" -> JsString(Base58.encode(ts.e.bytes)),
      "merklePath" -> JsArray(
        ts.proof.hashes.map(digest => JsString(Base58.encode(digest)))
      )
    ))
  }
}