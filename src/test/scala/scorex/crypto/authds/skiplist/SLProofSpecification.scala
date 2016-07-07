package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class SLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)
  val sl = new SkipList()(storage, hf)
  val elements = genEl(100)
  val nonIncludedElements = genEl(101).diff(elements)
  sl.update(SkipListUpdate(toDelete = Seq(), toInsert = elements))

  property("SLExtended proof check") {
    forAll(slelementGenerator) { newSE: SLElement =>
      whenever(!sl.contains(newSE)) {
        val proof = sl.elementProof(newSE).asInstanceOf[SLNonExistenceProof]
        proof.isEmpty shouldBe true

        val newRootHash = ExtendedSLProof.recalculate(sl.rootHash, proof, newSE)
        sl.insert(newSE)

        Base58.encode(sl.rootHash) shouldBe Base58.encode(newRootHash)
        sl.rootHash shouldEqual newRootHash
      }
    }
  }


  property("SLExistenceProof serialization") {
    elements.foreach { e =>
      proofCheck(e, defined = true)
    }
  }


  property("SLNoneExistanceProof serialization") {
    nonIncludedElements.foreach { e =>
      proofCheck(e, defined = false)
    }
  }

  def proofCheck(e: SLElement, defined: Boolean): Unit = {
    val proof = sl.elementProof(e)
    proof.isDefined shouldBe defined
    proof.check(sl.rootHash) shouldBe true

    val decoded = SLProof.decode(proof.bytes).get
    decoded.isDefined shouldBe defined
    decoded.check(sl.rootHash) shouldBe true

    decoded.bytes shouldEqual proof.bytes
  }


}
