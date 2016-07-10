package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class ExtendedSLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)
  val sl = new SkipList()(storage, hf)
  //  val elements = genEl(6, Some(11))
  val elements = genEl(300)
  val nonIncludedElements = genEl(11).diff(elements)
  sl.update(SkipListUpdate(toDelete = Seq(), toInsert = elements))


  property("SLExtended proof empty check") {
    forAll(slelementGenerator) { newSE: SLElement =>
      //      val sl2 = new SkipList()(storage, hf)
      //      sl2.contains(newSE) shouldBe false
      //
      //      val proof = sl2.elementProof(newSE).asInstanceOf[SLNonExistenceProof]
      //      proof.isEmpty shouldBe true
      //
      //      val newRootHash = ExtendedSLProof.recalculate(proof, newSE, sl2.topNode.level)
      //      sl2.insert(newSE)
      //      val newProof = sl2.elementProof(newSE)
      //      newProof.check(sl2.rootHash)
      //
      //      Base58.encode(sl2.rootHash) shouldBe Base58.encode(newRootHash)
      //      sl2.rootHash shouldEqual newRootHash
      //
      //      sl2.delete(newSE)
    }
  }

  property("SLExtended: recalculate rootHash when update 1 element") {
    val e = elements.last
    sl.contains(e) shouldBe true
    val oldProof = sl.extendedElementProof(e).asInstanceOf[ExtendedSLExistenceProof]
    oldProof.check(sl.rootHash) shouldBe true
    val newE = updatedElement(e)

    sl.contains(newE) shouldBe true
    sl.update(newE)

    val proofForUpdate = ProofToRecalculate(newE, oldProof)
    val recalculatedHash = ExtendedSLProof.recalculate(Seq(proofForUpdate))

    recalculatedHash shouldEqual sl.rootHash
  }

  property("Update elements") {
    //works for 3 elements
    val forUpdate = elements.take(4)

    val proofsForUpdate = forUpdate map { e =>
      val proof = sl.extendedElementProof(e).asInstanceOf[ExtendedSLExistenceProof]
      proof.check(sl.rootHash) shouldBe true
      ProofToRecalculate(updatedElement(e), proof)
    }

    proofsForUpdate.foreach(p => sl.update(p.newEl))

    val recalculatedHash = ExtendedSLProof.recalculate(proofsForUpdate)
    recalculatedHash shouldEqual sl.rootHash




  }


  def updatedElement(e: NormalSLElement): NormalSLElement = {
    val newE = e.copy(value = (1: Byte) +: e.value)

    e.key shouldEqual newE.key
    e.value should not equal newE.value
    newE

  }

}
