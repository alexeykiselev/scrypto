package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class ExtendedSLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)
  val sl = new SkipList()(storage, hf)
  val elements = genEl(10)
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

  property("SLExtended: recalculate for SLExistenceProof") {
    val e = elements.last.asInstanceOf[NormalSLElement]
    val proof = sl.elementProof(e).asInstanceOf[SLExistenceProof]
    val newE = e.copy(value = (1: Byte) +: e.value)

    e.key shouldEqual newE.key
    e.value should not equal newE.value
    println(Base58.encode(e.bytes))
    println(Base58.encode(newE.bytes))

    sl.contains(newE) shouldBe true
    val proofForUpdate = ProofToRecalculate(newE, proof)
    val recalculated = ExtendedSLProof.recalculateProofs(Seq(proofForUpdate)).head

    proofForUpdate.eProof.proof shouldEqual recalculated.eProof.proof
    proofForUpdate.eProof.e shouldEqual e
    recalculated.eProof.e shouldEqual newE

    recalculated.eProof.rootHash() sameElements sl.rootHash shouldBe false
    sl.update(newE)
    println(Base58.encode(sl.elementProof(newE).asInstanceOf[SLExistenceProof].e.bytes))
    println(Base58.encode(recalculated.eProof.e.bytes))

    println(sl)
    recalculated.eProof.rootHash()
    println("=========")
    sl.elementProof(newE).asInstanceOf[SLExistenceProof].rootHash()
    println("=========")



  }


}
