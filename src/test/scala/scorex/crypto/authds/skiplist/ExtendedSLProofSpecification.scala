package scorex.crypto.authds.skiplist

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.authds.storage.MvStoreBlobBlobStorage
import scorex.crypto.encode.Base58
import scorex.crypto.hash.{Blake2b256, CommutativeHash}

class ExtendedSLProofSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with SLGenerators {

  implicit val storage = new MvStoreBlobBlobStorage(None)
  implicit val hf: CommutativeHash[Blake2b256.type] = new CommutativeHash(Blake2b256)

  property("SLExtended proof empty check") {
    forAll(slelementGenerator) { newSE: SLElement =>
      val sl2 = new SkipList()(storage, hf)
      sl2.contains(newSE) shouldBe false

      val proof = sl2.elementProof(newSE).asInstanceOf[SLNonExistenceProof]
      proof.isEmpty shouldBe true

      val newRootHash = ExtendedSLProof.recalculate(sl2.rootHash, proof, newSE)
      sl2.insert(newSE)
      val newProof = sl2.elementProof(newSE)
      newProof.check(sl2.rootHash)

      Base58.encode(sl2.rootHash) shouldBe Base58.encode(newRootHash)
      sl2.rootHash shouldEqual newRootHash

      sl2.delete(newSE)
    }
  }


}
