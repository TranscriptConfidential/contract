import { expect } from "chai";
import { ethers } from "hardhat";
import { createInstance, createEncryptedInput } from "@zama-fhe/relayer-sdk";
import { SepoliaConfig } from "@zama-fhe/relayer-sdk/config";

describe("ConfidentialTranscript (with Relayer SDK)", function () {
  let transcript: any;
  let university: any, pg: any, student: any;

  beforeEach(async () => {
    [university, pg, student] = await ethers.getSigners();

    const Transcript = await ethers.getContractFactory("ConfidentialTranscript");
    transcript = await Transcript.deploy(university.address, pg.address);
    await transcript.waitForDeployment();
  });

  it("should mint transcript with encrypted GPA + CID", async () => {
    // 1. Init SDK (mock encryption context)
    const instance = await createInstance(SepoliaConfig);

    // 2. Encrypt student CID + GPA
    const cidInput = createEncryptedInput(instance, student.address);
    cidInput.addUint256(1234567890n); // fake CID digest

    const gpaInput = createEncryptedInput(instance, university.address);
    gpaInput.addUint16(375); // GPA = 3.75 scaled by 100

    // 3. Prepare handles + attestation proof
    const { handles: cidHandles, proof: cidProof } = await cidInput.encrypt();
    const { handles: gpaHandles, proof: gpaProof } = await gpaInput.encrypt();

    // 4. Call mintTranscriptExternal
    await transcript
      .connect(university)
      .mintTranscriptExternal(
        student.address,
        1,
        cidHandles[0], // externalEuint256
        gpaHandles[0], // externalEuint16
        cidProof // attestation proof
      );

    expect(await transcript.ownerOf(1)).to.equal(student.address);
  });

  it("should allow PG authority to check scholarship eligibility", async () => {
    // Reuse encryption inputs
    const instance = await createInstance(SepoliaConfig);
    const gpaInput = createEncryptedInput(instance, university.address);
    gpaInput.addUint16(420); // GPA = 4.20 scaled by 100
    const { handles: gpaHandles, proof } = await gpaInput.encrypt();

    const cidInput = createEncryptedInput(instance, student.address);
    cidInput.addUint256(99999999n);
    const { handles: cidHandles } = await cidInput.encrypt();

    await transcript
      .connect(university)
      .mintTranscriptExternal(
        student.address,
        2,
        cidHandles[0],
        gpaHandles[0],
        proof
      );

    // PG authority checks scholarship (threshold = 350 => 3.5 GPA)
    const eligible = await transcript
      .connect(pg)
      .checkScholarshipEligibilityByToken(2, 350);

    expect(eligible).to.not.equal("0x"); // returns valid ebool handle
  });

  it("should revoke transcript", async () => {
    const instance = await createInstance(SepoliaConfig);
    const gpaInput = createEncryptedInput(instance, university.address);
    gpaInput.addUint16(300); // GPA = 3.00
    const { handles: gpaHandles, proof } = await gpaInput.encrypt();

    const cidInput = createEncryptedInput(instance, student.address);
    cidInput.addUint256(8888n);
    const { handles: cidHandles } = await cidInput.encrypt();

    await transcript
      .connect(university)
      .mintTranscriptExternal(
        student.address,
        3,
        cidHandles[0],
        gpaHandles[0],
        proof
      );

    await transcript.connect(university).revokeTranscript(3);

    await expect(transcript.getEncryptedCID(3)).to.be.revertedWith("invalid token");
  });
});
