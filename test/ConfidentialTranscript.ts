
import { expect } from "chai";
import { ethers, fhevm } from "hardhat";

describe("ConfidentialTranscript - FHE E2E (mock)", function () {
    before(async function () {
        [this.university, this.student] = await ethers.getSigners();
        this.Factory = await ethers.getContractFactory("ConfidentialTranscript");
        this.deployed = await this.Factory.deploy(this.university.address, this.student.address, "bafybeidd63tyniz4uoswngruzlwjvczf2kf5p4udd557phfjij2ycwmppa");
        await this.deployed.waitForDeployment();
        this.contract = this.deployed;
        await fhevm.initializeCLIApi();
   });
  it("encrypts cid and gpa, requests reveal and resolves", async function () {


    console.log(await this.contract.getAddress());
    console.log(this.university.address, this.student.address);

    const input = await fhevm
      .createEncryptedInput(await this.contract.getAddress(), this.university.address)
      .add256(123n)
      .add16(BigInt(3.52 * 1000))
      .encrypt();

    const tx = await this.contract.connect(this.university).mintTranscriptExternal(this.student.address, 123, input.handles[0], input.handles[1], input.inputProof);
    await tx.wait();

    const bl = await this.contract.balanceOf(this.student.address);
    console.log(bl);
    expect(bl).greaterThan(0);  


  });

  it("decrypts cid", async function () {

    // decrypt
    const decrypt = await this.contract.connect(this.student).decryptCid()
    await decrypt.wait()


    console.log("Waiting for decryption oracle...");
    
    // Wait for decryption
    await fhevm.awaitDecryptionOracle();

    // get revealed cid
    const revealedCid = await this.contract._decryptedCID(this.student.address)
    console.log(revealedCid);
    expect(revealedCid).to.equal(123);


  });
});


