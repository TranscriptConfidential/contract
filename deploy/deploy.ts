import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const deployedConfidentialTranscript = await deploy("ConfidentialTranscript", {
    from: deployer,
    log: true,
    args: ["0x621F7cCDAa5A06433AE5f89C7849EdFe605CcD6C", "0x621F7cCDAa5A06433AE5f89C7849EdFe605CcD6C", "bafybeidd63tyniz4uoswngruzlwjvczf2kf5p4udd557phfjij2ycwmppa"]
    
  });

  console.log(`ConfidentialTranscript contract: `, deployedConfidentialTranscript.address);
};
export default func;
func.id = "deploy_confidentialTranscript"; // id required to prevent reexecution
func.tags = ["ConfidentialTranscript"];
