import { DeployFunction } from "hardhat-deploy/types";
import { HardhatRuntimeEnvironment } from "hardhat/types";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployer } = await hre.getNamedAccounts();
  const { deploy } = hre.deployments;

  const deployedConfidentialTranscript = await deploy("ConfidentialTranscript", {
    from: deployer,
    log: true,
    
  });

  console.log(`ConfidentialTranscript contract: `, deployedConfidentialTranscript.address);
};
export default func;
func.id = "deploy_confidentialTranscript"; // id required to prevent reexecution
func.tags = ["ConfidentialTranscript"];
