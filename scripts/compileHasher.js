// Generates Hasher artifacts at compile-time using circomlibjs poseidon codegen.
// - Hasher  : Poseidon-2 (Merkle tree leaf hashing)  -> poseidon(bytes32[2])
// - Hasher4 : Poseidon-4 (swap output commitment)     -> poseidon(bytes32[4])
const path = require('path')
const fs = require('fs')
const genContract = require('circomlibjs').poseidonContract

function writeHasher(name, arity) {
  const outputPath = path.join(__dirname, '..', 'artifacts', 'contracts', `${name}.sol`)
  const outputFile = path.join(outputPath, `${name}.json`)
  if (!fs.existsSync(outputPath)) {
    fs.mkdirSync(outputPath, { recursive: true })
  }
  const contract = {
    _format: 'hh-sol-artifact-1',
    sourceName: `contracts/${name}.sol`,
    linkReferences: {},
    deployedLinkReferences: {},
    contractName: name,
    abi: genContract.generateABI(arity),
    bytecode: genContract.createCode(arity),
  }
  fs.writeFileSync(outputFile, JSON.stringify(contract, null, 2))
}

writeHasher('Hasher', 2)
writeHasher('Hasher4', 4)
