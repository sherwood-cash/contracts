const { wtns, groth16 } = require('snarkjs')
const { utils } = require('ffjavascript')

const fs = require('fs')
const tmp = require('tmp-promise')
const util = require('util')
const exec = util.promisify(require('child_process').exec)

const { toFixedHex } = require('./utils')

async function prove(input, keyBasePath) {
  const { proof } = await groth16.fullProve(
    utils.stringifyBigInts(input),
    `${keyBasePath}.wasm`,
    `${keyBasePath}.zkey`,
  )
  const pA = [toFixedHex(proof.pi_a[0]), toFixedHex(proof.pi_a[1])]
  const pB = [
    [toFixedHex(proof.pi_b[0][1]), toFixedHex(proof.pi_b[0][0])],
    [toFixedHex(proof.pi_b[1][1]), toFixedHex(proof.pi_b[1][0])],
  ]
  const pC = [toFixedHex(proof.pi_c[0]), toFixedHex(proof.pi_c[1])]
  return { pA, pB, pC }
}

function proveZkutil(input, keyBasePath) {
  input = utils.stringifyBigInts(input)
  // console.log('input', input)
  return tmp.dir().then(async (dir) => {
    dir = dir.path
    let out

    try {
      await wtns.debug(
        utils.unstringifyBigInts(input),
        `${keyBasePath}.wasm`,
        `${dir}/witness.wtns`,
        `${keyBasePath}.sym`,
        {},
        console,
      )
      const witness = utils.stringifyBigInts(await wtns.exportJson(`${dir}/witness.wtns`))
      fs.writeFileSync(`${dir}/witness.json`, JSON.stringify(witness, null, 2))

      out = await exec(
        `zkutil prove -c ${keyBasePath}.r1cs -p ${keyBasePath}.params -w ${dir}/witness.json -r ${dir}/proof.json -o ${dir}/public.json`,
      )
      await exec(`zkutil verify -p ${keyBasePath}.params -r ${dir}/proof.json -i ${dir}/public.json`)
    } catch (e) {
      console.log(out, e)
      throw e
    }
    return '0x' + JSON.parse(fs.readFileSync(`${dir}/proof.json`).toString()).proof
  })
}

module.exports = { prove, proveZkutil }
