// tslint:disable:no-if-statement
import { KMS } from 'aws-sdk' // tslint:disable-line:no-implicit-dependencies

const kms = new KMS()

const isBase64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/

export const dictionary = new Map()

async function decrypt(ciphertext: string): Promise<string> {
  const result = await kms
    .decrypt({ CiphertextBlob: Buffer.from(ciphertext, 'base64') })
    .promise()
  const plaintext = result.Plaintext ? result.Plaintext.toString() : ciphertext

  return dictionary.set(ciphertext, plaintext) && plaintext
}

export default async (ciphertext: string): Promise<string> => {
  const isEmptyString = ciphertext.length === 0 // empty string?
  const decryptDisabled = ['1', 1, 'true', true].includes(process.env.DISABLE_AWS_KMS_THINGY ?? false) // we shouldn't decrypt?
  const isBase64Encoded = isBase64.test(ciphertext) // not a base64 encoded ciphertext?

  if (isEmptyString || decryptDisabled || !isBase64Encoded) {
    return String(ciphertext)
  }

  const cached = dictionary.get(ciphertext)
  if (cached) {
    return cached
  }

  return decrypt(ciphertext)
}
