// tslint:disable:no-expression-statement
import * as AWS from 'aws-sdk'
import * as mockAWS from 'aws-sdk-mock'

mockAWS.setSDKInstance(AWS)

mockAWS.mock('KMS', 'decrypt', (params: any, callback: any) =>
  callback(
    null,
    params && params.CiphertextBlob && params.CiphertextBlob.toString(),
  ),
)

mockAWS.mock('KMS', 'encrypt', (params: any, callback: any) =>
  callback(
    null,
    params && params.CiphertextBlob && params.CiphertextBlob.toString(),
  ),
)