
// convert object to array buffer
const objectToArrayBuffer = (value: object) =>
Uint8Array.from(Buffer.from(JSON.stringify(value))).buffer

// call function with context converted to array buffer & response JSON parsed
export const wrapFFI = (bbsFunction: Function, context: object) => JSON.parse(bbsFunction(objectToArrayBuffer(context)))

// convert array buffer to base64
export const arrayBufferToBase64 = (arrayBuffer: ArrayBufferLike) => Buffer.from(arrayBuffer).toString('base64')

// convert base64 to Uint8Array
export const base64ToUint8Array = (base64Data: string) => new Uint8Array(Buffer.from(base64Data, 'base64'))
