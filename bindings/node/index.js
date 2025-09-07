import { ts_protect_secret } from "derec-library";
const secret_id = new Uint8Array([1, 2, 3, 4, 255]);
const secret_data = new Uint8Array([5, 6, 7, 8, 255]);
const channels = new BigUint64Array([1n, 2n, 3n]);
const threshold = 2;
const version = 1;
console.log("ts_protect_secret: ", ts_protect_secret(secret_id, secret_data, channels, threshold, version));
//# sourceMappingURL=index.js.map