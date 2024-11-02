import { Buffer } from 'buffer';
import sha from './sha.js';
import sha256 from './sha256.js';
import md5 from './md5.js';

const algorithms = {
  sha1: sha,
  sha256: sha256,
  md5: md5
};

const blocksize = 64;
const zeroBuffer = Buffer.alloc(blocksize);
zeroBuffer.fill(0);

function hmac(fn, key, data) {
  if (!Buffer.isBuffer(key)) key = Buffer.from(key);
  if (!Buffer.isBuffer(data)) data = Buffer.from(data);

  if (key.length > blocksize) {
    key = fn(key);
  } else if (key.length < blocksize) {
    key = Buffer.concat([key, zeroBuffer], blocksize);
  }

  const ipad = Buffer.alloc(blocksize);
  const opad = Buffer.alloc(blocksize);
  for (let i = 0; i < blocksize; i++) {
    ipad[i] = key[i] ^ 0x36;
    opad[i] = key[i] ^ 0x5c;
  }

  const hash = fn(Buffer.concat([ipad, data]));
  return fn(Buffer.concat([opad, hash]));
}

function hash(alg, key) {
  alg = alg || 'sha1';
  const fn = algorithms[alg];
  const bufs = [];
  let length = 0;
  if (!fn) error('algorithm:', alg, 'is not yet supported');
  return {
    update(data) {
      if (!Buffer.isBuffer(data)) data = Buffer.from(data);

      bufs.push(data);
      length += data.length;
      return this;
    },
    digest(enc) {
      const buf = Buffer.concat(bufs);
      const r = key ? hmac(fn, key, buf) : fn(buf);
      bufs.length = 0; // clear bufs
      return enc ? r.toString(enc) : r;
    }
  };
}

function error() {
  const m = [...arguments].join(' ');
  throw new Error([m, 'we accept pull requests', 'https://github.com/liaodalin19903/mark-common-js/pulls'].join('\n'));
}

export const createHash = (alg) => {
  return hash(alg);
};

export const createHmac = (alg, key) => {
  return hash(alg, key);
};

export const createCredentials = () => {
  error('sorry, createCredentials is not implemented yet');
};

export const createCipher = () => {
  error('sorry, createCipher is not implemented yet');
};

export const createCipheriv = () => {
  error('sorry, createCipheriv is not implemented yet');
};

export const createDecipher = () => {
  error('sorry, createDecipher is not implemented yet');
};

export const createDecipheriv = () => {
  error('sorry, createDecipheriv is not implemented yet');
};

export const createSign = () => {
  error('sorry, createSign is not implemented yet');
};

export const createVerify = () => {
  error('sorry, createVerify is not implemented yet');
};

export const createDiffieHellman = () => {
  error('sorry, createDiffieHellman is not implemented yet');
};

export const pbkdf2 = () => {
  error('sorry, pbkdf2 is not implemented yet');
};

export default {
  createHash,
  createHmac,
  createCredentials,
  createCipher,
  createCipheriv,
  createDecipher,
  createDecipheriv,
  createSign,
  createVerify,
  createDiffieHellman,
  pbkdf2
}