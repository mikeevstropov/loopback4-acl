import {promisify} from 'util';
import {ACL_DEFAULT_EXPIRES_IN, ACL_DEFAULT_TOKEN_SECRET, ACLBindings} from '../keys';
import {createError} from '../utils';
import {inject} from '@loopback/core';
import {HttpErrors} from '@loopback/rest';

const jwt = require('jsonwebtoken');
const signAsync = promisify(jwt.sign);
const verifyAsync = promisify(jwt.verify);

export type TokenPayload = {
  uid: string,
  key: string,
}

export type TokenDetails = {
  value: string,
  expiresIn: number,
}

export class ACLTokenService {

  constructor(
    @inject(ACLBindings.TOKEN_SECRET)
    readonly tokenSecret: string = ACL_DEFAULT_TOKEN_SECRET,
    @inject(ACLBindings.TOKEN_EXPIRES_IN)
    readonly tokenExpiresIn: string = ACL_DEFAULT_EXPIRES_IN,
  ) {}

  public async encode(payload: TokenPayload, expiresIn?: number): Promise<TokenDetails> {

    if (!this.tokenSecret)
      throw createError(
        HttpErrors.Forbidden,
        'NO_TOKEN_SECRET',
        'Token secret is empty.',
      );

    expiresIn = expiresIn ?? Number(this.tokenExpiresIn);
    const options = expiresIn === 0 ? {} : {expiresIn};

    let token: string;
    try {
      token = await signAsync(
        payload,
        this.tokenSecret,
        options,
      );
    } catch (error) {
      throw createError(
        HttpErrors.Forbidden,
        'TOKEN_ENCODING_ERROR',
        error.toString(),
      );
    }

    return {value: token, expiresIn};
  }

  public async decode(token: string): Promise<TokenPayload> {

    if (!this.tokenSecret)
      throw createError(
        HttpErrors.Forbidden,
        'NO_TOKEN_SECRET',
        'Token secret is empty.',
      );

    if (!token)
      throw createError(
        HttpErrors.Forbidden,
        'NO_TOKEN_TO_VERIFY',
        'Verifying token is empty.',
      );

    let payload: TokenPayload;
    try {
      payload = await verifyAsync(token, this.tokenSecret);
    } catch (error) {
      throw createError(
        HttpErrors.Forbidden,
        'TOKEN_VERIFYING_ERROR',
        error.message,
      );
    }

    return payload;
  };
}
