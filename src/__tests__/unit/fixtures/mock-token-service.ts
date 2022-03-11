import {
  TokenPayload,
  TokenDetails,
  ACLTokenService,
} from "../../../";

export const mockTokenPayload = {uid: 'uid', key: 'key'};
export const mockTokenDetails = {value: 'token', expiresIn: 0};

export class MockTokenService extends ACLTokenService {

  async encode(payload: TokenPayload, expiresIn?: number): Promise<TokenDetails> {
    return mockTokenDetails;
  }

  async decode(token: string): Promise<TokenPayload> {
    return mockTokenPayload;
  }
}
