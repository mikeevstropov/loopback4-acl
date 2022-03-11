import {expect} from 'chai';
import {ACLTokenService} from "../../../";
import {ACL_DEFAULT_EXPIRES_IN, ACL_DEFAULT_TOKEN_SECRET} from "../../../";

/**
 * This test suite is for testing the ACLTokenService.
 */
describe('acl-token', () => {

  const tokenService = new ACLTokenService(
    ACL_DEFAULT_TOKEN_SECRET,
    ACL_DEFAULT_EXPIRES_IN,
  );

  it('encode and decode token payload', async () => {

    const payload = {uid: 'test-user', key: 'token-key'};
    const details = await tokenService.encode(payload);
    const decoded = await tokenService.decode(details.value);

    expect(payload.uid).to.eql(decoded.uid);
    expect(payload.key).to.eql(decoded.key);
  });
});
