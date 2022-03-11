import {
  ACLBindings,
  ACLPrincipal,
  ACLUserService,
  AuthenticateFn,
  ACLTokenService,
  AuthenticateActionProvider,
} from "../../../index";
import {
  mockUser,
  mockPrincipals,
  MockUserService,
} from "../fixtures/mock-user-service";
import {use, expect} from "chai";
import {Request} from "@loopback/rest";
import {Entity} from "@loopback/repository";
import chaiAsPromised from 'chai-as-promised';
import {MockUser} from "../fixtures/mock-user";
import {Context, instantiateClass} from "@loopback/context";
import {MockTokenService} from "../fixtures/mock-token-service";

use(chaiAsPromised);

describe('AuthenticateActionProvider', () => {
  describe('constructor()', () => {
    it('instantiateClass injects setter acl.session.user in the constructor', async () => {
      const context = new Context();
      const user = new MockUser();
      const tokenService = new ACLTokenService();
      const userService = new MockUserService();
      context.bind(ACLBindings.TOKEN_SERVICE).to(tokenService);
      context.bind(ACLBindings.USER_SERVICE).to(userService);
      const provider = await instantiateClass(
        AuthenticateActionProvider,
        context,
      );
      await provider.setSessionUser(user);
      expect(await context.get(ACLBindings.SESSION_USER)).to.be.equal(user);
    });
    it('instantiateClass injects setter acl.session.principals in the constructor', async () => {
      const context = new Context();
      const principals = ['user-role'];
      const tokenService = new ACLTokenService();
      const userService = new MockUserService();
      context.bind(ACLBindings.TOKEN_SERVICE).to(tokenService);
      context.bind(ACLBindings.USER_SERVICE).to(userService);
      const provider = await instantiateClass(
        AuthenticateActionProvider,
        context,
      );
      await provider.setSessionPrincipals(principals);
      expect(await context.get(ACLBindings.SESSION_PRINCIPALS)).to.be.equal(principals);
    });
    it('instantiateClass injects setter acl.session.principals in the constructor', async () => {
      const context = new Context();
      const tokenService = new ACLTokenService();
      const userService = new MockUserService();
      context.bind(ACLBindings.TOKEN_SERVICE).to(tokenService);
      context.bind(ACLBindings.USER_SERVICE).to(userService);
      const provider = await instantiateClass(
        AuthenticateActionProvider,
        context,
      );
      expect(provider.tokenService).to.be.equal(tokenService);
    });
    it('instantiateClass injects setter acl.session.principals in the constructor', async () => {
      const context = new Context();
      const tokenService = new ACLTokenService();
      const userService = new MockUserService();
      context.bind(ACLBindings.TOKEN_SERVICE).to(tokenService);
      context.bind(ACLBindings.USER_SERVICE).to(userService);
      const provider = await instantiateClass(
        AuthenticateActionProvider,
        context,
      );
      expect(provider.tokenService).to.be.equal(tokenService);
    });
  });

  describe('value()', () => {
    let provider: AuthenticateActionProvider;
    let sessionUser: Entity | undefined;
    let sessionPrincipals: ACLPrincipal[];

    beforeEach(() => {
      givenAuthenticateActionProvider();
    });

    it('returns a function which authenticates a request and returns a user', async () => {
      const authenticate: AuthenticateFn = provider.value();
      const request = <Request>{headers: {authorization: 'token'}};
      const user = await authenticate(request);
      expect(user).to.be.equal(mockUser);
    });
    it('updates session user', async () => {
      const authenticate: AuthenticateFn = provider.value();
      const request = <Request>{headers: {authorization: 'token'}};
      await authenticate(request);
      expect(sessionUser).to.be.equal(mockUser);
    });
    it('updates session principals', async () => {
      const authenticate: AuthenticateFn = provider.value();
      const request = <Request>{headers: {authorization: 'token'}};
      await authenticate(request);
      expect(sessionPrincipals).to.be.equal(mockPrincipals);
    });
    it('returns undefined if authentication fails by invalid token', async () => {
      givenAuthenticateActionProvider(
        new ACLTokenService(),
      );
      const authenticate = provider.value();
      const request = <Request>{headers: {authorization: 'token'}};
      expect(await authenticate(request)).to.be.undefined;
    });
    it('returns undefined if authentication fails by user resolving', async () => {
      givenAuthenticateActionProvider(
        undefined,
        new MockUserService(true),
      );
      const authenticate = provider.value();
      const request = <Request>{};
      expect(await authenticate(request)).to.be.undefined;
    });

    function givenAuthenticateActionProvider(
      tokenService?: ACLTokenService,
      userService?: ACLUserService,
    ) {
      sessionUser = undefined;
      sessionPrincipals = [];
      tokenService = tokenService ?? new MockTokenService();
      userService = userService ?? new MockUserService();

      provider = new AuthenticateActionProvider(
        tokenService,
        userService,
        (value: Entity | undefined) => sessionUser = value,
        (value: ACLPrincipal[]) => sessionPrincipals = value,
      );
    }
  });
});
