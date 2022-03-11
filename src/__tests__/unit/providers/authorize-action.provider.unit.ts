import {
  ACLBindings,
  ACLCommonPrincipal,
  ACLMetadata,
  ACLPermission,
  ACLPrincipal,
  AuthorizeActionProvider,
  AuthorizeFn,
} from "../../../index";
import {mockPrincipals, mockUser,} from "../fixtures/mock-user-service";
import {expect, use} from "chai";
import {Request} from "@loopback/rest";
import {Entity} from "@loopback/repository";
import chaiAsPromised from 'chai-as-promised';
import {Context, instantiateClass} from "@loopback/context";

use(chaiAsPromised);

describe('AuthorizeActionProvider', () => {
  describe('constructor()', () => {
    it('instantiateClass injects setter acl.decorator.metadata in the constructor', async () => {
      const context = new Context();
      const metadata: ACLMetadata = {rules: []};
      context.bind(ACLBindings.METADATA).to(metadata);
      const provider = await instantiateClass(
        AuthorizeActionProvider,
        context,
      );
      expect(await provider.getMetadata()).to.be.equal(metadata);
    });
    it('instantiateClass injects setter acl.session.user in the constructor', async () => {
      const context = new Context();
      context.bind(ACLBindings.SESSION_USER).to(mockUser);
      const provider = await instantiateClass(
        AuthorizeActionProvider,
        context,
      );
      expect(await provider.getSessionUser()).to.be.equal(mockUser);
    });
    it('instantiateClass injects setter acl.session.principals in the constructor', async () => {
      const context = new Context();
      context.bind(ACLBindings.SESSION_PRINCIPALS).to(mockPrincipals);
      const provider = await instantiateClass(
        AuthorizeActionProvider,
        context,
      );
      expect(await provider.getSessionPrincipals()).to.be.equal(mockPrincipals);
    });
  });
  describe('value()', () => {

    it('returns true if no metadata provided', async () => {
      const provider = givenAuthorizeActionProvider();
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    // Testing $everyone
    it('returns false if $everyone is denied without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns false if $everyone is denied with session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $everyone is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed with session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    // Testing $authenticated
    it('returns true if $authenticated is denied without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $authenticated is denied with session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $authenticated is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $authenticated is allowed with session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    // Testing $owner
    it('returns true if $owner is denied without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $owner is denied with non-owner session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.OWNER,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $owner is denied with owner session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{path: `/collection/${mockUser.id}`};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $owner is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $owner is allowed with non-owner session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $owner is allowed with owner session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.OWNER,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{path: `/collection/${mockUser.id}`};
      expect(await authorize(request)).to.be.true;
    });
    // Testing specific principal
    it('returns true if specific principal is allowed without session user', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: specificPrincipal,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if specific principal is allowed with not matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const unknownPrincipal = 'unknown-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: specificPrincipal,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [unknownPrincipal]
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if specific principal is allowed with matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: specificPrincipal,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [specificPrincipal]
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if specific principal is denied without session user', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: specificPrincipal,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if specific principal is denied with not matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const unknownPrincipal = 'unknown-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: specificPrincipal,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [unknownPrincipal]
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if specific principal is denied with matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: specificPrincipal,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [specificPrincipal]
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    // Testing concurrent specific principals
    it('returns true if first matched principal is allowed and second is denied', async () => {
      const firstPrincipal = 'first-principal';
      const secondPrincipal = 'second-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: firstPrincipal,
        permission: ACLPermission.ALLOW
      }, {
        principal: secondPrincipal,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [firstPrincipal, secondPrincipal]
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if first matched principal is denied and second is allowed', async () => {
      const firstPrincipal = 'first-principal';
      const secondPrincipal = 'second-principal';
      const metadata: ACLMetadata = {rules: [{
          principal: firstPrincipal,
          permission: ACLPermission.DENY
        }, {
          principal: secondPrincipal,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [firstPrincipal, secondPrincipal]
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    // Testing $everyone with $authenticated
    it('returns false if $everyone is denied and $authenticated is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY
      },{
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $everyone is denied and $authenticated is allowed with session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        },{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed and $authenticated is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW
      },{
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed and $authenticated is denied without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW
        },{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $everyone is allowed and $authenticated is denied with session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW
        },{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    // Testing $everyone with $owner
    it('returns false if $everyone is denied and $owner is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY
      },{
        principal: ACLCommonPrincipal.OWNER,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns false if $everyone is denied and $owner is allowed with non-owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $everyone is denied and $owner is allowed with owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{path: '/collection/' + mockUser.id};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed and $owner is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW
      },{
        principal: ACLCommonPrincipal.OWNER,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed and $owner is allowed with non-owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW
      },{
        principal: ACLCommonPrincipal.OWNER,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $everyone is allowed and $owner is denied with owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW
      },{
        principal: ACLCommonPrincipal.OWNER,
        permission: ACLPermission.DENY
      }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{path: '/collection/' + mockUser.id};
      expect(await authorize(request)).to.be.false;
    });
    // Testing $authenticated with $owner
    it('returns true if $authenticated is denied and $owner is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.DENY
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $authenticated is denied and $owner is allowed with non-owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.DENY
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $authenticated is denied and $owner is allowed with owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.DENY
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{path: '/collection/' + mockUser.id};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $authenticated is allowed and $owner is allowed without session user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $authenticated is allowed and $owner is allowed with non-owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const entityId = mockUser.id + 'not-same';
      const request = <Request>{path: `/collection/${entityId}`};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $authenticated is allowed and $owner is denied with owner user', async () => {
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW
        },{
          principal: ACLCommonPrincipal.OWNER,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(metadata, mockUser);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{path: '/collection/' + mockUser.id};
      expect(await authorize(request)).to.be.false;
    });
    // Testing $everyone with specific
    it('returns false if $everyone is denied and specific principal is allowed without session user', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY
      },{
        principal: specificPrincipal,
        permission: ACLPermission.ALLOW
      }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns false if $everyone is denied and specific principal is allowed with not matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const unknownPrincipal = 'unknown-principal'
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        },{
          principal: specificPrincipal,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [unknownPrincipal],
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $everyone is denied and specific principal is allowed with matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        },{
          principal: specificPrincipal,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [specificPrincipal],
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $everyone is denied and specific principal is denied with matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY
        },{
          principal: specificPrincipal,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [specificPrincipal],
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });
    it('returns true if $everyone is allowed and specific principal is allowed without session user', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW
        },{
          principal: specificPrincipal,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(metadata);
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed and specific principal is allowed with not matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const unknownPrincipal = 'unknown-principal'
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW
        },{
          principal: specificPrincipal,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [unknownPrincipal],
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns true if $everyone is allowed and specific principal is allowed with matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW
        },{
          principal: specificPrincipal,
          permission: ACLPermission.ALLOW
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [specificPrincipal],
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.true;
    });
    it('returns false if $everyone is allowed and specific principal is denied with matched user principal', async () => {
      const specificPrincipal = 'specific-principal';
      const metadata: ACLMetadata = {rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW
        },{
          principal: specificPrincipal,
          permission: ACLPermission.DENY
        }]}
      const provider = givenAuthorizeActionProvider(
        metadata,
        mockUser,
        [specificPrincipal],
      );
      const authorize: AuthorizeFn = provider.value();
      const request = <Request>{};
      expect(await authorize(request)).to.be.false;
    });

    function givenAuthorizeActionProvider(
      metadata?: ACLMetadata,
      sessionUser?: Entity,
      sessionPrincipals?: ACLPrincipal[],
    ) {
      return new AuthorizeActionProvider(
        () => Promise.resolve(metadata),
        () => Promise.resolve(sessionUser),
        () => Promise.resolve(sessionPrincipals),
      );
    }
  });
});
