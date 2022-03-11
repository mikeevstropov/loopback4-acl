import {
  ACLRule,
  ACLMetadata,
  ACLPrincipal,
  ACLPermission,
  ACLCommonPrincipal,
} from '../decorators';
import {ACLBindings} from '../keys';
import {Getter} from '@loopback/core';
import {Request} from '@loopback/rest';
import {inject, Provider} from '@loopback/context';
import {AnyObject, Entity} from '@loopback/repository';

export type AuthorizeFn = (request: Request) => Promise<boolean>;

export class AuthorizeActionProvider implements Provider<AuthorizeFn> {
  constructor(
    @inject.getter(ACLBindings.METADATA)
    readonly getMetadata: Getter<ACLMetadata | undefined>,
    @inject.getter(ACLBindings.SESSION_USER)
    readonly getSessionUser: Getter<Entity | undefined>,
    @inject.getter(ACLBindings.SESSION_PRINCIPALS)
    readonly getSessionPrincipals: Getter<ACLPrincipal[] | undefined>,
  ) {}

  value(): AuthorizeFn {
    return request => this.action(request);
  }

  async action(request: Request): Promise<boolean> {
    const metadata = await this.getMetadata();
    if (!metadata) return true;
    // Specific permission.
    let allowedBySpecificPrincipal = false;
    let deniedBySpecificPrincipal = false;
    // Owner permission.
    let allowedByOwnerPrincipal = false;
    let deniedByOwnerPrincipal = false;
    // Authenticated permission.
    let allowedByAuthenticatedPrincipal = false;
    let deniedByAuthenticatedPrincipal = false;
    // Everyone permission.
    let allowedByEveryonePrincipal = false;
    let deniedByEveryonePrincipal = false;
    // Resolve common principals.
    const user = await this.getSessionUser();
    const commonPrincipals = AuthorizeActionProvider
      .getCommonPrincipals(request, user);
    // Resolve permissions by rules.
    const specificPrincipals = await this.getSessionPrincipals();
    const rules = metadata.rules;
    rules.forEach((rule: ACLRule) => {
      // Specific rule.
      if (specificPrincipals?.includes(rule.principal)) {
        if (rule.permission === ACLPermission.ALLOW)
          allowedBySpecificPrincipal = true;
        if (rule.permission === ACLPermission.DENY)
          deniedBySpecificPrincipal = true;
      }
      // Common rule.
      if (commonPrincipals.includes(rule.principal)) {
        // $owner
        if (rule.principal === ACLCommonPrincipal.OWNER) {
          if (rule.permission === ACLPermission.ALLOW)
            allowedByOwnerPrincipal = true;
          if (rule.permission === ACLPermission.DENY)
            deniedByOwnerPrincipal = true;
        }
        // $authenticated
        if (rule.principal === ACLCommonPrincipal.AUTHENTICATED) {
          if (rule.permission === ACLPermission.ALLOW)
            allowedByAuthenticatedPrincipal = true;
          if (rule.permission === ACLPermission.DENY)
            deniedByAuthenticatedPrincipal = true;
        }
        // $everyone
        if (rule.principal === ACLCommonPrincipal.EVERYONE) {
          if (rule.permission === ACLPermission.ALLOW)
            allowedByEveryonePrincipal = true;
          if (rule.permission === ACLPermission.DENY)
            deniedByEveryonePrincipal = true;
        }
      }
    })
    // Apply specific rule in priority.
    if (allowedBySpecificPrincipal) return true;
    if (deniedBySpecificPrincipal) return false;
    // Apply common rule by $owner.
    if (allowedByOwnerPrincipal) return true;
    if (deniedByOwnerPrincipal) return false;
    // Apply common rule by $authenticated.
    if (allowedByAuthenticatedPrincipal) return true;
    if (deniedByAuthenticatedPrincipal) return false;
    // Apply common rule by $everyone.
    if (allowedByEveryonePrincipal) return true;
    if (deniedByEveryonePrincipal) return false;
    // Allow by default.
    return true;
  }

  public static getCommonPrincipals(request: Request, user?: AnyObject): ACLCommonPrincipal[] {
    const principals = [];
    // Has '$everyone'
    principals.push(ACLCommonPrincipal.EVERYONE);
    if (user) {
      // Has '$authenticated'
      principals.push(ACLCommonPrincipal.AUTHENTICATED)
      // Has '$owner'
      const userId = user?.id + '';
      const path = request.path ?? '';
      const regex = new RegExp(`\/${userId}($|[\/\?])`);
      const idInPath = regex.test(path);
      if (idInPath) principals.push(ACLCommonPrincipal.OWNER);
    }
    return principals;
  }
}
