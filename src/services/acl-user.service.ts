import {Entity} from '@loopback/repository';
import {ACLAnyPrincipal} from '../decorators';
import {TokenPayload} from './acl-token.service';

export interface ACLUserService {

  /**
   * Resolve the Session User instance.
   */
  resolveUser(tokenPayload: TokenPayload): Promise<Entity | undefined>;

  /**
   * Resolve role-like names of the Session User.
   *
   * Optional.
   * Do return an empty array if you're not using roles.
   */
  resolvePrincipals(user: Entity): Promise<ACLAnyPrincipal[]>;
}
