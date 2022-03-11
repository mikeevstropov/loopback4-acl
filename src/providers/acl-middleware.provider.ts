import {ACLBindings} from '../keys';
import {createError} from '../utils';
import {HttpErrors} from '@loopback/rest';
import {Middleware} from '@loopback/rest';
import {Provider} from '@loopback/context';
import {asMiddleware} from '@loopback/rest';
import {inject, injectable} from '@loopback/core';
import {RestMiddlewareGroups} from '@loopback/rest';
import {AuthorizeFn} from './authorize-action.provider';
import {AuthenticateFn} from './authenticate-action.provider';

@injectable(
  asMiddleware({
    group: RestMiddlewareGroups.AUTHENTICATION,
    upstreamGroups: [RestMiddlewareGroups.FIND_ROUTE],
  }),
)
export class ACLMiddlewareProvider implements Provider<Middleware> {
  constructor(
    @inject(ACLBindings.AUTHENTICATE_ACTION)
    private authenticate: AuthenticateFn,
    @inject(ACLBindings.AUTHORIZE_ACTION)
    private authorize: AuthorizeFn,
  ) {}

  value(): Middleware {
    return async (ctx, next) => {
      await this.authenticate(ctx.request);
      const allowed = await this.authorize(ctx.request);
      if (!allowed)
        throw createError(
          HttpErrors.Forbidden,
          'AUTHORIZATION_REQUIRED',
          'User authorization required.',
        );
      return next();
    };
  }
}
