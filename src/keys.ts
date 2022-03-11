import {AuthorizeFn} from './providers';
import {Middleware} from '@loopback/rest';
import {ACLUserService} from './services';
import {ACLTokenService} from './services';
import {AuthenticateFn} from './providers';
import {Entity} from "@loopback/repository";
import {ACLComponent} from "./acl-component";
import {ACLMetadata, ACLAnyPrincipal} from './decorators';
import {BindingKey, MetadataAccessor} from '@loopback/core';

export namespace ACLBindings {
  export const COMPONENT = BindingKey.create<ACLComponent>(
    'components.ACLComponent',
  );
  export const METADATA = BindingKey.create<ACLMetadata>(
    'acl.decorator.metadata',
  );
  export const MIDDLEWARE = BindingKey.create<Middleware>(
    'acl.middleware',
  );
  export const AUTHENTICATE_ACTION = BindingKey.create<AuthenticateFn>(
    'acl.authenticate.action',
  );
  export const AUTHORIZE_ACTION = BindingKey.create<AuthorizeFn>(
    'acl.authorize.action',
  );
  export const USER_SERVICE = BindingKey.create<ACLUserService>(
    'acl.user.service',
  );
  export const TOKEN_SERVICE = BindingKey.create<ACLTokenService>(
    'acl.token.service',
  );
  export const TOKEN_SECRET = BindingKey.create<string | undefined>(
    'acl.token.secret',
  );
  export const TOKEN_EXPIRES_IN = BindingKey.create<string | undefined>(
    'acl.token.expires.in',
  );
  export const SESSION_USER = BindingKey.create<Entity | undefined>(
    'acl.session.user',
  );
  export const SESSION_PRINCIPALS = BindingKey.create<ACLAnyPrincipal[]>(
    'acl.session.principals',
  );
}

export const ACL_METADATA_CLASS_KEY = MetadataAccessor.create<
  ACLMetadata,
  MethodDecorator
>('acl:method');

export const ACL_METADATA_METHOD_KEY = MetadataAccessor.create<
  ACLMetadata,
  ClassDecorator
>('acl:class');

export const ACL_DEFAULT_TOKEN_SECRET = 'jahkzlnu';
export const ACL_DEFAULT_EXPIRES_IN = '1209600'
