import {ACLBindings} from './keys';
import {ACLTokenService} from "./services";
import {ACLMetadataProvider} from './providers';
import {ACLMiddlewareProvider} from './providers';
import {AuthorizeActionProvider} from './providers';
import {AuthenticateActionProvider} from './providers';
import {Binding, Component, ProviderMap} from '@loopback/core';
import {ACL_DEFAULT_EXPIRES_IN, ACL_DEFAULT_TOKEN_SECRET} from './keys';

export class ACLComponent implements Component {
  providers: ProviderMap = {
    [ACLBindings.METADATA.key]: ACLMetadataProvider,
    [ACLBindings.MIDDLEWARE.key]: ACLMiddlewareProvider,
    [ACLBindings.AUTHENTICATE_ACTION.key]: AuthenticateActionProvider,
    [ACLBindings.AUTHORIZE_ACTION.key]: AuthorizeActionProvider,
  };
  bindings: Binding[] = [
    Binding.bind(ACLBindings.SESSION_USER).to(undefined),
    Binding.bind(ACLBindings.SESSION_PRINCIPALS).to([]),
    Binding.bind(ACLBindings.TOKEN_SERVICE).toClass(ACLTokenService),
    Binding.bind(ACLBindings.TOKEN_SECRET).to(ACL_DEFAULT_TOKEN_SECRET),
    Binding.bind(ACLBindings.TOKEN_EXPIRES_IN).to(ACL_DEFAULT_EXPIRES_IN),
  ];
}
