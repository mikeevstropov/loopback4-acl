import {ACLOptions} from "../types";
import {ACLBindings} from "../keys";
import {config, CoreBindings} from '@loopback/core';
import {ACLMetadata, getAclMetadata} from '../decorators';
import {Constructor, inject, Provider} from '@loopback/context';

/**
 * Provides authentication metadata of a controller method
 * @example `context.bind('authentication.operationMetadata').toProvider(ACLMetadataProvider)`
 */
export class ACLMetadataProvider
  implements Provider<ACLMetadata | undefined> {
  constructor(
    @inject(CoreBindings.CONTROLLER_CLASS, {optional: true})
    private readonly controllerClass: Constructor<{}>,
    @inject(CoreBindings.CONTROLLER_METHOD_NAME, {optional: true})
    private readonly methodName: string,
    @config({fromBinding: ACLBindings.COMPONENT})
    private readonly options: ACLOptions = {},
  ) {}

  value(): ACLMetadata | undefined {
    if (!this.controllerClass || !this.methodName) return;
    const metadata = getAclMetadata(
      this.controllerClass,
      this.methodName,
    );
    // Skip authentication if `skip` is `true`
    if (metadata?.skip) return undefined;
    if (metadata) return metadata;
    // Fall back to default metadata
    return this.options.defaultMetadata;
  }
}
