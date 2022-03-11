import {
  acl,
  ACLRule,
  ACLMetadata,
  ACLBindings,
  ACLPrincipal,
  ACLPermission,
  ACLMetadataProvider,
} from "../../../";
import {expect} from "chai";
import {CoreBindings} from "@loopback/core";
import {Context, Provider} from "@loopback/context";

describe('ACLMetadataProvider', () => {
  let provider: Provider<ACLMetadata | undefined>;
  const roleName = 'test-role';

  const defaultMetadata = {rules: [{
    principal: roleName,
    permission: ACLPermission.DENY
  }]};

  const classRules: ACLRule[] = [
    {
      principal: ACLPrincipal.EVERYONE,
      permission: ACLPermission.DENY,
    },
    {
      principal: ACLPrincipal.AUTHENTICATED,
      permission: ACLPermission.ALLOW,
    },
  ];
  const methodRules: ACLRule[] = [
    {
      principal: roleName,
      permission: ACLPermission.ALLOW,
    },
  ];

  @acl.rules(classRules)
  class TestController {

    @acl.rules(methodRules)
    whoAmI() {}

    @acl.skip()
    hello() {}
  }

  class ControllerWithNoMetadata {
    whoAmI() {}
  }

  beforeEach(() => {
    provider = new ACLMetadataProvider(TestController, 'whoAmI');
  });

  it('returns acl metadata of a controller method', async () => {
    const aclMetadata: ACLMetadata | undefined = await provider.value();
    const rules = aclMetadata?.rules;
    expect(rules?.[0]).to.eql({
      principal: ACLPrincipal.EVERYONE,
      permission: ACLPermission.DENY,
      method: 'whoAmI',
    });
    expect(rules?.[1]).to.eql({
      principal: ACLPrincipal.AUTHENTICATED,
      permission: ACLPermission.ALLOW,
      method: 'whoAmI',
    });
  });

  it('returns undefined for a method decorated with @acl.skip', async () => {
    const context: Context = new Context();
    context.bind(CoreBindings.CONTROLLER_CLASS).to(TestController);
    context.bind(CoreBindings.CONTROLLER_METHOD_NAME).to('hello');
    context.bind(CoreBindings.CONTROLLER_METHOD_META)
      .toProvider(ACLMetadataProvider);
    const aclMetadata: ACLRule[] =
      await context.get(CoreBindings.CONTROLLER_METHOD_META);
    expect(aclMetadata).to.be.undefined;
  });

  it('returns undefined for a method decorated with @acl.skip even with default metadata', async () => {
    const context: Context = new Context();
    context.bind(CoreBindings.CONTROLLER_CLASS).to(TestController);
    context.bind(CoreBindings.CONTROLLER_METHOD_NAME).to('hello');
    context
      .bind(CoreBindings.CONTROLLER_METHOD_META)
      .toProvider(ACLMetadataProvider);
    context
      .configure(ACLBindings.COMPONENT)
      .to({defaultMetadata});
    const authMetadata: ACLMetadata | undefined =
      await context.get(CoreBindings.CONTROLLER_METHOD_META);
    expect(authMetadata).to.be.undefined;
  })

  it('returns undefined if no @acl metadata is defined', async () => {
    const context: Context = new Context();
    context
      .bind(CoreBindings.CONTROLLER_CLASS)
      .to(ControllerWithNoMetadata);
    context.bind(CoreBindings.CONTROLLER_METHOD_NAME).to('whoAmI');
    context
      .bind(CoreBindings.CONTROLLER_METHOD_META)
      .toProvider(ACLMetadataProvider);
    const authMetadata: ACLMetadata[] | undefined =
      await context.get(CoreBindings.CONTROLLER_METHOD_META);
    expect(authMetadata).to.be.undefined;
  });

  it('returns default metadata if no @acl metadata is defined', async () => {
    const context: Context = new Context();
    context
      .bind(CoreBindings.CONTROLLER_CLASS)
      .to(ControllerWithNoMetadata);
    context.bind(CoreBindings.CONTROLLER_METHOD_NAME).to('whoAmI');
    context
      .configure(ACLBindings.COMPONENT)
      .to({defaultMetadata});
    context
      .bind(CoreBindings.CONTROLLER_METHOD_META)
      .toProvider(ACLMetadataProvider);
    const aclMetadata: ACLMetadata[] | undefined =
      await context.get(CoreBindings.CONTROLLER_METHOD_META);
    expect(aclMetadata).to.be.eql(defaultMetadata);
  });

  it('returns undefined when the class or method is missing', async () => {
    const context: Context = new Context();
    context
      .bind(CoreBindings.CONTROLLER_METHOD_META)
      .toProvider(ACLMetadataProvider);
    const aclMetadata: ACLMetadata[] | undefined =
      await context.get(CoreBindings.CONTROLLER_METHOD_META);
    expect(aclMetadata).to.be.undefined;
  });
});
