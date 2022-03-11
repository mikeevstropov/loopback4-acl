import {
  acl,
  ACLMetadata,
  ACLPermission,
  getAclMetadata,
  ACLCommonPrincipal,
} from '../../..';
import {use} from 'chai';
import {expect} from 'chai';
import chaiSubset from "chai-subset";

use(chaiSubset);

describe('ACL', () => {
  describe('@acl decorator', () => {
    it('can use default metadata in class level', () => {
      @acl()
      class TestClass {
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.eql({rules: [], skip: false});
    });
    it('can use default metadata in method level', () => {
      class TestClass {
        @acl()
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.eql({rules: [], skip: false});
    });
    it('can use default metadata in class and method level', () => {
      @acl()
      class TestClass {
        @acl()
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.eql({rules: [], skip: false});
    });
    it('can add metadata in class level', () => {
      const metadata: ACLMetadata = {
        rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY,
          method: 'whoAmI',
        }, {
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW,
          method: 'whoAmI',
        }],
        skip: false,
      };

      @acl(metadata)
      class TestClass {
        whoAmI() {}
      }

      const appliedMetadata = getAclMetadata(TestClass, 'whoAmI');
      expect(appliedMetadata).to.eql(metadata);
    });
    it('can add metadata in method level', () => {
      const metadata: ACLMetadata = {
        rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY,
          method: 'whoAmI',
        }, {
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW,
          method: 'whoAmI',
        }],
        skip: false,
      };

      class TestClass {
        @acl(metadata)
        whoAmI() {}
      }

      const appliedMetadata = getAclMetadata(TestClass, 'whoAmI');
      expect(appliedMetadata).to.eql(metadata);
    });
    it('can merge class and method metadata', () => {
      const classMetadata = {
        rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.DENY,
          method: 'whoAmI'
        }, {
          principal: ACLCommonPrincipal.AUTHENTICATED,
          permission: ACLPermission.ALLOW,
          method: 'whoAmI'
        }],
        skip: false,
      };
      const methodMetadata = {
        rules: [{
          principal: ACLCommonPrincipal.EVERYONE,
          permission: ACLPermission.ALLOW,
          method: 'whoAmI'
        }],
        skip: false,
      };

      @acl(classMetadata)
      class TestClass {
        @acl(methodMetadata)
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.eql({
        rules: [
          ...classMetadata.rules,
          ...methodMetadata.rules
        ],
        skip: false,
      });
    });
  })

  describe('@acl.skip() decorator', () => {
    it('can add "skip" option in class level', () => {
      @acl.skip()
      class TestClass {
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.eql({rules: [], skip: true});
    });
    it('can add "skip" option in method level', () => {
      class TestClass {
        @acl.skip()
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.eql({rules: [], skip: true});
    });
  });

  describe('@acl.rules() decorator', () => {
    it('can add rules option in class level', () => {
      const rules = [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY,
      }, {
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW,
      }];

      @acl.rules(rules)
      class TestClass {
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.containSubset({rules});
      expect(metadata?.rules).to.lengthOf(2);
    });
    it('can add rules option in method level', () => {
      const rules = [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY,
      }, {
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW,
      }];

      class TestClass {
        @acl.rules(rules)
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.containSubset({rules});
      expect(metadata?.rules).to.lengthOf(2);
    });
    it('can merge class and method rules option', () => {
      const classRules = [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.DENY,
      }, {
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW,
      }];
      const methodRules = [{
        principal: ACLCommonPrincipal.EVERYONE,
        permission: ACLPermission.ALLOW,
      }];

      @acl.rules(classRules)
      class TestClass {
        @acl.rules(methodRules)
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata).to.containSubset({rules: [...classRules, ...methodRules]});
      expect(metadata?.rules).to.lengthOf(3);
    });
    it('can merge duplicated rules of class and method levels', () => {
      const rule = {
        principal: ACLCommonPrincipal.AUTHENTICATED,
        permission: ACLPermission.ALLOW,
      };

      @acl.rules([rule])
      class TestClass {
        @acl.rules([rule])
        whoAmI() {}
      }

      const metadata = getAclMetadata(TestClass, 'whoAmI');
      expect(metadata?.rules?.[0]).to.containSubset(rule);
      expect(metadata?.rules).to.lengthOf(1);
    });
  });
});
