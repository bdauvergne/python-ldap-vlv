import ldap_vlv
import ldap
import ldap.sasl

c = ldap_vlv.SSSVLVPagedLDAPObject('ldapi://')
c.sasl_interactive_bind_s("", ldap.sasl.external())

import sys

for dn, att in c.search_s('ou=interne,ou=personnes,o=formiris', ldap.SCOPE_SUBTREE, 'objectClass=person', attrlist=['cn'],
        offset=int(sys.argv[1]), length=int(sys.argv[2]), ordering='cn:1.3.6.1.4.1.1466.109.114.2'):
    print dn
