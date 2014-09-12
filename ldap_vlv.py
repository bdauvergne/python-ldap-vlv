import ldap
from ldap.ldapobject import LDAPObject
from ldap.controls import (RequestControl, ResponseControl,
        KNOWN_RESPONSE_CONTROLS, DecodeControlTuples)

from pyasn1.type import univ, namedtype, tag, namedval, constraint
from pyasn1.codec.ber import encoder, decoder

__ALL__ = ['VLVRequestControl', 'VLVResponseControl', 'SSSRequestControl',
    'SSSResponseControl', 'SSSVLVPagedLDAPObject']


class ByOffsetType(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
            tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('offset', univ.Integer()),
            namedtype.NamedType('contentCount', univ.Integer()))


class TargetType(univ.Choice):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('byOffset', ByOffsetType()),
            namedtype.NamedType('greaterThanOrEqual', univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                    tag.tagFormatSimple, 1))))


class VirtualListViewRequestType(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('beforeCount', univ.Integer()),
            namedtype.NamedType('afterCount', univ.Integer()),
            namedtype.NamedType('target', TargetType()),
            namedtype.OptionalNamedType('contextID', univ.OctetString()))

VLV_REQUEST_CONTROL_OID = '2.16.840.1.113730.3.4.9'

class VLVRequestControl(RequestControl):
    def __init__(self, before_count=0, after_count=0,
            offset=None, content_count=None, greater_than_or_equal=None,
            context_id=None, controlType=VLV_REQUEST_CONTROL_OID,
            **kwargs):
        RequestControl.__init__(self, controlType, **kwargs)
        assert (offset is not None and content_count is not None) or greater_than_or_equal, 'offset and ' \
            'content_count must be set together or greater_than_or_equal must be ' \
            'used'
        self.before_count = before_count
        self.after_count = after_count
        self.offset = offset
        self.content_count = content_count
        self.greater_than_or_equal = greater_than_or_equal
        self.context_id = context_id

    def encodeControlValue(self):
        p = VirtualListViewRequestType()
        p.setComponentByName('beforeCount', self.before_count)
        p.setComponentByName('afterCount', self.after_count)
        if self.offset is not None and self.content_count is not None:
            by_offset = ByOffsetType()
            by_offset.setComponentByName('offset', self.offset)
            by_offset.setComponentByName('contentCount', self.content_count)
            target = TargetType()
            target.setComponentByName('byOffset', by_offset)
        elif self.greater_than_or_equal:
            target = TargetType()
            target.setComponentByName('greaterThanOrEqual',
                    self.greater_than_or_equal)
        else:
            raise NotImplementedError
        p.setComponentByName('target', target)
        return encoder.encode(p)


class VirtualListViewResultType(univ.Enumerated):
    namedValues = namedval.NamedValues(
               ('success', 0),
               ('operationsError', 1),
               ('protocolError', 3),
               ('unwillingToPerform', 53),
               ('insufficientAccessRights', 50),
               ('adminLimitExceeded', 11),
               ('innapropriateMatching', 18),
               ('sortControlMissing', 60),
               ('offsetRangeError', 61),
               ('other', 80),
    )


class VirtualListViewResponseType(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('targetPosition', univ.Integer()),
            namedtype.NamedType('contentCount', univ.Integer()),
            namedtype.NamedType('virtualListViewResult',
                VirtualListViewResultType()),
            namedtype.OptionalNamedType('contextID', univ.OctetString()))

VLV_RESPONSE_CONTROL_OID = '2.16.840.1.113730.3.4.10'

class VLVResponseControl(ResponseControl):
    def __init__(self, controlType=VLV_RESPONSE_CONTROL_OID, **kwargs):
        ResponseControl.__init__(self, controlType=controlType, **kwargs)

    def decodeControlValue(self, encoded):
        p, rest = decoder.decode(encoded, asn1Spec=VirtualListViewResponseType())
        assert not rest, 'all data could not be decoded'
        self.target_position = int(p.getComponentByName('targetPosition'))
        self.content_count = int(p.getComponentByName('contentCount'))
        self.result = int(p.getComponentByName('virtualListViewResult'))
        self.result_code = p.getComponentByName('virtualListViewResult') \
                .prettyOut(self.result)
        self.context_id = p.getComponentByName('contextID')
        if self.context_id:
            self.context_id = str(self.context_id)


#    SortKeyList ::= SEQUENCE OF SEQUENCE {
#                     attributeType   AttributeDescription,
#                     orderingRule    [0] MatchingRuleId OPTIONAL,
#                     reverseOrder    [1] BOOLEAN DEFAULT FALSE }


class SortKeyType(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('attributeType', univ.OctetString()),
            namedtype.OptionalNamedType('orderingRule',
                  univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                  )
                ),
            namedtype.DefaultedNamedType('reverseOrder', univ.Boolean(False).subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))))


class SortKeyListType(univ.SequenceOf):
    componentType = SortKeyType()

SSS_REQUEST_CONTROL_OID = '1.2.840.113556.1.4.473'

class SSSRequestControl(RequestControl):
    '''Order result server side

        >>> s = SSSRequestControl('-cn')
    '''

    def __init__(self, ordering_rules, controlType=SSS_REQUEST_CONTROL_OID,
            **kwargs):
        RequestControl.__init__(self, controlType=controlType, **kwargs)
        self.ordering_rules = ordering_rules
        if isinstance(ordering_rules, basestring):
            ordering_rules = [ordering_rules]
        for rule in ordering_rules:
            rule = rule.split(':')
            assert len(rule) < 3, 'syntax for ordering rule: [-]<attribute-type>[:ordering-rule]'

    def asn1(self):
        p = SortKeyListType()
        for i, rule in enumerate(self.ordering_rules):
            q = SortKeyType()
            reverse_order = rule.startswith('-')
            if reverse_order:
                rule = rule[1:]
            if ':' in rule:
                attribute_type, ordering_rule = rule.split(':')
            else:
                attribute_type, ordering_rule = rule, None
            q.setComponentByName('attributeType', attribute_type)
            if ordering_rule:
                q.setComponentByName('orderingRule', ordering_rule)
            if reverse_order:
                q.setComponentByName('reverseOrder', 1)
            p.setComponentByPosition(i, q)
        return p

    def encodeControlValue(self):
        return encoder.encode(self.asn1())


#      SortResult ::= SEQUENCE {
#         sortResult  ENUMERATED {
#             success                   (0), -- results are sorted
#             operationsError           (1), -- server internal failure
#             timeLimitExceeded         (3), -- timelimit reached before
#                                            -- sorting was completed
#             strongAuthRequired        (8), -- refused to return sorted
#                                            -- results via insecure
#                                            -- protocol
#             adminLimitExceeded       (11), -- too many matching entries
#                                            -- for the server to sort
#             noSuchAttribute          (16), -- unrecognized attribute
#                                            -- type in sort key
#             inappropriateMatching    (18), -- unrecognized or
#                                            -- inappropriate matching
#                                            -- rule in sort key
#             insufficientAccessRights (50), -- refused to return sorted
#                                            -- results to this client
#             busy                     (51), -- too busy to process
#             unwillingToPerform       (53), -- unable to sort
#             other                    (80)
#             },
#       attributeType [0] AttributeDescription OPTIONAL }


class SortResultType(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('sortResult', univ.Enumerated().subtype(
                namedValues=namedval.NamedValues(
                        ('success', 0),
                        ('operationsError', 1),
                        ('timeLimitExceeded', 3),
                        ('strongAuthRequired', 8),
                        ('adminLimitExceeded', 11),
                        ('noSuchAttribute', 16),
                        ('inappropriateMatching', 18),
                        ('insufficientAccessRights', 50),
                        ('busy', 51),
                        ('unwillingToPerform', 53),
                        ('other', 80)),
                subtypeSpec=univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(
                        0, 1, 3, 8, 11, 16, 18, 50, 51, 53, 80))),
            namedtype.OptionalNamedType('attributeType',
                  univ.OctetString().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                  )
                ))


SSS_RESPONSE_CONTROL_OID = '1.2.840.113556.1.4.474'

class SSSResponseControl(ResponseControl):
    def __init__(self, controlType=SSS_RESPONSE_CONTROL_OID, **kwargs):
        ResponseControl.__init__(self, controlType=controlType, **kwargs)

    def decodeControlValue(self, encoded):
        p, rest = decoder.decode(encoded, asn1Spec=SortResultType())
        assert not rest, 'all data could not be decoded'
        self.result = int(p.getComponentByName('sortResult'))
        self.result_code = p.getComponentByName('sortResult').prettyOut(self.result)
        self.attribute_type_error = p.getComponentByName('attributeType')


KNOWN_RESPONSE_CONTROLS[VLV_REQUEST_CONTROL_OID] = VLVRequestControl
KNOWN_RESPONSE_CONTROLS[VLV_RESPONSE_CONTROL_OID] = VLVResponseControl
KNOWN_RESPONSE_CONTROLS[SSS_REQUEST_CONTROL_OID] = SSSRequestControl
KNOWN_RESPONSE_CONTROLS[SSS_RESPONSE_CONTROL_OID] = SSSResponseControl


class SSSVLVPagedLDAPObject(LDAPObject):
    def result4(self, msgid=ldap.RES_ANY, all=1, timeout=None, add_ctrls=0, add_intermediates=0, add_extop=0, resp_ctrl_classes=None):
      if timeout is None:
        timeout = self.timeout
      ldap_result = self._ldap_call(self._l.result4,msgid,all,timeout,add_ctrls,add_intermediates,add_extop)
      if ldap_result is None:
          resp_type, resp_data, resp_msgid, resp_ctrls, resp_name, resp_value = (None,None,None,None,None,None)
      else:
        if len(ldap_result)==4:
          resp_type, resp_data, resp_msgid, resp_ctrls = ldap_result
          resp_name, resp_value = None,None
        else:
          resp_type, resp_data, resp_msgid, resp_ctrls, resp_name, resp_value = ldap_result
        if add_ctrls:
          resp_data = [ (t,r,DecodeControlTuples(c,resp_ctrl_classes)) for t,r,c in resp_data ]
      decoded_resp_ctrls = DecodeControlTuples(resp_ctrls,resp_ctrl_classes)
      for ctrl in decoded_resp_ctrls:
          if ctrl.controlType == VLV_RESPONSE_CONTROL_OID:
              self.context_id = ctrl.context_id
      return resp_type, resp_data, resp_msgid, decoded_resp_ctrls, resp_name, resp_value

    def search_ext(self, base, scope, filterstr='(objectClass=*)',
            attrlist=None, attrsonly=0, serverctrls=None, clientctrls=None,
            timeout=-1, sizelimit=0, offset=None, length=None, ordering=None,
            context_id=None):
        assert not (offset and length) or ordering, 'if VLV is used ordering is mandatory'
        assert not ((offset is not None) ^ (length is not None)), 'offset and length must be set on unset at the same time'
        serverctrls = serverctrls or []
        clientctrls = []
        if ordering:
            serverctrls.append(SSSRequestControl(ordering, criticality=True))
            print serverctrls[-1].asn1().prettyPrint()
        if offset is not None:
            serverctrls.append(VLVRequestControl(offset=offset,
                after_count=length, content_count=0, criticality=True,
                context_id=context_id))
        self.vlv = True
        result = LDAPObject.search_ext(self, base, scope, filterstr, attrlist,
                attrsonly, serverctrls, clientctrls, timeout, sizelimit)
        del self.vlv
        return result


    def search_ext_s(self, base, scope, filterstr='(objectClass=*)',
        attrlist=None, attrsonly=0, serverctrls=None, clientctrls=None, timeout=-1,
        sizelimit=0, offset=None, length=None, ordering=None, context_id=None):
      msgid = self.search_ext(base, scope, filterstr, attrlist, attrsonly,
              serverctrls, clientctrls, timeout, sizelimit, offset, length,
              ordering, context_id)
      return self.result(msgid, all=1, timeout=timeout)[1]

    def search(self, base, scope, filterstr='(objectClass=*)', attrlist=None,
        attrsonly=0, offset=None, length=None, ordering=None, context_id=None):
      return self.search_ext(base, scope, filterstr, attrlist, attrsonly,
              None, None, -1, 0, offset, length, ordering, context_id)

    def search_s(self, base, scope, filterstr='(objectClass=*)', attrlist=None,
            attrsonly=0, offset=None, length=None, ordering=None, context_id=None):
      return self.search_ext_s(base, scope, filterstr, attrlist, attrsonly,
              None, None, self.timeout, 0, offset, length,
              ordering, context_id)

    def search_st(self,  base, scope, filterstr='(objectClass=*)',
            attrlist=None, attrsonly=0, timeout=-1, offset=None, length=None,
            ordering=None, context_id=None):
      return self.search_ext_s(base, scope, filterstr, attrlist, attrsonly,
              None, None, timeout, offset, length, ordering, context_id)
