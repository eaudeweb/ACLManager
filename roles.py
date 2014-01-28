#The contents of this file are subject to the Mozilla Public
#License Version 1.1 (the "License"); you may not use this file
#except in compliance with the License. You may obtain a copy of
#the License at http://www.mozilla.org/MPL/
#
#Software distributed under the License is distributed on an "AS
#IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
#implied. See the License for the specific language governing
#rights and limitations under the License.
#
#The Initial Owner of the Original Code is European Environment
#Agency (EEA). Portions created by Eau de Web are Copyright (C) 
#2007 by European Environment Agency. All Rights Reserved.
#
#Contributor(s):
#  Original Code: 
#        Cornel Nitu (Eau de Web)

from AccessControl import ClassSecurityInfo
from Globals import InitializeClass

class acl_roles:

    security = ClassSecurityInfo()

    def has_ano_role(self):
        """ check if the user anonymous """
        return self.REQUEST.AUTHENTICATED_USER.getUserName() == 'Anonymous User'

    def has_sta_role(self, username=None):
        """ check if the user has STA (Stakeholder) role assigned"""
        if username:
            user_object = self.acl_users.getUser(username)
            if user_object:
                return user_object.has_role('Stakeholder')
            else:
                return False
        return self.REQUEST.AUTHENTICATED_USER.has_role('Stakeholder')

    def has_nat_role(self, username=None):
        """ check if the user has STA (Stakeholder) role assigned"""
        if username:
            user_object = self.acl_users.getUser(username)
            if user_object:
                return user_object.has_role('NAT')
            else:
                return False
        return self.REQUEST.AUTHENTICATED_USER.has_role('NAT')

    def has_etc_role(self, username=None):
        """ check if the user has ETC (ETC Expert) role assigned"""
        if username:
            user_object = self.acl_users.getUser(username)
            if user_object:
                return user_object.has_role('ETC Expert')
            else:
                return False
        return self.REQUEST.AUTHENTICATED_USER.has_role('ETC Expert')

    def has_adm_role(self, username=None):
        """ check if the user has ADM (Administrator) role assigned"""
        if username:
            user_object = self.acl_users.getUser(username)
            if user_object:
                return user_object.has_role('Administrator') or user_object.has_role('Manager')
            else:
                return False
        return self.REQUEST.AUTHENTICATED_USER.has_role('Administrator') or self.REQUEST.AUTHENTICATED_USER.has_role('Manager')

InitializeClass(acl_roles)
