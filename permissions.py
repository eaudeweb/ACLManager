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

from AccessControl import ClassSecurityInfo, getSecurityManager
from Globals import InitializeClass

class acl_permissions:

    security = ClassSecurityInfo()

    security.declareProtected('Article 17 - Edit decision', 'permission_edit_decision')
    def permission_edit_decision(self):
        raise NotImplemented

    security.declareProtected('Article 17 - View decision', 'permission_view_decision')
    def permission_view_decision(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Manage data sheet', 'permission_manage_wiki')
    def permission_manage_wiki(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Edit data sheet', 'permission_edit_wiki')
    def permission_edit_wiki(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Add data sheet comments', 'permission_add_wiki_comments')
    def permission_add_wiki_comments(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Manage audit trail', 'permission_manage_audit')
    def permission_manage_audit(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Edit audit trail', 'permission_edit_audit')
    def permission_edit_audit(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Add audit trail comments', 'permission_add_audit_comments')
    def permission_add_audit_comments(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Add conclusion', 'permission_add_conclusion')
    def permission_add_conclusion(self):
        raise NotImplemented

    security.declareProtected('Article 17 - Edit conclusion', 'permission_edit_conclusion')
    def permission_edit_conclusion(self):
        raise NotImplemented

    security.declareProtected('Article 17 - View ETC comments', 'permission_view_etc_comments')
    def permission_view_etc_comments(self):
        raise NotImplemented

    security.declareProtected('Article 17 - View STA comments', 'permission_view_sta_comments')
    def permission_view_sta_comments(self):
        raise NotImplemented

    security.declareProtected('Article 17 - View STA conclusions', 'permission_view_sta_conclusions')
    def permission_view_sta_conclusions(self):
        raise NotImplemented

    security.declareProtected('Article 17 - View ETC conclusions', 'permission_view_etc_conclusions')
    def permission_view_etc_conclusions(self):
        raise NotImplemented

    def checkPermission(self, p_permission):
        """
        Generic function to check a given permission on the current object.
        @param p_permission: permissions name
        @type p_permission: string
        @return:
            - B{1} if the current user has the permission
            - B{None} otherwise
        """
        return getSecurityManager().checkPermission(p_permission, self)

    def checkPermissionAddConclusion(self):
        """ check if the authenticated user has the rights to add a conclusion """
        return self.checkPermission('Article 17 - Add conclusion')

    def checkPermissionEditConclusion(self):
        """ check if the authenticated user has the rights to edit a conclusion """
        return self.checkPermission('Article 17 - Edit conclusion')

    def checkPermissionEditDecision(self):
        """ check if the authenticated user has the rights to add/edit a decision """
        return self.checkPermission('Article 17 - Edit decision')

    def checkPermissionViewDecision(self):
        """ check if the user has the rights to view a decision """
        return self.checkPermission('Article 17 - View decision')

    def checkPermissionManageWiki(self):
        """ check if the user has the rights to manage wiki tool """
        return self.checkPermission('Article 17 - Manage data sheet')

    def checkPermissionEditWiki(self):
        """ check if the user has the rights to edit wiki pages """
        return self.checkPermission('Article 17 - Edit data sheet')

    def checkPermissionAddWikiComments(self):
        """ check if the user has the rights to add wiki comments """
        return self.checkPermission('Article 17 - Add data sheet comments')

    def checkPermissionManageAudit(self):
        """ check if the user has the rights to manage wiki tool """
        return self.checkPermission('Article 17 - Manage audit trail')

    def checkPermissionEditAudit(self):
        """ check if the user has the rights to edit wiki pages """
        return self.checkPermission('Article 17 - Edit audit trail')

    def checkPermissionAddAuditComments(self):
        """ check if the user has the rights to add wiki comments """
        return self.checkPermission('Article 17 - Add audit trail comments')

    def checkPermissionViewETCComments(self):
        """ check if the user has the rights to add/view comments on ETC conclusions """
        return self.checkPermission('Article 17 - View ETC comments')

    def checkPermissionViewSTAComments(self):
        """ check if the user has the rights to add/view comments on STA conclusions """
        return self.checkPermission('Article 17 - View STA comments')

    def checkPermissionViewSTAConclusions(self):
        """ check if the user has the rights to view STA conclusions """
        return self.checkPermission('Article 17 - View STA conclusions')

    def checkPermissionViewETCConclusions(self):
        """ check if the user has the rights to view ETC conclusions """
        return self.checkPermission('Article 17 - View ETC conclusions')

InitializeClass(acl_permissions)