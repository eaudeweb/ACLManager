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

import os
import logging
import re
from DateTime import DateTime

#Zope imports
#from zope.interface import implements
from OFS.Folder import Folder
from Globals import InitializeClass
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from AccessControl import ClassSecurityInfo, Unauthorized
from AccessControl.Permissions import view_management_screens, view, manage_users

#Product imports
import utils
import captcha
from paginator import ObjectPaginator
from permissions import acl_permissions
from roles import acl_roles

logger = logging.getLogger(__name__)

manage_addACLManager_html = PageTemplateFile('zpt/manage_add', globals())

def manage_addACLManager(self, id='', title='', REQUEST=None):
    """ Create a ACLManager type of object.  """
    ob = ACLManager(id, title)
    self._setObject(id, ob)
    if REQUEST is not None:
        return self.manage_main(self, REQUEST, update_menu=1)

class ACLManager(Folder, acl_permissions, acl_roles):
    """ """

    meta_type = 'ACL Manager'
    icon = 'misc_/ACLManager/ACLManager.gif'

    security = ClassSecurityInfo()

    def __init__(self, id, title):
        """ """
        self.id = id
        self.title = title
        self.public_key = ''
        self.private_key = ''
        self.deadline = ''
        self.support_email = ''
        self.register_email = ''
        self.use_captcha = True

    #Add account
    security.declarePrivate('create_account')
    def create_account(self, username, password, confirm):
        """ create the account in the Zope's UserFolder """
        self.acl_users._addUser(username, password, confirm, roles=[], domains=[])

    security.declareProtected(view, 'confirmAccount')
    def confirmAccount(self, key, REQUEST, RESPONSE):
        """ activate an account """
        session = REQUEST.SESSION
        username = utils.email_decode(key)
        user = self.acl_users.getUser(username)
        if user:
            if user.getRoles() == ('Authenticated',):
                self.edit_account(username, user._getPassword(), roles=['Stakeholder'])
                #send notification email to the administrators
                self.send_notification(username, user.getUserName())
                session.set('username', user.getUserName())
            else:
                session.set('active_account', user.getUserName())
        else:
            session.set('err_username', 'There has been an error')
        return RESPONSE.redirect('confirmation_html')

    security.declarePrivate('create_account_details')
    def create_account_details(self, username, name, email, institution, abbrev, ms, qualification):
        """ save user's credentials in the database """
        #use the ZSQLMethod from ZMI
        self.insert_user_details(user=username, name=name, email=email, institution=institution, abbrev=abbrev, MS=ms, qualification=qualification, account_date=DateTime().strftime('%Y-%m-%d %H:%M'))

    #Add LDAP account
    security.declareProtected(manage_users, 'getLDAPSchema')
    def getLDAPSchema(self):
        """ returns the schema for a LDAPUserFolder """
        return self.acl_users.getLDAPSchema()

    security.declareProtected(manage_users, 'findLDAPUsers')
    def findLDAPUsers(self, params='', term=''):
        """ search for users in LDAP """
        if params and term:
            try:
                self.buffer = {}
                users = self.acl_users.findUser(search_param=params, search_term=term)
                [ self.buffer.setdefault(u['uid'], u['cn']) for u in users ]
                return users
            except: return ()
        else:   return ()

    security.declareProtected(manage_users, 'addLDAPUserRoles')
    def addLDAPUserRoles(self, user_dns='', roles='', REQUEST=None):
        """ """
        #process form values
        if user_dns == '':  user_dns = []
        else: user_dns = utils.convertToList(user_dns)
        if roles == '': roles = []
        else: roles = utils.convertToList(roles)
        #assign roles
        for user_dn in user_dns:
            self.acl_users.manage_editUserRoles(user_dn, roles)
            username = self.getLDAPAttribute(user_dn, 'uid')
            if not username:
                self.create_account_details(username, '', '', self.getLDAPAttribute(user_dn, 'o'), '', '', '')
            try:
                email = self.getLDAPAttribute(user_dn, 'mail')
                name = self.getLDAPAttribute(user_dn, 'cn')
                self.send_ldap_user_notification(username, name, email, roles)
            except:
                pass
        if REQUEST is not None:
            REQUEST.RESPONSE.redirect('ldap_users_html')

    #Edit account
    security.declarePrivate('edit_account')
    def edit_account(self, username, password, roles, domains=[]):
        """ create the account in the Zope's UserFolder """
        self.acl_users._doChangeUser(username, password, roles, domains)

    security.declarePrivate('edit_account_details')
    def edit_account_details(self, username, name, email, institution, abbrev, ms, qualification):
        """ save user's credentials in the database """
        #use the ZSQLMethod from ZMI
        self.update_user_details(user=username, name=name, email=email, institution=institution, abbrev=abbrev, MS=ms, qualification=qualification, account_date=DateTime().strftime('%Y-%m-%d %H:%M'))

    security.declareProtected(manage_users, 'editLDAPUser')
    def editLDAPUser(self, username, institution='', abbrev='', ms='', roles=[], REQUEST=None, RESPONSE=None):
        """ edit account credentials (only password for LDAP) """

        if REQUEST is not None:
            user = self.acl_users.getUser(username)

            if user:
                session = REQUEST.SESSION

                roles = utils.convertToList(roles)
                user_dn = user.getUserDN()

                self.acl_users.manage_editUserRoles(user_dn, roles)
                if self.getUserDetails(username):   #backwards compatibility
                    self.edit_account_details(username, '', '', institution, abbrev, ms, '')
                else:
                    self.create_account_details(username, '', '', institution, abbrev, ms, '')
                session.set('op_completed', True)
            return RESPONSE.redirect(REQUEST.HTTP_REFERER)
        else:
            raise NotImplemented

    security.declareProtected(manage_users, 'editUser')
    def editUser(self, username, name, email, institution, abbrev, ms, qualification, password, roles=[], REQUEST=None, RESPONSE=None):
        """ process the request for a new account """

        if REQUEST is not None:
            #get the user credentials
            user = self.acl_users.getUser(username)
            user_info = self.getUserDetails(username)

            if user:
                session = REQUEST.SESSION

                #validate form fields
                if not name:
                    session.set('err_name', 'Please enter your name')

                email_expr = re.compile('^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}$', re.IGNORECASE)
                if not re.match(email_expr, email):
                    session.set('err_email', 'Please enter a correct email address')

                pwd_changed = 1
                if not password:
                    pwd_changed = 0
                    password = user._getPassword()

                roles = utils.convertToList(roles)

                if not session.keys():
                    #create account
                    self.edit_account(username, password, roles)
                    self.edit_account_details(username, name, email, institution, abbrev, ms, qualification)

                    if pwd_changed:
                        #send notification email to user if password has been changed
                        self.forgot_password(username, email, password)
                        session.set('password_changed', 1)

                    session.set('op_completed', True)
                else:
                    #put form field values on session
                    session.set('name', name)
                    session.set('email', email)
                    session.set('institution', institution)
                    session.set('ms', ms)
                    session.set('qualification', qualification)
                    session.set('roles', roles)
            return RESPONSE.redirect(REQUEST.HTTP_REFERER)
        else:
            raise NotImplemented

    #Delete accounts
    security.declareProtected(manage_users, 'deleteLocalUsers')
    def deleteLocalUsers(self, del_users=[], type='', REQUEST=None):
        """ """
        del_users = utils.convertToList(del_users)
        if del_users:
            #delete from acl_users
            self.acl_users._delUsers(del_users, REQUEST)
            for user in del_users:
                #delete from database
                self.delete_user_details(user=user)
        if REQUEST is not None:
            return REQUEST.RESPONSE.redirect('users_html#%s' % type)

    security.declareProtected(manage_users, 'deleteLDAPUsers')
    def deleteLDAPUsers(self, del_users=[], REQUEST=None):
        """ """
        del_users = utils.convertToList(del_users)
        for user_dn in del_users:
            self.acl_users.manage_editUserRoles(user_dn, role_dns=[])
            username = self.getLDAPAttribute(user_dn, 'uid')
            self.delete_user_details(user=username)
        if REQUEST is not None:
            return REQUEST.RESPONSE.redirect('ldap_users_html')

    #View accounts
    security.declareProtected(manage_users, 'getUserDetails')
    def getUserDetails(self, username):
        """" return the user details """
        user_info = self.lookup_user(user=username)
        if user_info:
            return user_info[0]

    security.declareProtected(manage_users, 'paggingUsers')
    def paggingUsers(self, users_list):
        return ObjectPaginator(users_list, num_per_page=15, orphans=8)

    security.declareProtected(view, 'getSpecificUserRoles')
    def getSpecificUserRoles(self, user):
        """ return a dictionary with the user roles """
        user_ob = self.acl_users.getUser(user)
        if user_ob is not None:
            return self.acl_manager.getUserRoles(user_ob)
        else:
            return {'administrator':0, 'expert':0, 'stakeholder':0, 'nat': 0}

    security.declareProtected(view, 'getAuthenticatedUserRoles')
    def getAuthenticatedUserRoles(self, username):
        """ return the roles of the authenticated user """
        user_object = self.acl_users.getUser(username)
        return user_object.getRoles()

    security.declareProtected(manage_users, 'getUserRoles')
    def getUserRoles(self, user):
        """ return a dictionary with the user roles """
        output = {'administrator':0, 'expert':0, 'stakeholder':0, 'nat':0}
        user_roles = user.getRoles()
        if 'Manager' in user_roles:
            output['administrator'] = 1
        if 'ETC Expert' in user_roles:
            output['expert'] = 1
        if 'Stakeholder' in user_roles:
            output['stakeholder'] = 1
        if 'NAT' in user_roles:
            output['nat'] = 1
        return output

    security.declareProtected(manage_users, 'getLDAPUserRoles')
    def getLDAPUserRoles(self, user_roles):
        """ return a dictionary with the user roles """
        output = {'administrator':0, 'expert':0, 'stakeholder':0, 'nat':0}
        if 'Manager' in user_roles:
            output['administrator'] = 1
        if 'ETC Expert' in user_roles:
            output['expert'] = 1
        if 'Stakeholder' in user_roles:
            output['stakeholder'] = 1
        if 'NAT' in user_roles:
            output['nat'] = 1
        return output

    security.declareProtected(view, 'getUserFullDetails')
    def getUserFullDetails(self, name):
        """ return the user full name and institution """
        user_ob = self.acl_users.getUser(name)
        user_details = ''
        if hasattr(user_ob, 'RID'):
            user_dn = user_ob.getUserDN()
            user_details = '%s - %s' % (self.acl_users.getLDAPAttribute(user_dn, 'cn'), self.acl_users.getLDAPAttribute(user_dn, 'o'))
        else:
            user_info = self.getUserDetails(name)
            user_details = '%s - %s' % (user_info['name'], user_info['institution'])
        return user_details

    security.declareProtected(view, 'getUserInstitution')
    def getUserInstitution(self, name):
        """ return the user's institution name """
        user_details = ''
        user_ob = self.acl_users.getUser(name)
        user_info = self.getUserDetails(name)
        if user_info:
            user_details = '%s' % user_info['institution']
        elif hasattr(user_ob, 'RID'):
            user_dn = user_ob.getUserDN()
            user_details = '%s' % self.acl_users.getLDAPAttribute(user_dn, 'o')
        return user_details

    security.declareProtected(view, 'getUserInstAbbrev')
    def getUserInstAbbrev(self, name):
        """ return the user's institution abbreviation """
        user_ob = self.acl_users.getUser(name)
        user_info = self.getUserDetails(name)
        if user_info:
            return '%s' % user_info['abbrev']

    security.declareProtected(view, 'getUserAccountDate')
    def getUserAccountDate(self, name):
        """ return the user's account creation date """
        user_ob = self.acl_users.getUser(name)
        user_info = self.getUserDetails(name)
        if user_info:
            return '%s' % user_info['account_date']

    security.declareProtected(view, 'getUserMS')
    def getUserMS(self, name):
        """ return the user's institution name """
        user_ob = self.acl_users.getUser(name)
        user_info = self.getUserDetails(name)
        if user_info:
            user_details = '%s' % user_info['MS']
            return user_details
        return ''

    security.declarePrivate('get_user_name')
    def get_user_name(self, user, name=''):
        """ """
        try:
            if hasattr(user, 'RID'):
                user_dn = user.getUserDN()
                user_details = '%s' % self.acl_users.getLDAPAttribute(user_dn, 'cn')
                return unicode(user_details, 'latin-1')
            else:
                user_info = self.getUserDetails(user)
                user_details = '%s' % user_info['name']
                return unicode(user_details, 'utf-8')
        except:
            return name

    security.declareProtected(view, 'getUserFullName')
    def getUserFullName(self, name):
        """ return the user full name """
        user_ob = self.acl_users.getUser(name)
        if self.acl_manager.has_etc_role(name) or self.acl_manager.has_adm_role(name):
            if self.acl_manager.has_etc_role() or self.acl_manager.has_adm_role():
                return self.get_user_name(user_ob, name)
            else:
                return ''
        else:
            return self.get_user_name(user_ob, name)

    security.declareProtected(manage_users, 'getValidRoles')
    def getValidRoles(self):
        """ return a list with all the valid roles """
        return ['Manager', 'ETC Expert', 'Stakeholder', 'NAT']

    security.declarePrivate('login_ldap')
    def login_ldap(self, username, password):
        """ authenticate a user against LDAP """
        return self.acl_users.authenticate(username, password, request=None)

    security.declarePrivate('map_ldap_account')
    def map_ldap_account(self, username):
        """ authenticate a user against LDAP """
        user = self.acl_users.getUser(username)
        return self.acl_users.manage_editUserRoles(user_dn=user.getUserDN(), role_dns=['ETC Expert'])

    security.declareProtected(manage_users, 'getLDAPAttribute')
    def getLDAPAttribute(self, user_dn, attr):
        """ return a LDAP attribute for a given user dn"""
        user_details = self.acl_users.getUserDetails(user_dn, format='dictionary')
        if user_details.has_key(attr):
            return user_details[attr][0]
        return ''

    security.declareProtected(manage_users, 'getUsersType')
    def getUsersType(self, users):
        """ return the list of pending and active users given the local users list """
        active = []
        pending = []
        for user in users:
            user_ob = self.acl_users.getLocalUser(user['user'])
            if self.getUserDetails(user['user']):
                 if user_ob is not None:
                    if user_ob.getRoles() != ('Authenticated',):
                        active.append(user_ob)
                    else:
                        pending.append(user_ob)
        return pending, active

    #sign-up interfaces
    security.declareProtected(view, 'signupUser')
    def signupUser(self, username, password, confirm, name, email, institution, abbrev, ms_eu, ms_other, qualification, REQUEST=None, RESPONSE=None):
        """ process the request for a new account """
        if REQUEST is not None:

            session = REQUEST.SESSION
            ms = ms_eu or ms_other

            if self.use_captcha:
                #check if captcha is valid
                check_captcha = captcha.submit(REQUEST.get('recaptcha_challenge_field', ''),
                                               REQUEST.get('recaptcha_response_field', ''),
                                               getattr(self, 'private_key'),
                                               REQUEST.get('REMOTE_ADDR', '')
                                               )
                if check_captcha.is_valid is False:
                    #Captcha is wrong show a error .
                    session.set('err_captcha', 'Incorrect. Try again')

            #validate form fields
            if not username:
                session.set('err_username', 'Please enter a username')
            else:
                #check username
                username_expr = re.compile('^[a-z0-9]*$')
                if not re.match(username_expr, username):
                    session.set('err_username', 'Only lowercase letters and numbers allowed')

            if self.acl_users.getUser(username):
                session.set('err_username', 'Sorry, that username already exists!')

            if not password or not confirm:
                session.set('err_password', 'Password and confirmation must be specified')
            if (password or confirm) and (password != confirm):
                session.set('err_password', 'Passwords must match!')

            email_expr = re.compile('^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}$', re.IGNORECASE)
            if not re.match(email_expr, email):
                session.set('err_email', 'Please enter a correct email address')

            if not ms:
                session.set('err_ms', 'Please enter a Member State')
            if not institution:
                session.set('err_institution', 'Please enter the Institution')
            if not name:
                session.set('err_name', 'Please enter your name')

            if not session.keys():
                #create account
                self.create_account(username, password, confirm)
                self.create_account_details(username, name, email, institution, abbrev, ms, qualification)
                #send an email with the activation link
                self.send_confirmation(username, name, email)
                session.set('op_completed', True)
            else:
                #put form field values on session
                session.set('username', username)
                session.set('password', password)
                session.set('confirm', confirm)
                session.set('name', name)
                session.set('email', email)
                session.set('institution', institution)
                session.set('abbrev', abbrev)
                session.set('ms_eu', ms_eu)
                session.set('ms_other', ms_other)
                session.set('qualification', qualification)

            return RESPONSE.redirect(REQUEST.HTTP_REFERER)
        else:
            raise NotImplemented

    security.declareProtected(view, 'signupLDAPUser')
    def signupLDAPUser(self, username, password, ms_eu, ms_other, institution, abbrev, REQUEST=None, RESPONSE=None):
        """ process the request for a new account """
        if REQUEST is not None:
            session = REQUEST.SESSION
            ms = ms_eu or ms_other

            if self.use_captcha:
                #check if captcha is valid
                check_captcha = captcha.submit(REQUEST.get('recaptcha_challenge_field', ''),
                                               REQUEST.get('recaptcha_response_field', ''),
                                               getattr(self, 'private_key'),
                                               REQUEST.get('REMOTE_ADDR', '')
                                               )
                if check_captcha.is_valid is False:
                    #Captcha is wrong show a error .
                    session.set('err_captcha', 'Incorrect. Try again')

            #validate form fields
            if not username:
                session.set('err_username', 'Please enter a username')
            if not ms:
                session.set('err_ms', 'Please enter a Member State')
            if not institution:
                session.set('err_institution', 'Please enter the Institution')

            local_users = self.acl_users.getLocalUsers()
            user_ob = self.acl_users.getUser(username)
            if user_ob:
                if [user for user in local_users if user[0] == user_ob.getUserDN()]:
                    session.set('err_username', 'Sorry, that username already exists!')

            if not password:
                session.set('err_password', 'The password field is empty')


            if username and password:
                #try to login with the LDAP account
                user = self.login_ldap(username, password)
                if user is None:
                    session.set('err_login', 'Username and password do not match')
                else:
                    if not session.keys():
                        self.map_ldap_account(username)
                        self.create_account_details(username, '', '', institution, abbrev, ms, '')
                        #send notification email to the administrators
                        self.send_ldap_notification(username)
                        session.set('op_completed', True)
                    else:
                        #put form field values on session
                        session.set('username', username)
                        session.set('ms_eu', ms_eu)
                        session.set('ms_other', ms_other)
                        session.set('institution', institution)
                        session.set('abbrev', abbrev)

            return RESPONSE.redirect(REQUEST.HTTP_REFERER)
        else:
            raise NotImplemented

    #notification
    security.declarePublic('suggest_removal')
    def suggest_removal(self, username, picture_link, reason):
        """ suggest picture removal """
        mailhost = self._getOb('MailHost', None)
        if mailhost:
            key = utils.email_encode(username)
            values = {'website': self.aq_parent.title,
                      'username': username,
                      'picture_link': picture_link,
                      'reason': reason
                     }
            template = self._getOb('picture_removal', None)
            if template:
                mailhost.simple_send(mto=self.support_email, mfrom=self.register_email, subject='[Article 17] - suggest removal', body=template.document_src() % values)

    security.declarePrivate('send_confirmation')
    def send_confirmation(self, username, name, email):
        """ send an email with the activation link """
        mailhost = self._getOb('MailHost', None)
        if mailhost:
            key = utils.email_encode(username)
            values = {'website': self.aq_parent.title,
                      'name': name,
                      'support-email': self.support_email,
                      'activation-link': '%s/confirmAccount?key=%s' % (self.absolute_url(), key)
                     }
            template = self._getOb('signup-user', None)
            if template:
                mailhost.simple_send(mto=email, mfrom=self.register_email, subject='%s - account activation' % self.aq_parent.title, body=template.document_src() % values)

    security.declarePrivate('send_notification')
    def send_notification(self, username, name):
        """ send an email to the administrator when a new user is registered in the system """
        mailhost = self._getOb('MailHost', None)
        if mailhost:
            values = {'website': self.aq_parent.title,
                      'name': name,
                      'username': username,
                      'users_link': '%s/user_details_html?user=%s' % (self.absolute_url(), username),
                     }
            template = self._getOb('signup-admin', None)
            if template:
                mailhost.simple_send(mto=self.support_email, mfrom=self.register_email, subject='%s - account activation' % self.aq_parent.title, body=template.document_src() % values)

    security.declarePrivate('send_ldap_notification')
    def send_ldap_notification(self, username):
        """ send an email to the administrator when a new LDAP user is registered in the system """
        mailhost = self._getOb('MailHost', None)
        if mailhost:
            values = {'website': self.aq_parent.title,
                      'username': username,
                      'users_link': '%s/ldap_user_details_html?user=%s' % (self.absolute_url(), username),
                     }
            template = self._getOb('signup-ldap-admin', None)
            if template:
                mailhost.simple_send(mto=self.support_email, mfrom=self.register_email, subject='%s - account activation' % self.aq_parent.title, body=template.document_src() % values)

    security.declarePrivate('send_ldap_user_notification')
    def send_ldap_user_notification(self, username, name, email, roles):
        """ send an email to the LDAP user when the administrator creates an account for him in the system """
        mailhost = self._getOb('MailHost', None)
        user_roles = []
        for role in roles:
            if role == 'NAT':
                user_roles.append('Article 17 National Data Coordinator')
            else:
                user_roles.append(role)
        if mailhost:
            values = {'website': self.aq_parent.title,
                      'link': self.aq_parent.absolute_url(),
                      'username': username,
                      'roles': ','.join(user_roles),
                     }
            template = self._getOb('signin-ldap-user', None)
            if template:
                mailhost.simple_send(mto=email, mfrom=self.register_email, subject='%s - account created' % self.aq_parent.title, body=template.document_src() % values)

    #notification
    security.declarePrivate('forgot_password')
    def forgot_password(self, username, email, password):
        """ send an email with the activation link """
        mailhost = self._getOb('MailHost', None)
        if mailhost:
            key = utils.email_encode(username)
            values = {'username': username,
                      'password': password,
                      'support-email': self.support_email,
                      'login-link': '%s/loggedin' % self.aq_parent.absolute_url()
                     }
            template = self._getOb('forgot-password', None)
            if template:
                mailhost.simple_send(mto=email, mfrom=self.register_email, subject='%s - Your new password' % self.aq_parent.title, body=template.document_src() % values)

    #captcha
    security.declareProtected(view, 'showCaptcha')
    def showCaptcha(self):
        """ """
        return captcha.displayhtml(getattr(self, 'public_key'))

    def getDeadline(self):
        """ """
        return utils.convert_date_to_string(self.deadline)

    def pastDeadline(self):
        """ """
        return self.deadline.isPast()

    def isList(self, l):
        return isinstance(l, list)

    security.declareProtected(manage_users, 'editProperties')
    def editProperties(self, deadline, public_key, private_key, support_email, register_email, use_captcha=False, REQUEST=None, RESPONSE=None):
        """ edit properties """

        if REQUEST is not None:
            session = REQUEST.SESSION
            if use_captcha: use_captcha = True
            self.deadline = utils.convert_string_to_date(deadline)
            self.public_key = public_key
            self.private_key = private_key
            self.support_email = support_email
            self.register_email = register_email
            self.use_captcha = use_captcha
            session.set('op_completed', True)
            return RESPONSE.redirect(REQUEST.HTTP_REFERER)
        else:
            raise NotImplemented

    security.declareProtected(view, 'signup_html')
    signup_html = PageTemplateFile('zpt/signup', globals())

    security.declareProtected(view, 'ldap_html')
    ldap_html = PageTemplateFile('zpt/ldap_signup', globals())

    security.declareProtected(manage_users, 'users_html')
    users_html = PageTemplateFile('zpt/manage_users', globals())

    security.declareProtected(manage_users, 'add_ldap_user_html')
    add_ldap_user_html = PageTemplateFile('zpt/add_ldap_user', globals())

    security.declareProtected(manage_users, 'ldap_users_html')
    ldap_users_html = PageTemplateFile('zpt/manage_ldap_users', globals())

    security.declareProtected(manage_users, 'user_details_html')
    user_details_html = PageTemplateFile('zpt/manage_user_details', globals())

    security.declareProtected(manage_users, 'ldap_user_details_html')
    ldap_user_details_html = PageTemplateFile('zpt/manage_ldap_user_details', globals())

    security.declareProtected(view, 'confirmation_html')
    confirmation_html = PageTemplateFile('zpt/signup_confirmation', globals())

    security.declareProtected(manage_users, 'properties_html')
    properties_html = PageTemplateFile('zpt/properties', globals())

    security.declareProtected(view_management_screens, 'update26012008')
    def update26012008(self):
        """ update procedure """
        self.support_email = ''
        self.register_email = ''

    security.declareProtected(view_management_screens, 'update25072008')
    def update25072008(self):
        """ update procedure """
        self.use_captcha = True

    security.declarePublic('add_user')
    def add_user(self):
        """ create user in zope's acl_users """
        if not verify_api_key(self.REQUEST):
            return invalid_key_response(self.REQUEST.RESPONSE)
        return 'ok'


InitializeClass(ACLManager)

def verify_api_key(REQUEST):
    key = os.environ.get('ACL_MANAGER_API_KEY')
    if not key:
        logger.warn("No ACL_MANAGER_API_KEY is set")
        return False
    request_key = REQUEST.form.get('api_key')
    return bool(request_key == key)


def invalid_key_response(RESPONSE):
    RESPONSE.setStatus(403)
    return "Api key is not valid"
