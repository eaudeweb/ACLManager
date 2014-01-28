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

import base64
from DateTime import DateTime

def convertToList(s):
    """Convert to list"""
    if isinstance(s, tuple):
        s = list(s)
    elif not isinstance(s, list):
        s = [s]
    return s

def email_encode(s):
    """ Encodes a string to an ASCII string.
        To be used in the user interface, to avoid problems with the encodings, HTML entities, etc..
    """
    if s:
        if isinstance(s, unicode):
            s = s.encode('utf8')
        return base64.encodestring(s)#base64.urlsafe_b64encode(s)
    else:
        return s

def email_decode(s):
    """ Decodes a string from an ASCII string.
        To be used in the user interface, to avoid problems with the encodings, HTML entities, etc..
    """
    return base64.decodestring(s)#base64.urlsafe_b64decode(s)

def convert_string_to_date(strdate, sep='/'):
    """Takes a string that represents a date like 'dd/mm/yyyy' and returns a DateTime object"""
    try:
        parts = strdate.split(sep)
        year = int(parts[2], 10)
        month = int(parts[1], 10)
        day = int(parts[0], 10)
        if month<1 or month>12: return None
        return DateTime('%s/%s/%s 00:00:00' % (str(year), str(month), str(day)))
    except:
        return None

def convert_date_to_string(date, sep='/'):
    """Takes a string that represents a date like 'dd/mm/yyyy' and returns a DateTime object"""
    if date:
        year = str(date.year())
        month = str(date.month())
        day = str(date.day())
        if len(month)==1:
            month = '0' + month
        if len(day)==1:
            day = '0' + day
        return '%s/%s/%s' % (day, month, year)
    else:
        return ''