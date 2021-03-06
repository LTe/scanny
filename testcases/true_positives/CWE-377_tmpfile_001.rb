# 2011/09/12: cockpit/lib/chumby-stats/stats.rb
# Copyright © 2009 Novell, Inc.  All Rights Reserved.
#
# THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
# IT MAY NOT BE USED, COPIED, DISTRIBUTED, DISCLOSED, ADAPTED, PERFORMED,
# DISPLAYED, COLLECTED, COMPILED, OR LINKED WITHOUT NOVELL'S PRIOR WRITTEN
# CONSENT.  USE OR EXPLOITATION OF THIS WORK WITHOUT AUTHORIZATION COULD SUBJECT
# THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
#
# NOVELL PROVIDES THE WORK "AS IS," WITHOUT ANY EXPRESS OR IMPLIED WARRANTY,
# INCLUDING WITHOUT THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE, AND NON-INFRINGEMENT. NOVELL, THE AUTHORS OF THE WORK, AND
# THE OWNERS OF COPYRIGHT IN THE WORK ARE NOT LIABLE FOR ANY CLAIM, DAMAGES, OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING
# FROM, OUT OF, OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE
# WORK.

#!/usr/bin/env ruby

require 'optparse'
require 'ostruct'
require "rexml/document"
include REXML

INKSCAPE = '/usr/bin/inkscape'
RSVG = '/usr/bin/rsvg'
TEMPFILE = '/tmp/stats.svg' # TESTCASE: CWE-377
ERRBG = ['stop-color:black;stop-opacity:1','stop-color:red;stop-opacity:1']
WARNBG = ['stop-color:black;stop-opacity:1','stop-color:orange;stop-opacity:1']



tmp_f = File.new(TEMPFILE,'w+') # XXX tom: local (ab-)users like insecure tmp files. maybe not an issue in this case?
tmp_f.puts template
tmp_f.close

