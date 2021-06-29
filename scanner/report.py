import json

class report:
    def __init__(self,p,r,showall = False):
        self.data = p
        self.cache = r
        self.showall = showall

    def htmlbar(self,pct):
        if pct < 80:
          col = '#C00000'
        elif pct < 100:
          col = '#ED7D31'
        else:
          col = '#00B050'
          
        maxwidth = 200
        barwidth = pct / 100 * maxwidth
        whitewidth = maxwidth - barwidth
        
        return '<table border=0><tr><td width=60px>' + str(round(pct,2)) + '%</td><td width=' + str(int(barwidth)) + ' bgcolor='+col + '>&nbsp;</td><td width=' + str(int(whitewidth)) + '>&nbsp;</td></tr></table>'

    def generate(self):
          
      globalerr = 0
      globalok = 0
      for policy in self.data:
          globalerr += len(self.data[policy][0])
          globalok += len(self.data[policy][1])
          globaltotal = globalok + globalerr
          globalpct = globalok / (globalok + globalerr) * 100          
        
      content = '''<!DOCTYPE html>
                <html>
                <head>
                <title>AWS Security Info - Vulnerability Report</title>
<style>
body {{
  background-color	: #E7E6E6;
  font-family		: Arial, Helvetica, sans-serif;
}}

h1 {{
	color: #FFFFFF;
	background-color: #485CC7;
	padding: 20px 20px 20px 20px;
	border-width:1px;  
	border-style:solid;
}}

h3 {{
    color: #485CC7;
    background-color: #89CFF0;
    border-style: solid solid solid solid;
    border-width: 1px;
    padding: 2px 2px 2px 2px;

}}
th {{
  background-color: #485CC7;
  color: white;
}}
th, td {{
  padding: 3px;
  text-align: left;
}}
.evidence {{
  border: 1px solid gray;
  background-color: #c0c0c0;
  
}}

table, th, td {{
  border: 1px solid gray;
}}
table {{
  border-collapse: collapse;
}}
</style>

</head>

                    <h1>AWS Security Configuration Misconfiguration Report</h1>
<h2>Overview</h2>
<p>Date : <b>{date}</b></p>
<p><a href="http://www.awssecurity.info">AWS Security Info</a> performed a configuration misconfiguration assessment on {date} encompassing the scope described below:</p>
<p>
<table width=300px style="text-align:center;">
<tr><th style="text-align:center;">AWS Account</th></tr>
<tr><td style="text-align:center;">{account}</td></tr>
</table>
</p>
<p>
This document is classified as <b>strictly private and confidential</b>.
</p>
<h3>Executive Summary</h3>
<p>Total of <b>{globalok}</b> out of <b>{globaltotal}</b> resources do not have any known configuration issues.</p>
{globalpcthtmlbar}
<p><i>DISCLAIMER : The reported percentage reported is purely arbitrary and should only be used as an indicator.  It should be noted that even solutions with scores above 90% can still be comprormised.</i></p>

'''.format(
      date = self.cache['sts']['get_caller_identity']['us-east-1']['ResponseMetadata']['HTTPHeaders']['date'],
      account = self.cache['sts']['get_caller_identity']['us-east-1']['Account'],
      globalok = globalok,
      globaltotal = globaltotal,
      globalpcthtmlbar = self.htmlbar(globalpct)

      )

      w = 100
      severities = {
        'critical' : {
          'html' : '<td width={w} bgcolor=#000000 style="text-align: center; vertical-align: middle;"><font color=#FFFFFF>CRITICAL</font></td>'.format(w=w),
          'count' : 0
        },
        'high' : {
          'html' : '<td width={w} bgcolor=#C00000 style="text-align: center; vertical-align: middle;"><font color=#FFFFFF>HIGH</font></td>'.format(w=w),
          'count' : 0
        },
        'medium' : {
          'html' : '<td width={w} bgcolor=#CCCC00 style="text-align: center; vertical-align: middle;"><font color=#000000>MEDIUM</font></td>'.format(w=w),
          'count' : 0
        },
        'low' : {
          'html' : '<td width={w} bgcolor=#0066CC style="text-align: center; vertical-align: middle;"><font color=#FFFFFF>LOW</font></td>'.format(w=w),
          'count' : 0
        },
        'info' : {
          'html'  : '<td width={w} bgcolor=#00CCFF style="text-align: center; vertical-align: middle;"><font color=#000000>INFO</font></td>'.format(w=w),
          'count' : 0
        }
      }

      content = content + '<h3>Criticality count</h3>'
      content = content + '<table>'

      for s in severities:
            for policy in self.data:
                  if self.data[policy]['severity'] == s:
                    severities[s]['count'] += len(self.data[policy][0])
                    
      for s in severities:                    
        content = content + '<tr>' + severities[s]['html'] + '<td>' + str(severities[s]['count']) + '</td><td>' + self.htmlbar(severities[s]['count'] / globalerr * 100) + '</td></tr>'
            
      content = content + '<table>'

      content = content + '''
      <h2>Disclaimer</h2>
<p>The AWS cloud vulnerability test that existed as of <b>{date}</b>. Information security threats are continually changing, with new vulnerabilities discovered on a daily basis, and no solution or cloud account can ever be 100% secure no matter how much security testing is conducted. 
This report is intended only to provide documentation on potential issues that may exist in AWS account <b>{account}</b>.  It is still the account owner's responsibility to perform any triage and remediation actions based on the recommendations in this report.</p>
<p>This report cannot and does not protect against personal or business loss as the result of use of the applications or systems described. AWS Security Info offers no warranties, representations or legal certifications concerning the applications or systems it tests. All software includes defects: nothing in this document is intended to represent or warrant that security testing was complete and without error, nor does this document represent or warrant that the application tested is suitable to task, free of other defects than reported, fully compliant with any industry standards, or fully compatible with any operating system, hardware, or other application. By using this information you agree that AWS Security Info shall be held harmless in any event.
</p>
<h2>About the tool</h2>
<p>
AWS Security Info is provided free of charge under an open source model.  The only condition for use is your contribution to report bugs, feature requests, and source code.
<li><a href="https://github.com/massyn/aws-security/">Github</a> repository</li>
<li><a href="https://github.com/massyn/aws-security/issues">Report</a> an issue or feature request</li>
<li>Author : <a href="https://twitter.com/massyn">Phil Massyn</a></li>
</p>
    '''.format(
      date = self.cache['sts']['get_caller_identity']['us-east-1']['ResponseMetadata']['HTTPHeaders']['date'],
      account = self.cache['sts']['get_caller_identity']['us-east-1']['Account'])

      # -- table
      content = content + '<h2 id="top">Summary</h2>'
      content = content + '<table border=1>'
      for severity in severities:
        for policy in self.data:
          if self.data[policy]['severity'] == severity:
            totalerr = len(self.data[policy][0])
            totalok = len(self.data[policy][1])
            pct = totalok / (totalok + totalerr) * 100

            if pct != 100 or self.showall == True:
              content = content + '<tr>{sev}<td><a href="#{policy}">{policy}</a></td><td>{totalok} / {total}</td><td>{pct}</td></tr>'.format(policy = policy,
                  totalerr = totalerr,
                  totalok = totalok,
                  total = totalok + totalerr,
                  pct = self.htmlbar(pct),
                  sev = severities[self.data[policy]['severity']]['html']
              )
      content = content + '</table>'

      content = content + '<h2>Detail</h2>'
      for severity in severities:
        #content = content + '<table border=1><tr>' + severities[severity]['html'] + '</tr></table>'

        for policy in self.data:
              if self.data[policy]['severity'] == severity:
                totalerr = len(self.data[policy][0])
                totalok = len(self.data[policy][1])

                pct = totalok / (totalok + totalerr) * 100

                if self.data[policy]['description'] == '':
                  print (policy + ' - WARNING - no description')
                if self.data[policy]['remediation'] == '':
                  print (policy + ' - WARNING - no remediation')
                if self.data[policy]['vulnerability'] == '':
                  print (policy + ' - WARNING - no vulnerability')
                if self.data[policy]['references'] == []:
                  print (policy + ' - WARNING - no references')
                if self.data[policy]['links'] == []:
                  print (policy + ' - WARNING - no links')

                non = self.data[policy][0]

                if pct != 100 or self.showall == True:
                  content = content + '''
                     
                      <table border=0><tr>{severityhtml}<td><h3 id="{policy}">{policy}</h3><p>{htmlbar}</p></td></tr></table>
                      
                      <h4>Description</h4>
                      <p>{description}</p>
                      <h4>Vulnerability</h4>
                      <p>{vulnerability}</p>
                      <h4>Remediation</h4>
                      <p>{remediation}</p>
                      <h4>Vulnerable resources</h4>
                      <p><div class="evidence"><pre>{non}</pre></div></p>
                      <h4>Links</h4>
                      <p>{links}</p>
                      <h4>References</h4>
                      <p>{references}</p>
                      <p><a href="#top">Top</a></p>
                      <hr>
                      '''.format(
                              policy = policy,
                              pct     = pct,
                              non     = json.dumps(non,indent=4),
                              description = self.data[policy]['description'],
                              remediation = self.data[policy]['remediation'],
                              vulnerability = self.data[policy]['vulnerability'],
                              htmlbar = self.htmlbar(pct),
                              links = self.data[policy]['links'],
                              references = self.data[policy]['references'],
                              severity = self.data[policy]['severity'],
                              severityhtml = severities[self.data[policy]['severity']]['html']
                              
                      )

      return content
