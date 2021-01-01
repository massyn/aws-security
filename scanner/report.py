import json

class report:
    def __init__(self,p,r):
        self.data = p
        self.cache = r

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

    def generate(self,file):
        with open(file,'wt') as f:
            f.write('''<!DOCTYPE html>
                <html>
                <head>
                <title>AWS Security Info - Vulnerability Report</title>
<style>
body {
  background-color	: #E7E6E6;
  font-family		: Arial, Helvetica, sans-serif;
}

h1 {
	color: #FFFFFF;
	background-color: #485CC7;
	padding: 20px 20px 20px 20px;
	border-width:1px;  
	border-style:solid;
}

h3 {
    color: #485CC7;
    background-color: #89CFF0;
    border-style: solid solid solid solid;
    border-width: 1px;
    padding: 2px 2px 2px 2px;

}
th {
  background-color: #485CC7;
  color: white;
}
th, td {
  padding: 10px;
  text-align: left;
}
.evidence {
  border: 1px solid gray;
  background-color: #c0c0c0;
  
}

table, th, td {
  border: 1px solid gray;
}
table {
  border-collapse: collapse;
}
</style>

</head>

                    <h1>AWS Security Info</h1>
<h2>Executive Summary</h2>
<p>The following report has been automatically generated.
</p>
<p>
<ul>''')
            f.write('<li>AWS Account : <b>{account}</b></li>'.format(account = self.cache['sts']['get_caller_identity']['Account']))
            f.write('<li>Date of scan : <b>{date}</b></li></ul></p>'.format(date = self.cache['sts']['get_caller_identity']['ResponseMetadata']['HTTPHeaders']['date']))

            globalerr = 0
            globalok = 0
            for policy in self.data:
                globalerr += len(self.data[policy][0])
                globalok += len(self.data[policy][1])
                globaltotal = globalok + globalerr
                globalpct = globalok / (globalok + globalerr) * 100

            f.write('<li>Total of <b>{globalok}</b> out of <b>{globaltotal}</b> resources do not have any known vulnerabilities.</li>'.format(globalok = globalok, globaltotal = globaltotal))
            f.write(self.htmlbar(globalpct))
            # -- table
            f.write('<h2>Summary</h2>')
            f.write('<table border=1>')
            for policy in self.data:
                totalerr = len(self.data[policy][0])
                totalok = len(self.data[policy][1])
                pct = totalok / (totalok + totalerr) * 100

                f.write('<tr><td><a href="#{policy}">{policy}</a></td><td>{pct}</td></tr>'.format(policy = policy,
                    totalerr = totalerr,
                    totalok = totalok,
                    pct = self.htmlbar(pct)
                ))
            f.write('</table>')

            f.write('<h2>Detail</h2>')
            for policy in self.data:
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
                                
                f.write('''
                    <h3 id="{policy}">{policy}</h3>
                    <p>{htmlbar}</p>
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
                    
                    '''.format(
                            policy = policy,
                            pct     = pct,
                            non     = json.dumps(non,indent=4),
                            description = self.data[policy]['description'],
                            remediation = self.data[policy]['remediation'],
                            vulnerability = self.data[policy]['vulnerability'],
                            htmlbar = self.htmlbar(pct),
                            links = self.data[policy]['links'],
                            references = self.data[policy]['references']
                            
                    ))
