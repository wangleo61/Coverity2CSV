
# Coverity2CSV

Export the Coverity defect as CVS file

1. Vulnerable line number
2. Owasp top ten 2017 information(A1-A10)
3. CVSS Score
4. CVSS Severity 
5. Defect remediation guidance


#
Python 2.7 install

#CWE & OWASP Top 10
We will going you mentioned map the base value of a CWE (merged defect attribute) to a separate private Python dictionary of terms for whichever OWASP standard you are interested in.
The relationship between CWE and OWASP Top 10
https://cwe.mitre.org/data/definitions/1026.html

OWASP Top Introduction
https://owasp.org/www-pdf-archive/OWASP_Top_10-2017_%28en%29.pdf.pdf

#Add the resource file (CWE_ Owasp_ Map.json ）Read the mapping relationship between CWE and OWASP,

In addition, the content of the mapping relationship websit http://cwe.mitre.org/data/definitions/1026.html

#CVSS Related new feature 2020-10-15
Add new fields in Coverity Connect for CSV erport
CVSS_Audited
CVSS_Score
CVSS_Severity
CVSS_Vector


#Execute the command before export CVS, this will be generating the value for this fields
"C:\Program Files\Coverity\Coverity Reports\bin\cov-generate-cvss-report.exe"    C:\Users\leo\Desktop\Leo\xxx.yaml --password console --profile C:\Program Files\Coverity\Coverity Reports\config\Master_CWE_CVSS_Base_Score_Profile_V1.json --score 



