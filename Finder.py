from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IScanIssue
import re

matches = [
	r'<\w+>.*?<\/\w+>',
	r'<.* \w+=.*\/>',
]
scanned = []

class CustomIssue(IScanIssue):
    def __init__(self, BasePair, Confidence='Certain', IssueBackground=None, IssueDetail=None, IssueName='Python Scripter generated issue', RemediationBackground=None, RemediationDetail=None, Severity='High'):
        self.HttpMessages=[BasePair]
        self.HttpService=BasePair.getHttpService()
        self.Url=BasePair.getUrl() 
        self.Confidence = Confidence
        self.IssueBackground = IssueBackground 
        self.IssueDetail = IssueDetail
        self.IssueName = IssueName
        self.IssueType = 134217728 
        self.RemediationBackground = RemediationBackground 
        self.RemediationDetail = RemediationDetail 
        self.Severity = Severity 

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService

    def getUrl(self):
        return self.Url

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return self.IssueBackground

    def getIssueDetail(self):
        return self.IssueDetail

    def getIssueName(self):
        return self.IssueName

    def getIssueType(self):
        return self.IssueType

    def getRemediationBackground(self):
        return self.RemediationBackground

    def getRemediationDetail(self):
        return self.RemediationDetail

    def getSeverity(self):
        return self.Severity

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
	
        self.callbacks = callbacks
        self.callbacks.setExtensionName("BIT/XML-Finder")
        self.callbacks.registerHttpListener(self)

        sys.stdout = self.callbacks.getStdout()
        self.helpers = self.callbacks.getHelpers()

        print "[BIT/XML-Finder] by BitTheByte"
        print "[GITHUB] https://github.com/BitTheByte"
        return


    def processHttpMessage(self, toolflag, messageIsRequest, messageInfo):
    	if messageIsRequest: return

        request = messageInfo.getRequest()
        requestInfo = self.helpers.analyzeRequest(messageInfo)
        url = requestInfo.getUrl()

        if not self.callbacks.isInScope(url): return

        body = request[requestInfo.getBodyOffset():]
        path = requestInfo.url.getPath()
        host = requestInfo.url.getHost()

    	if host+path in scanned:return
    	scanned.append(host+path)

        for regex in matches:
        	if re.search(regex, body.tostring()):
		        issue = CustomIssue(
		            BasePair=messageInfo,
		            IssueName='XML based request',
		            IssueDetail='The following host is using xml at the request body<br>Check for XML injection',
		            Severity='High',
		            Confidence='Certain'
		        )
		        self.callbacks.addScanIssue(issue)
        return
    
