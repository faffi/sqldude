from burp import IBurpExtender
from burp import IParameter
#from burp import IMenuItemHandler
from burp import IContextMenuFactory
from burp import IExtensionHelpers
from burp import IRequestInfo
from javax.swing import JMenuItem
from java.awt.datatransfer import Clipboard,StringSelection
from java.awt import Toolkit
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyEvent
class BurpExtender(IBurpExtender, IContextMenuFactory, ActionListener):


	def __init__(self):
		self.menuItem = JMenuItem('sqldude')
		self.menuItem.addActionListener(self)
					
	def _build(self):
		#Grab first selected message, bail if none
		iRequestInfo = self._helpers.analyzeRequest(self.ctxMenuInvocation.getSelectedMessages()[0])
		if iRequestInfo is None:
			print('Request info object is null, bailing')
			return 

		#print(len(iRequestInfo.getParameters()))
		#for i in iRequestInfo.getParameters():
		#		print(i.getName())
		#print('cookies: ' + ''.join(cookies))
		#parms = [i for i in iRequestInfo.getParameters() if i.getType() == IParameter.PARAM_BODY]
		parms = filter(lambda x: x.getType() == IParameter.PARAM_BODY, iRequestInfo.getParameters())
		cookies = filter(lambda x: x.getType() == IParameter.PARAM_COOKIE, iRequestInfo.getParameters())
		#print('parms ' + ''.join(parms))
		payload = 'sqlmap -u \'%s\' --cookies=\'%s\'' % (iRequestInfo.getUrl(), ';'.join([('%s=%s' % (c.getName(),c.getValue())) for c in cookies ]) ) 
		if len(parms) > 0:
				p = ['%s=%s' % (p.getName(), p.getValue()) for p in parms]
				payload = '%s --data=\'%s\'' % (payload, '&'.join(p))
		#print('Found Cookies:\n\t' + '\n\t'.join([('%s=%s' % (c.getName(), c.getValue())) for c in cookies]))
		s = StringSelection(payload)                                                                                                                                                                                                        
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(s,s) #put string on clipboard            
		print(payload)

	def actionPerformed(self, actionEvent):
		self._build()

	def registerExtenderCallbacks(self, callbacks):
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName('sqldude')
		callbacks.registerContextMenuFactory(self)
		self.mCallBacks = callbacks
		print('sqldude up')
		return
	
	def createMenuItems(self, ctxMenuInvocation):
		self.ctxMenuInvocation = ctxMenuInvocation
		return [self.menuItem]


