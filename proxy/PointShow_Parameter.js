// reference : https://github.com/zaproxy/zaproxy/blob/eca1849117cd865f52cdce8f56c833dc2f3592de/src/org/parosproxy/paros/network/HttpMessage.java
function proxyRequest(msg) { return true; }

function proxyResponse(msg) {
	var contentType = msg.getResponseHeader().getHeader("Content-Type");
	var paramUrl    = msg.getUrlParams();
	var paramForm   = msg.getFormParams();
	var paramCookie = msg.getCookieParamsAsString();

	if ((contentType == null && contentType != "text/html") || (paramUrl.isEmpty() == true && paramForm.isEmpty() == true))
		return true;

	var proxyInfoMessage = "<script>var RealstudySecurityWindow=window.open('','RealstudySecurityWindow','scrollbars=yes,resizable=yes,top=500,left=500,width=400,height=400');"
						 + "RealstudySecurityWindow.document.body.innerHTML = '';";
	var parameterMessage = "", iter, item;

	parameterMessage += "RealstudySecurityWindow.document.write('";
	parameterMessage += "PARAM_URL [";
	iter = paramUrl.iterator();
	while (iter.hasNext()) {
		item = iter.next();
		parameterMessage += item.getName() + ":" + item.getValue() + ", ";
	}
	parameterMessage += "]<br>PARAM_FORM [";
	iter = paramForm.iterator();
	while (iter.hasNext()) {
		item = iter.next();
		parameterMessage += item.getName() + ":" + item.getValue() + ", ";
	}
	parameterMessage += "]<br>COOKIE [" + paramCookie + "]<br>"

	parameterMessage += "');</script>"
	proxyInfoMessage += parameterMessage + msg.getResponseBody();
	msg.setResponseBody(proxyInfoMessage);

	return true
}
