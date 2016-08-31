function proxyRequest(msg) { return true; }

function proxyResponse(msg) {
	var contentType   = msg.getResponseHeader().getHeader("Content-Type");
	var paramUrl      = msg.getUrlParams();
	var paramForm     = msg.getFormParams();
	var paramCookie   = msg.getCookieParamsAsString();
	var contentLength = msg.getResponseHeader().getHeader('Content-Length');

	if ((contentType == null && contentType != "text/html") || (paramUrl.isEmpty() == true && paramForm.isEmpty() == true))
		return true;

	var proxyInfoMessage = "<script>var RealstudySecurityWindow=window.open('','RealstudySecurityWindow','scrollbars=yes,resizable=yes,top=500,left=500,width=900,height=200');"
						 + "RealstudySecurityWindow.document.body.innerHTML = '';";
	var iter, item;

	proxyInfoMessage += "RealstudySecurityWindow.document.write('";
	proxyInfoMessage += "PARAM_URL [";
	iter = paramUrl.iterator();
	while (iter.hasNext()) {
		item = iter.next();
		proxyInfoMessage += item.getName() + ":" + item.getValue() + ", ";
	}
	proxyInfoMessage += "]<br>PARAM_FORM [";
	iter = paramForm.iterator();
	while (iter.hasNext()) {
		item = iter.next();
		proxyInfoMessage += item.getName() + ":" + item.getValue() + ", ";
	}
	proxyInfoMessage += "]<br><br>COOKIE [" + paramCookie + "]<br>"
	proxyInfoMessage += "');</script>"

	msg.setResponseBody(proxyInfoMessage + msg.getResponseBody());
	msg.getResponseHeader().setHeader('Content-Length', getByteLength(proxyInfoMessage) + parseInt(contentLength));

	return true
}

function getByteLength(s,b,i,c){
    for(b=i=0;c=s.charCodeAt(i++);b+=c>>11?3:c>>7?2:1);
    return b;
}
