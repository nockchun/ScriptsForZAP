function proxyRequest(msg) { return true; }

function proxyResponse(msg) {
	var contentType = msg.getResponseHeader().getHeader("Content-Type");
	if ((contentType == null && contentType != "text/html"))
		return true;

	var body = msg.getResponseBody().toString();
	regInput = /(<\s*input.*type=(?:'|")?)hidden/gi;

	if (regInput.test(body)) {
		body = body.replace(regInput, "$1text");

		msg.setResponseBody(body);
		msg.getResponseHeader().setHeader('Content-Length', getByteLength(body))
	}

	return true
}

function getByteLength(s,b,i,c){
    for(b=i=0;c=s.charCodeAt(i++);b+=c>>11?3:c>>7?2:1);
    return b;
}