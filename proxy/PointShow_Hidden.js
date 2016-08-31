// This script show up a hidden fields.
// If you have another hidden type. then you can add rules.

var rules = [
	[/(<\s*input.*type=(?:'|")?)hidden/gi, "$1text"]
];

function proxyResponse(msg) {
	// check content type.
	var contentType  = msg.getResponseHeader().getHeader("Content-Type");
	var statusCode   = msg.getResponseHeader().getStatusCode();
	var targetTypes  = [/text\/html/i];
	var isTargetType = false;

	if (statusCode != 200) return true;
	for (var i=0; i < targetTypes.length; i++) {
		if(targetTypes[i].test(contentType)) {
			isTargetType = true;
			break;
		}
	}
	if (!isTargetType) return true;

	// modify hidden fields.
	var body = msg.getResponseBody().toString();

	for (var i=0; i < rules.length; i++) {
		if (rules[i][0].test(body)) {
			body = body.replace(rules[i][0], rules[i][1]);
		}
	}
	msg.setResponseBody(body);
	msg.getResponseHeader().setHeader('Content-Length', getByteLength(body))

	return true
}

function proxyRequest(msg) { return true; }
function getByteLength(s,b,i,c){
    for(b=i=0;c=s.charCodeAt(i++);b+=c>>11?3:c>>7?2:1);
    return b;
}