// This script shows security information.

var window = [100, 700, 800, 300]; // window[x, y, width, height]
var rules = [
	/(.{0,40})(admin|adm|manager|mgr|pass|password|user|account)(.{0,40})/gi,	//insecure
	/(.{0,40})(exception|sql|configuration|config|dump)(.{0,40})/gi,			//error
	/(.{0,40})(\?(?:\.\.\/)*.*\.\w{3,4})(.{0,40})/gi							// download
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

	// generate a security information
	var body          = msg.getResponseBody().toString();	
	var paramUrl      = msg.getUrlParams();
	var paramForm     = msg.getFormParams();
	var paramCookie   = msg.getCookieParamsAsString();
	var contentLength = msg.getResponseHeader().getHeader('Content-Length');
	var infoWindow    = "<script>var RealstudySecurityWindow=window.open('','RealstudySecurityWindow','scrollbars=yes,resizable=yes,"
					  + "top="+window[1]+",left="+window[0]+",width="+window[2]+",height="+window[3]+"');"
					  + "RealstudySecurityWindow.document.body.innerHTML=decodeURI(\"";
	var infoContents, iter, item;

	infoContents = "<font color='blue'>PARAM_URL [";
	iter = paramUrl.iterator();
	while (iter.hasNext()) {
		item = iter.next();
		infoContents += item.getName() + ":" + item.getValue() + ", ";
	}
	infoContents += "]<br>PARAM_FORM [";
	iter = paramForm.iterator();
	while (iter.hasNext()) {
		item = iter.next();
		infoContents += item.getName() + ":" + item.getValue() + ", ";
	}
	infoContents += "]</font><br>COOKIE [" + paramCookie + "]<br>"
	infoContents += findInsecureInfomation(body);

	infoWindow += encodeURI(infoContents) + "\");</script>";

	msg.setResponseBody(body+infoWindow);
	msg.getResponseHeader().setHeader('Content-Length', getByteLength(body+infoWindow));

	return true
}

function findInsecureInfomation(body) {
	var foundResults = "<hr><h2>Insecure Information</h2>";
	var regResult;

	for (var i=0; i < rules.length; i++) {
		while (found = rules[i].exec(body)) {
			foundResults += found[1].replace(/</g, "[").replace(/>/g, "]");
			foundResults += "<font color='red'>" + found[2] + "</font>"
			foundResults += found[3].replace(/</g, "[").replace(/>/g, "]") + "<br>";
		}
	}

	return foundResults;
}

function getByteLength(s,b,i,c){
    for(b=i=0;c=s.charCodeAt(i++);b+=c>>11?3:c>>7?2:1);
    return b;
}

function proxyRequest(msg) { return true; }
