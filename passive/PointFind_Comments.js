var alertRisk = 3, alertReliability = 2, alertCWE_ID = 0, alertWASC_ID = 0;
alertTitle		= "Point:Comments in source";
alertParam		= "N/A";
alertAttack		= "N/A";
alertEvidence	= "Reference to Description";
alertDesc		= "Including a ensecure contents in source code";
alertOtherInfo	= "";
alertSolution	= "erase";

function scan(ps, msg, src) {
	// check content type.
	var contentType  = msg.getResponseHeader().getHeader("Content-Type");
	var statusCode   = msg.getResponseHeader().getStatusCode();
	var targetTypes  = [/text\/html/i, /text\/javascript/i, /text\/css/i];
	var isTargetType = false;

	if (statusCode != 200) return true;
	for (var i=0; i < targetTypes.length; i++) {
		if(targetTypes[i].test(contentType)) {
			isTargetType = true;
			break;
		}
	}
	if (!isTargetType) return true;

	// find comments
	var body = msg.getResponseBody().toString();
	var re_common = /(\<![\s]*--(.|\s)*?--[\s]*\>)/gm;
	var re_css    = /\/\*(.|\s)*?\*\//gm;
	var re_line   = /(\/\/.*)/gm;
	var sensitiveInfo = [re_common, re_css, re_line];

	var foundResults = [];
	var counter=0;
	for (var i=0; i < sensitiveInfo.length; i++) {
		if (sensitiveInfo[i].test(body)) {
			sensitiveInfo[i].lastIndex = 0;
			while(comm = sensitiveInfo[i].exec(body)) {
				counter = counter + 1;
				foundResults.push(comm[0]);
			}
		}
	}
	for (var j=0; j < foundResults.length; j++) {
		alertOtherInfo += foundResults[j] + "\n";
	}

	if (counter > 0)
		ps.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc,
			msg.getRequestHeader().getURI().toString(), alertParam, alertAttack,
			alertOtherInfo, alertSolution, alertEvidence, alertCWE_ID, alertWASC_ID, msg);
}