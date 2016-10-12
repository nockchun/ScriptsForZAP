alertRisk = 3; alertReliability = 3; alertCWE_ID = 0; alertWASC_ID = 0;

alertTitle		= "Point XSS";
alertParam		= "N/A";
alertAttack		= "__point_check__<';\"scRsCriPtIpt";
alertEvidence	= "Reference to Description";
alertDesc		= "XSS Injection string test.";
alertOtherInfo	= "";
alertSolution	= "filter a script string.";

function scan(as, msg, param, value) {
	var msgNew = msg.cloneRequest();		// Copy requests before reusing them
	as.setParam(msg, param, alertAttack);	// setParam (message, parameterName, newValue)
	as.sendAndReceive(msg, false, false);	// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)

	var re = /__point_check__(?:[<'"&glt;%3c27]*)?(?:[script]*)?/gi;
	var body = msg.getResponseBody().toString();
	var alertParam = param;

	var foundResults = [];
	var counter = 0;

	while(comm = re.exec(body)) {
		counter = counter + 1;
		foundResults.push(comm[0]+"\n");
	}

	if (counter > 0) {
		alertOtherInfo = foundResults.toString();
		as.raiseAlert(alertRisk, alertReliability, alertTitle, alertDesc,
			msg.getRequestHeader().getURI().toString(), alertParam, alertAttack,
			alertOtherInfo, alertSolution, alertEvidence, alertCWE_ID, alertWASC_ID, msg);
	}
}